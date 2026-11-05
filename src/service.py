"""Shared service layer used by both the web API and the Streamlit dashboard.

Keeps training, scoring and result summarising in one place so the two front
ends always behave the same way.
"""

import io
import json
import os
import threading

import numpy as np
import pandas as pd

from engine import FEATURES, LogAnomalyEngine
from generate_data import generate

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(ROOT, "models", "anomaly_model.pkl")
RESULTS_PATH = os.path.join(ROOT, "results", "nsl_kdd_results.json")
SAMPLE_PATH = os.path.join(ROOT, "data", "malicious_logs.csv")

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 100_000
MAX_RECORDS_RETURNED = 200
MIN_TRAIN_ROWS = 20


class InputError(ValueError):
    """The caller sent something we can't use (bad CSV, too big, too small)."""


def parse_csv(data):
    """Parse uploaded CSV bytes into a DataFrame, with size limits."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise InputError(f"File too large (limit {MAX_UPLOAD_BYTES // 1024 // 1024} MB).")
    try:
        df = pd.read_csv(io.BytesIO(data), nrows=MAX_ROWS + 1)
    except Exception as exc:  # pandas raises several different error types
        raise InputError(f"Could not read the file as CSV: {exc}") from exc
    if df.empty:
        raise InputError("The CSV has no rows.")
    if len(df) > MAX_ROWS:
        raise InputError(f"Too many rows (limit {MAX_ROWS:,}).")
    return df


def missing_features(df, features=FEATURES):
    return [c for c in features if c not in df.columns]


def sample_logs():
    return pd.read_csv(SAMPLE_PATH)


def demo_training_data():
    """Synthetic, mostly-normal traffic used for the built-in demo model."""
    return generate(rows=1000, attack_fraction=0.05).drop(columns=["label"])


class ModelStore:
    """Holds the active model in memory and on disk (thread-safe)."""

    def __init__(self, path=MODEL_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._engine = None
        self.source = None
        self.trained_rows = None

    def _set(self, engine, source, rows):
        self._engine, self.source, self.trained_rows = engine, source, rows

    def train(self, df, contamination=0.05, source="uploaded data"):
        if len(df) < MIN_TRAIN_ROWS:
            raise InputError(f"Need at least {MIN_TRAIN_ROWS} rows to train (got {len(df)}).")
        if not 0.001 <= contamination <= 0.5:
            raise InputError("Contamination must be between 0.001 and 0.5.")
        missing = missing_features(df)
        if len(missing) == len(FEATURES):
            raise InputError(f"None of the expected columns are present: {', '.join(FEATURES)}.")
        engine = LogAnomalyEngine(contamination=contamination).fit(df)
        with self._lock:
            engine.save(self.path)
            self._set(engine, source, len(df))
        return {"rows": len(df), "contamination": contamination, "missing_columns": missing}

    def engine(self):
        """Return the active engine, loading or bootstrapping one if needed."""
        with self._lock:
            if self._engine is not None:
                return self._engine
            if os.path.exists(self.path):
                self._set(LogAnomalyEngine.load(self.path), "saved model", None)
                return self._engine
        self.train(demo_training_data(), source="demo (synthetic traffic)")
        return self._engine

    def info(self):
        engine = self.engine()
        return {
            "source": self.source,
            "trained_rows": self.trained_rows,
            "contamination": engine.contamination,
            "features": engine.features,
            "risk_threshold": round(engine.risk_threshold, 2),
        }


def analyze(df, engine):
    """Score a DataFrame and return a JSON-safe summary plus the scored frame."""
    if len(df) > MAX_ROWS:
        raise InputError(f"Too many rows (limit {MAX_ROWS:,}).")
    missing = missing_features(df, engine.features)
    if len(missing) == len(engine.features):
        raise InputError(f"None of the expected columns are present: {', '.join(engine.features)}.")

    scored = engine.score(df)
    flagged = scored["anomaly_status"] == "CRITICAL ANOMALY"

    # Typical sessions score well above 0, so start the histogram where the data does.
    hist_min = float(min(np.floor(scored["risk_score"].min() / 10) * 10, 90))
    edges = np.linspace(hist_min, 100, 11)
    bins = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        in_bin = (scored["risk_score"] >= lo) & (
            scored["risk_score"] <= hi if hi == 100 else scored["risk_score"] < hi
        )
        bins.append(
            {
                "range": f"{lo:.4g}-{hi:.4g}",
                "normal": int((in_bin & ~flagged).sum()),
                "anomaly": int((in_bin & flagged).sum()),
            }
        )

    top = scored.assign(row=np.arange(1, len(scored) + 1)).sort_values(
        "risk_score", ascending=False
    )
    top = top.head(MAX_RECORDS_RETURNED)
    records = json.loads(top.to_json(orient="records"))  # NaN -> null, numpy -> python

    summary = {
        "rows": int(len(scored)),
        "anomalies": int(flagged.sum()),
        "anomaly_rate": round(float(flagged.mean()), 4),
        "risk_threshold": round(engine.risk_threshold, 2),
        "max_risk": float(scored["risk_score"].max()),
        "missing_columns": missing,
        "histogram": bins,
        "histogram_min": hist_min,
        "records": records,
        "records_truncated": len(scored) > MAX_RECORDS_RETURNED,
    }
    return summary, scored


def load_benchmark():
    """The saved NSL-KDD benchmark results, or None if the file is absent."""
    if not os.path.exists(RESULTS_PATH):
        return None
    with open(RESULTS_PATH) as fh:
        return json.load(fh)


store = ModelStore()
