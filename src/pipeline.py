"""Shared helpers used by the web API (api.py) and the Streamlit dashboard
(dashboard.py), so both validate input and summarize results the same way."""

import json
from pathlib import Path

import numpy as np
import pandas as pd

from engine import FEATURES, LogAnomalyEngine

ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = ROOT / "results" / "nsl_kdd_results.json"
ROC_PATH = ROOT / "results" / "nsl_kdd_roc.png"

MAX_ROWS = 100_000
MIN_TRAIN_ROWS = 20
FLAGGED = "CRITICAL ANOMALY"

CONFIG_LABELS = {
    "mapped4": "4 mapped features",
    "numeric38": "38 numeric features",
    "numeric38_protocol": "38 numeric + protocol",
    "numeric38_all_cat": "38 numeric + protocol, flag, service",
}
MODEL_LABELS = {"isolation_forest": "Isolation Forest", "ocsvm": "One-Class SVM"}


class InputError(ValueError):
    """The uploaded data or parameters cannot be used (maps to HTTP 400)."""


def validate_logs(df, min_rows=1):
    """Reject data the engine would silently mangle (it zero-fills missing
    feature columns, so a wrong CSV would otherwise 'work' and mean nothing)."""
    if not any(col in df.columns for col in FEATURES):
        raise InputError(
            "CSV has none of the expected columns: " + ", ".join(FEATURES) + "."
        )
    if len(df) < min_rows:
        raise InputError(f"Need at least {min_rows} rows, got {len(df)}.")
    if len(df) > MAX_ROWS:
        raise InputError(f"Too many rows ({len(df):,}); the limit is {MAX_ROWS:,}.")
    return df.reset_index(drop=True)


def train_engine(df, contamination=0.05):
    if not 0 < contamination <= 0.5:
        raise InputError("Contamination must be greater than 0 and at most 0.5.")
    df = validate_logs(df, min_rows=MIN_TRAIN_ROWS)
    return LogAnomalyEngine(contamination=contamination).fit(df)


def describe_engine(engine, trained_rows):
    return {
        "trained_rows": int(trained_rows),
        "contamination": engine.contamination,
        "features": engine.features,
        "risk_threshold": round(engine.risk_threshold, 2),
    }


def summarize(scored, engine, max_rows=200):
    """Turn a scored DataFrame into plain, JSON-safe data for the UIs."""
    flagged_mask = scored["anomaly_status"] == FLAGGED
    flagged = scored[flagged_mask].sort_values("risk_score", ascending=False)

    counts, _ = np.histogram(scored["risk_score"], bins=20, range=(0, 100))
    summary = {
        "rows": int(len(scored)),
        "flagged": int(flagged_mask.sum()),
        "flag_rate": round(float(flagged_mask.mean()), 4) if len(scored) else 0.0,
        "risk_threshold": round(engine.risk_threshold, 2),
        "histogram": [int(c) for c in counts],
        "features": engine.features,
    }

    # If the file carries ground-truth labels (like the synthetic generator's),
    # report how well the detector did.
    if "label" in scored.columns:
        labels = pd.to_numeric(scored["label"], errors="coerce")
        if labels.isin([0, 1]).all() and labels.sum() > 0:
            attacks = labels == 1
            tp = int((flagged_mask & attacks).sum())
            summary["label_metrics"] = {
                "attacks": int(attacks.sum()),
                "caught": tp,
                "recall": round(tp / int(attacks.sum()), 4),
                "precision": round(tp / max(int(flagged_mask.sum()), 1), 4),
                "false_alarms": int((flagged_mask & ~attacks).sum()),
            }

    cols = [c for c in engine.features if c in flagged.columns] + ["risk_score"]
    top = flagged[cols].head(max_rows).copy()
    top.insert(0, "row", top.index + 1)  # 1-based row number in the uploaded file
    summary["flagged_rows"] = json.loads(top.to_json(orient="records"))
    summary["flagged_truncated"] = bool(len(flagged) > max_rows)
    return summary


def load_benchmark():
    """The saved NSL-KDD benchmark run, or None if it hasn't been generated."""
    if not RESULTS_PATH.exists():
        return None
    return json.loads(RESULTS_PATH.read_text())


def benchmark_table(results):
    """Flatten the benchmark JSON into one row per (feature set, detector)."""
    rows = []
    for model_key, configs in results["results"].items():
        for config_key, m in configs.items():
            rows.append(
                {
                    "Feature set": CONFIG_LABELS.get(config_key, config_key),
                    "Detector": MODEL_LABELS.get(model_key, model_key),
                    "Features": m["n_features"],
                    "Precision": m["precision"],
                    "Recall": m["recall"],
                    "F1": m["f1"],
                    "ROC AUC": m["roc_auc"],
                }
            )
    return pd.DataFrame(rows)
