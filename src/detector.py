"""Tier 1: the machine-learning detector for windows of log events.

An Isolation Forest is trained on an account's own history (assumed mostly
normal) over the rich features from features.py. Each window of events gets a
0-100 risk score, and a plain-language list of the features that made it unusual.
"""

import io

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from features import FEATURE_LABELS, FEATURES, Baseline

MIN_TRAIN_WINDOWS = 40
MODEL_VERSION = 1


def _to_risk(scores):
    """Isolation Forest scores are in [-1, 0): lower is more anomalous."""
    return np.clip(100.0 * (1.0 - (np.asarray(scores) + 1.0) / 2.0), 0, 100)


def _matrix(feature_rows):
    return np.array([[row[name] for name in FEATURES] for row in feature_rows], dtype=float)


class ThreatDetector:
    def __init__(self, contamination=0.03, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = None
        self.model = None
        self.threshold = None
        self.baseline = Baseline()
        self.n_windows = 0

    def fit(self, feature_rows, baseline):
        if len(feature_rows) < MIN_TRAIN_WINDOWS:
            raise ValueError(
                f"Need at least {MIN_TRAIN_WINDOWS} windows of history to learn a baseline; "
                f"got {len(feature_rows)}."
            )
        X = _matrix(feature_rows)
        self.scaler = RobustScaler().fit(X)
        scaled = self.scaler.transform(X)
        self.model = IsolationForest(
            n_estimators=200, contamination="auto", random_state=self.random_state
        ).fit(scaled)
        train_risk = _to_risk(self.model.score_samples(scaled))
        self.threshold = float(np.quantile(train_risk, 1.0 - self.contamination))
        self.baseline = baseline
        self.n_windows = len(feature_rows)
        return self

    def score(self, feature_rows):
        """Returns (risk scores, flagged flags) for a list of feature dicts."""
        scaled = self.scaler.transform(_matrix(feature_rows))
        risk = np.round(_to_risk(self.model.score_samples(scaled)), 2)
        return risk, risk >= self.threshold

    def explain(self, features, top=4, min_z=3.0):
        """The features that deviate most from this account's norm, most extreme first."""
        row = np.array([[features[name] for name in FEATURES]], dtype=float)
        z = self.scaler.transform(row)[0]
        center = self.scaler.center_
        picked = []
        for idx in np.argsort(-np.abs(z)):
            if abs(z[idx]) < min_z or len(picked) >= top:
                break
            name = FEATURES[idx]
            picked.append(
                {
                    "feature": name,
                    "label": FEATURE_LABELS[name],
                    "value": round(float(row[0][idx]), 3),
                    "typical": round(float(center[idx]), 3),
                    "z": round(float(z[idx]), 1),
                    "direction": "high" if z[idx] > 0 else "low",
                }
            )
        return picked

    # ---- persistence (stored as one blob in the database) ------------------

    def to_bytes(self) -> bytes:
        buffer = io.BytesIO()
        joblib.dump(
            {
                "version": MODEL_VERSION,
                "features": FEATURES,
                "model": self.model,
                "scaler": self.scaler,
                "threshold": self.threshold,
                "contamination": self.contamination,
                "baseline": self.baseline.to_dict(),
                "n_windows": self.n_windows,
            },
            buffer,
        )
        return buffer.getvalue()

    @classmethod
    def from_bytes(cls, blob: bytes):
        data = joblib.load(io.BytesIO(blob))
        if data.get("version") != MODEL_VERSION or data.get("features") != FEATURES:
            raise ValueError("Saved model is from an incompatible version; retrain the baseline.")
        det = cls(contamination=data["contamination"])
        det.model, det.scaler = data["model"], data["scaler"]
        det.threshold = data["threshold"]
        det.baseline = Baseline.from_dict(data["baseline"])
        det.n_windows = data["n_windows"]
        return det
