"""Core ML engine for the AI-driven log anomaly detector."""

import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["duration", "packet_count", "byte_size", "failed_logins"]


def select_features(df, features):
    """Return the feature matrix: add any missing columns as zeros and
    coerce bad values to numbers (missing/unparseable -> 0)."""
    df = df.copy()
    for col in features:
        if col not in df.columns:
            df[col] = 0
    return df[features].apply(pd.to_numeric, errors="coerce").fillna(0)


class LogAnomalyEngine:
    def __init__(self, contamination=0.05, random_state=42, features=None):
        self.contamination = contamination
        self.features = list(features) if features else list(FEATURES)
        self.model = IsolationForest(
            contamination=contamination, random_state=random_state
        )
        self.scaler = StandardScaler()

    def preprocess_data(self, df, is_training=True):
        X = select_features(df, self.features)
        if is_training:
            return self.scaler.fit_transform(X)
        return self.scaler.transform(X)

    def fit(self, df):
        """Fit the scaler and model on an in-memory DataFrame."""
        X_scaled = self.preprocess_data(df, is_training=True)
        self.model.fit(X_scaled)
        return self

    def save(self, model_output_path):
        out_dir = os.path.dirname(model_output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        joblib.dump((self.model, self.scaler, self.features), model_output_path)
        print(f"[+] Model saved to: {model_output_path}")

    def train(self, data_path, model_output_path):
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Missing training log data at: {data_path}")
        self.fit(pd.read_csv(data_path))
        self.save(model_output_path)

    @classmethod
    def load(cls, model_path):
        """Load a saved model (as written by save/train) into a ready engine."""
        model, scaler, features = joblib.load(model_path)
        engine = cls(contamination=model.contamination, features=features)
        engine.model, engine.scaler = model, scaler
        return engine

    @property
    def risk_threshold(self):
        """Risk score at which the model starts flagging rows (0-100)."""
        return float(np.clip(_to_risk(self.model.offset_), 0, 100))

    def score(self, df):
        """Score an in-memory DataFrame with an already fitted engine."""
        X_scaled = self.scaler.transform(select_features(df, self.features))
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        df = df.copy()
        df["anomaly_status"] = np.where(predictions == -1, "CRITICAL ANOMALY", "NORMAL")
        df["risk_score"] = np.round(np.clip(_to_risk(scores), 0, 100), 2)
        return df

    def detect_anomalies(self, df, model_path):
        return LogAnomalyEngine.load(model_path).score(df)


def _to_risk(scores):
    """score_samples is roughly in [-1, 0]; more negative = more anomalous."""
    return 100 * (1 - (scores + 1) / 2)
