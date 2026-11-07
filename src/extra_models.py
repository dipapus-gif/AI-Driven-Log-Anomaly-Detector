"""Two extra detectors for the NSL-KDD benchmark.

AutoencoderDetector   Unsupervised, like Isolation Forest: learns to reconstruct NORMAL rows through a
                      narrow bottleneck; rows it reconstructs badly are anomalies. Built on scikit-learn's
                      MLPRegressor (input -> input), so there is no deep-learning dependency to ship.

random_forest_*       A SUPERVISED reference. It sees attack labels while training, which the unsupervised
                      detectors never do, so it shows how far labels alone can get, not what the live platform
                      can do on attacks nobody has labeled yet.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler


class AutoencoderDetector:
    """Flag rows whose reconstruction error exceeds the (1 - contamination) quantile seen in training."""

    def __init__(self, contamination=0.05, hidden=(32, 8, 32), max_iter=80, random_state=42):
        self.contamination = contamination
        self.hidden = tuple(hidden)
        self.max_iter = max_iter
        self.random_state = random_state

    def _prepare(self, X, fit=False):
        X = np.asarray(X, dtype=float)
        if fit:
            # Byte counts and the like span many orders of magnitude; compress those columns first so a
            # handful of huge values don't dominate the squared error.
            lo, hi = X.min(axis=0), np.percentile(X, 99.9, axis=0)
            self.log_cols_ = (lo >= 0) & (hi > 1000)
        X = X.copy()
        X[:, self.log_cols_] = np.log1p(np.clip(X[:, self.log_cols_], 0, None))
        if fit:
            self.scaler_ = StandardScaler().fit(X)
        return np.clip(self.scaler_.transform(X), -8, 8)

    def fit(self, X):
        Z = self._prepare(X, fit=True)
        self.net_ = MLPRegressor(
            hidden_layer_sizes=self.hidden, activation="relu", solver="adam", batch_size=256,
            max_iter=self.max_iter, early_stopping=True, validation_fraction=0.1, n_iter_no_change=6,
            random_state=self.random_state,
        )
        self.net_.fit(Z, Z)
        self.threshold_ = float(np.quantile(self._error(Z), 1 - self.contamination))
        return self

    def _error(self, Z):
        return np.mean((self.net_.predict(Z) - Z) ** 2, axis=1)

    def score(self, X):
        """Reconstruction error. Higher means less like the normal traffic it learned."""
        return self._error(self._prepare(X))

    def predict(self, X):
        return (self.score(X) > self.threshold_).astype(int)


def random_forest(n_estimators=200, random_state=42):
    return RandomForestClassifier(n_estimators=n_estimators, n_jobs=-1, random_state=random_state)


def random_forest_scores(X_train, y_train, X_test, n_estimators=200, random_state=42):
    """Train on labeled rows, return (flagged at p>=0.5, attack probability) for X_test."""
    model = random_forest(n_estimators, random_state).fit(X_train, y_train)
    proba = model.predict_proba(X_test)[:, 1]
    return (proba >= 0.5).astype(int), proba


def random_forest_cv_scores(X, y, folds=5, n_estimators=100, random_state=42):
    """Cross-validated predictions on one labeled set: attack types seen in training appear in every
    held-out fold. This is the optimistic ceiling for a labeled detector."""
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=random_state)
    proba = cross_val_predict(random_forest(n_estimators, random_state), X, y, cv=cv, method="predict_proba")[:, 1]
    return (proba >= 0.5).astype(int), proba
