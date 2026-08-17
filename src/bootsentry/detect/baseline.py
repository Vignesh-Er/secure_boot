"""Baseline anomaly detection models (One-Class SVM & Local Outlier Factor) for evaluation ablation."""

from __future__ import annotations

import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from bootsentry.features.extractor import extract_feature_matrix, extract_feature_vector
from bootsentry.telemetry.record import BootRecord


class BaselineOneClassSVM:
    """One-Class SVM baseline for anomaly detection comparison."""

    def __init__(self, nu: float = 0.05, kernel: str = "rbf", gamma: str = "scale"):
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self.scaler: StandardScaler = StandardScaler()
        self.model: OneClassSVM = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)

    def fit(self, records: list[BootRecord]) -> BaselineOneClassSVM:
        X = extract_feature_matrix(records)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        return self

    def score_record(self, record: BootRecord) -> float:
        vec = extract_feature_vector(record).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)
        # raw decision function: negative means outlier
        raw = float(self.model.decision_function(vec_scaled)[0])
        # Logistic transform to [0, 1]
        score = 1.0 / (1.0 + np.exp(3.0 * raw))
        return float(np.clip(score, 0.0, 1.0))


class BaselineLocalOutlierFactor:
    """Local Outlier Factor (LOF) baseline for novelty detection."""

    def __init__(self, n_neighbors: int = 20, contamination: str | float = "auto"):
        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.scaler: StandardScaler = StandardScaler()
        self.model: LocalOutlierFactor = LocalOutlierFactor(
            n_neighbors=n_neighbors, contamination=contamination, novelty=True
        )

    def fit(self, records: list[BootRecord]) -> BaselineLocalOutlierFactor:
        X = extract_feature_matrix(records)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        return self

    def score_record(self, record: BootRecord) -> float:
        vec = extract_feature_vector(record).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)
        # raw decision function: negative means outlier
        raw = float(self.model.decision_function(vec_scaled)[0])
        score = 1.0 / (1.0 + np.exp(3.0 * raw))
        return float(np.clip(score, 0.0, 1.0))
