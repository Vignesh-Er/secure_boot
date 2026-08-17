"""Detector 1: Isolation Forest Behavioral Anomaly Model."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from bootsentry.features.extractor import (
    FEATURE_NAMES,
    extract_feature_matrix,
    extract_feature_vector,
)
from bootsentry.telemetry.record import FEATURE_VERSION, BootRecord


class IsolationForestDetector:
    """Isolation Forest anomaly detector with StandardScaler preprocessing."""

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: str | float = "auto",
        random_state: int = 42,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.feature_version = FEATURE_VERSION

        self.scaler: StandardScaler | None = None
        self.model: IsolationForest | None = None
        self.score_threshold: float = 0.5  # Normalized anomaly threshold [0, 1]

    def fit(self, records: list[BootRecord]) -> IsolationForestDetector:
        """Fit scaler and Isolation Forest strictly on clean normal records."""
        X = extract_feature_matrix(records)
        if X.shape[0] < 5:
            raise ValueError(f"Insufficient training samples ({X.shape[0]}), minimum 5 required.")

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        # Calibrate baseline scores on training set
        raw_scores = -self.model.score_samples(X_scaled)  # higher = more anomalous
        self.score_threshold = float(np.percentile(raw_scores, 95))  # 95th percentile baseline
        return self

    def score_record(self, record: BootRecord) -> float:
        """Calculate normalized anomaly score in [0, 1] for a single BootRecord."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model is not trained. Call fit() or load() first.")

        if record.feature_version != self.feature_version:
            raise ValueError(
                f"Feature version mismatch: model expects v{self.feature_version}, record has v{record.feature_version}"
            )

        vec = extract_feature_vector(record).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)

        # raw score: lower means more anomalous in sklearn, so invert
        raw_score = -float(self.model.score_samples(vec_scaled)[0])

        # Normalize score into roughly [0, 1] with sigmoid/threshold mapping
        # raw_score typically ranges from ~0.35 (very normal) to ~0.75 (highly anomalous)
        # Using centered logistic mapping:
        norm_score = 1.0 / (1.0 + np.exp(-12.0 * (raw_score - self.score_threshold)))
        return float(np.clip(norm_score, 0.0, 1.0))

    def predict(self, record: BootRecord) -> tuple[bool, float]:
        """Return (is_anomalous, anomaly_score)."""
        score = self.score_record(record)
        return score >= 0.5, score

    def save(self, file_path: Path | str) -> None:
        """Save model bundle to joblib file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "feature_version": self.feature_version,
            "scaler": self.scaler,
            "model": self.model,
            "score_threshold": self.score_threshold,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "feature_names": FEATURE_NAMES,
        }
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, file_path: Path | str) -> IsolationForestDetector:
        """Load model bundle from joblib file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        bundle = joblib.load(path)
        if bundle.get("feature_version") != FEATURE_VERSION:
            raise ValueError(
                f"Model feature version {bundle.get('feature_version')} is incompatible with current {FEATURE_VERSION}"
            )

        detector = cls(
            n_estimators=bundle["n_estimators"],
            contamination=bundle["contamination"],
            random_state=bundle["random_state"],
        )
        detector.scaler = bundle["scaler"]
        detector.model = bundle["model"]
        detector.score_threshold = bundle["score_threshold"]
        return detector
