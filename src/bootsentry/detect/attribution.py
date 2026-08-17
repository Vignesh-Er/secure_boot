"""Attribution Engine: Robust Median/MAD z-score explanations for anomalies."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from bootsentry.features.extractor import (
    FEATURE_NAMES,
    extract_feature_dict,
    extract_feature_matrix,
)
from bootsentry.telemetry.record import BootRecord


@dataclass
class FeatureAttribution:
    feature_name: str
    observed_value: float
    baseline_median: float
    baseline_mad: float
    robust_z: float  # (observed - median) / (1.4826 * MAD + eps)

    @property
    def formatted_sigma(self) -> str:
        sign = "+" if self.robust_z >= 0 else ""
        return f"{sign}{self.robust_z:.1f}sigma"

    def to_dict(self) -> dict[str, object]:
        return {
            "feature_name": self.feature_name,
            "observed_value": self.observed_value,
            "baseline_median": self.baseline_median,
            "baseline_mad": self.baseline_mad,
            "robust_z": self.robust_z,
            "formatted_sigma": self.formatted_sigma,
        }


class AttributionEngine:
    """Calculates robust z-score feature deviations to explain why a boot is anomalous."""

    def __init__(self):
        self.medians: dict[str, float] = {}
        self.mads: dict[str, float] = {}

    def fit(self, records: list[BootRecord]) -> AttributionEngine:
        """Calculate median and MAD for all 28 continuous features from normal baseline boots."""
        X = extract_feature_matrix(records)
        for i, name in enumerate(FEATURE_NAMES):
            col = X[:, i]
            med = float(np.median(col))
            mad = float(np.median(np.abs(col - med)))
            self.medians[name] = med
            self.mads[name] = max(1e-4, mad)
        return self

    def explain(self, record: BootRecord, top_k: int = 3) -> list[FeatureAttribution]:
        """Compute robust z-scores and return Top K most deviating features."""
        feat_dict = extract_feature_dict(record)
        attributions: list[FeatureAttribution] = []

        for name in FEATURE_NAMES:
            obs = feat_dict[name]
            med = self.medians.get(name, 0.0)
            mad = self.mads.get(name, 1.0)
            # 1.4826 * MAD normalizes MAD to standard deviation of a Gaussian distribution
            scale = 1.4826 * mad + 1e-4
            z = (obs - med) / scale
            attributions.append(
                FeatureAttribution(
                    feature_name=name,
                    observed_value=obs,
                    baseline_median=med,
                    baseline_mad=mad,
                    robust_z=float(z),
                )
            )

        # Sort by absolute deviation descending
        attributions.sort(key=lambda a: abs(a.robust_z), reverse=True)
        return attributions[:top_k]

    def save(self, file_path: Path | str) -> None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "medians": self.medians,
            "mads": self.mads,
        }
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, file_path: Path | str) -> AttributionEngine:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Attribution engine file not found: {path}")

        bundle = joblib.load(path)
        engine = cls()
        engine.medians = bundle["medians"]
        engine.mads = bundle["mads"]
        return engine
