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
        self.scales: dict[str, float] = {}

    def fit(self, records: list[BootRecord]) -> AttributionEngine:
        """Calculate median, MAD, and robust dispersion scale for all 28 continuous features."""
        X = extract_feature_matrix(records)
        for i, name in enumerate(FEATURE_NAMES):
            col = X[:, i]
            med = float(np.median(col))
            mad = float(np.median(np.abs(col - med)))
            self.medians[name] = med
            self.mads[name] = mad

            if mad > 1e-6:
                # Standard normal-consistent MAD scale
                scale = 1.4826 * mad
            else:
                # When MAD == 0 (>50% identical values), fallback to L1 mean absolute deviation
                l1_dev = float(np.mean(np.abs(col - med)))
                if l1_dev > 1e-6:
                    scale = 1.2533 * l1_dev
                else:
                    std = float(np.std(col))
                    scale = std if std > 1e-6 else max(1.0, abs(med) * 0.1)
            self.scales[name] = scale
        return self

    def explain(self, record: BootRecord, top_k: int = 3) -> list[FeatureAttribution]:
        """Compute robust z-scores and return Top K most deviating features."""
        feat_dict = extract_feature_dict(record)
        attributions: list[FeatureAttribution] = []

        for name in FEATURE_NAMES:
            obs = float(feat_dict.get(name, 0.0))
            med = self.medians.get(name, 0.0)
            mad = self.mads.get(name, 0.0)
            scale = self.scales.get(name, 1.4826 * mad if mad > 1e-6 else max(1.0, abs(med) * 0.1))

            # Numerical safety checks
            if not np.isfinite(obs) or abs(obs - med) < 1e-12:
                z = 0.0
            else:
                z = (obs - med) / scale
                if not np.isfinite(z):
                    z = 0.0


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
            "scales": self.scales,
        }
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, file_path: Path | str) -> AttributionEngine:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Attribution engine file not found: {path}")

        bundle = joblib.load(path)
        engine = cls()
        engine.medians = bundle.get("medians", {})
        engine.mads = bundle.get("mads", {})
        engine.scales = bundle.get("scales", {})
        # Backwards compatibility if scales was not previously serialized
        if not engine.scales:
            for name, mad in engine.mads.items():
                med = engine.medians.get(name, 0.0)
                engine.scales[name] = 1.4826 * mad if mad > 1e-6 else max(1.0, abs(med) * 0.1)
        return engine

