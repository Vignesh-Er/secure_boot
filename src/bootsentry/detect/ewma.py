"""Detector 3: EWMA and CUSUM Multi-Boot Drift Monitor."""

from __future__ import annotations

import math
from pathlib import Path

import joblib
import numpy as np

from bootsentry.telemetry.record import BootRecord


class EWMADriftMonitor:
    """Detects gradual multi-boot behavioral drift across successive boots (e.g. Attack A4).

    Maintains Exponentially Weighted Moving Averages (EWMA) and cumulative sum (CUSUM)
    statistics over boot durations, anomaly scores, and context switches.
    """

    def __init__(
        self,
        alpha: float = 0.2,
        cusum_k: float = 0.5,
        cusum_h: float = 4.0,
    ):
        self.alpha = alpha
        self.cusum_k = cusum_k
        self.cusum_h = cusum_h

        # Baseline statistics learned from clean boots
        self.baseline_mean_time: float = 50.0
        self.baseline_std_time: float = 10.0
        self.baseline_mean_score: float = 0.1
        self.baseline_std_score: float = 0.05

        # Online state tracking across boots
        self.ewma_time: float = self.baseline_mean_time
        self.ewma_score: float = self.baseline_mean_score
        self.cusum_pos: float = 0.0
        self.cusum_neg: float = 0.0
        self.history_scores: list[float] = []
        self.history_times: list[float] = []

    def fit(
        self, records: list[BootRecord], if_scores: list[float] | None = None
    ) -> EWMADriftMonitor:
        """Fit baseline parameters from normal training history."""
        times = [r.total_boot_time_ms for r in records if r.total_boot_time_ms > 0]
        if times:
            self.baseline_mean_time = float(np.mean(times))
            self.baseline_std_time = float(np.std(times)) + 1e-4
            self.ewma_time = self.baseline_mean_time

        if if_scores and len(if_scores) > 0:
            self.baseline_mean_score = float(np.mean(if_scores))
            self.baseline_std_score = float(np.std(if_scores)) + 1e-4
            self.ewma_score = self.baseline_mean_score

        self.reset_online_state()
        return self

    def reset_online_state(self) -> None:
        """Reset the sequential tracking state."""
        self.ewma_time = self.baseline_mean_time
        self.ewma_score = self.baseline_mean_score
        self.cusum_pos = 0.0
        self.cusum_neg = 0.0
        self.history_scores = []
        self.history_times = []

    def update(self, record: BootRecord, current_if_score: float = 0.0) -> tuple[bool, float, dict[str, float]]:
        """Update sequential monitor with current boot and calculate drift anomaly score [0, 1]."""
        t = record.total_boot_time_ms
        s = current_if_score

        self.history_times.append(t)
        self.history_scores.append(s)

        # Update EWMA
        self.ewma_time = self.alpha * t + (1.0 - self.alpha) * self.ewma_time
        self.ewma_score = self.alpha * s + (1.0 - self.alpha) * self.ewma_score

        # Standardized deviation of current EWMA
        z_time = (self.ewma_time - self.baseline_mean_time) / (self.baseline_std_time + 1e-6)
        z_score = (self.ewma_score - self.baseline_mean_score) / (self.baseline_std_score + 1e-6)

        # CUSUM update for upward drift
        z_curr = (t - self.baseline_mean_time) / (self.baseline_std_time + 1e-6)
        self.cusum_pos = max(0.0, self.cusum_pos + z_curr - self.cusum_k)
        self.cusum_neg = min(0.0, self.cusum_neg + z_curr + self.cusum_k)

        # Calculate drift score in [0, 1]
        # Drift score activates when CUSUM or EWMA exceeds threshold
        cusum_ratio = self.cusum_pos / (self.cusum_h + 1e-6)
        drift_score = 1.0 / (1.0 + math.exp(-3.0 * (cusum_ratio - 1.0)))

        # Also factor in sustained multi-boot IF score elevations
        if len(self.history_scores) >= 5:
            recent_mean = float(np.mean(self.history_scores[-5:]))
            if recent_mean > 0.3:
                drift_score = min(1.0, drift_score + (recent_mean - 0.3) * 0.8)

        drift_score = float(np.clip(drift_score, 0.0, 1.0))
        is_drift = drift_score >= 0.5

        stats = {
            "ewma_time_ms": self.ewma_time,
            "ewma_score": self.ewma_score,
            "cusum_pos": self.cusum_pos,
            "z_time": z_time,
            "z_score": z_score,
            "drift_score": drift_score,
        }
        return is_drift, drift_score, stats

    def save(self, file_path: Path | str) -> None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "alpha": self.alpha,
            "cusum_k": self.cusum_k,
            "cusum_h": self.cusum_h,
            "baseline_mean_time": self.baseline_mean_time,
            "baseline_std_time": self.baseline_std_time,
            "baseline_mean_score": self.baseline_mean_score,
            "baseline_std_score": self.baseline_std_score,
        }
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, file_path: Path | str) -> EWMADriftMonitor:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"EWMA monitor file not found: {path}")

        bundle = joblib.load(path)
        monitor = cls(
            alpha=bundle["alpha"],
            cusum_k=bundle["cusum_k"],
            cusum_h=bundle["cusum_h"],
        )
        monitor.baseline_mean_time = bundle["baseline_mean_time"]
        monitor.baseline_std_time = bundle["baseline_std_time"]
        monitor.baseline_mean_score = bundle["baseline_mean_score"]
        monitor.baseline_std_score = bundle["baseline_std_score"]
        monitor.reset_online_state()
        return monitor
