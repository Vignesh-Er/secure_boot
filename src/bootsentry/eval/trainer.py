"""Model training pipeline for BootSentry anomaly detectors."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Tuple

from bootsentry.detect.attribution import AttributionEngine
from bootsentry.detect.baseline import BaselineLocalOutlierFactor, BaselineOneClassSVM
from bootsentry.detect.ewma import EWMADriftMonitor
from bootsentry.detect.isolation_forest import IsolationForestDetector
from bootsentry.detect.markov import MarkovSequenceDetector
from bootsentry.telemetry.logger import read_boot_records
from bootsentry.telemetry.record import BootRecord


def train_all_models(
    data_file: Path | str = "data/telemetry/normal_boots.jsonl",
    models_dir: Path | str = "models",
) -> Dict[str, Path]:
    """Train all behavioral anomaly detection models strictly on clean baseline telemetry."""
    data_path = Path(data_file)
    models_path = Path(models_dir)
    models_path.mkdir(parents=True, exist_ok=True)

    records = read_boot_records(data_path)
    if not records:
        raise ValueError(f"No boot records found in {data_path}. Run 'make collect' first.")

    # Filter strictly normal boots for baseline training
    normal_records = [r for r in records if r.label == "normal"]
    if len(normal_records) < 10:
        raise ValueError(f"Insufficient normal training records ({len(normal_records)}), minimum 10 required.")

    print(f"[*] Training BootSentry anomaly models on {len(normal_records)} clean baseline boots...")

    # 1. Train Isolation Forest
    print("  [+] Fitting Isolation Forest (n_estimators=200, StandardScaler)...")
    if_detector = IsolationForestDetector(n_estimators=200, contamination="auto", random_state=42)
    if_detector.fit(normal_records)
    if_file = models_path / "isolation_forest.joblib"
    if_detector.save(if_file)

    # 2. Train Markov Sequence Model
    print("  [+] Fitting 1st-order Markov Sequence Model (Laplace smoothing)...")
    markov_detector = MarkovSequenceDetector(laplace_alpha=1.0)
    markov_detector.fit(normal_records)
    markov_file = models_path / "markov_sequence.joblib"
    markov_detector.save(markov_file)

    # 3. Train EWMA Drift Monitor
    print("  [+] Calibrating EWMA / CUSUM Multi-Boot Drift Monitor...")
    if_scores = [if_detector.score_record(r) for r in normal_records]
    ewma_monitor = EWMADriftMonitor(alpha=0.2, cusum_k=0.5, cusum_h=4.0)
    ewma_monitor.fit(normal_records, if_scores=if_scores)
    ewma_file = models_path / "ewma_monitor.joblib"
    ewma_monitor.save(ewma_file)

    # 4. Train Attribution Engine (Median / MAD references)
    print("  [+] Computing Median & MAD statistics for 28 continuous features...")
    attribution_engine = AttributionEngine()
    attribution_engine.fit(normal_records)
    attr_file = models_path / "attribution_engine.joblib"
    attribution_engine.save(attr_file)

    print(f"[OK] All models trained and saved to {models_path}")
    return {
        "isolation_forest": if_file,
        "markov": markov_file,
        "ewma": ewma_file,
        "attribution": attr_file,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train BootSentry Anomaly Detection Models")
    parser.add_argument("--data-file", type=str, default="data/telemetry/normal_boots.jsonl")
    parser.add_argument("--models-dir", type=str, default="models")
    args = parser.parse_args()

    train_all_models(data_file=args.data_file, models_dir=args.models_dir)


if __name__ == "__main__":
    main()
