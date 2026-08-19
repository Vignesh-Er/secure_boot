"""Model training pipeline for BootSentry anomaly detectors."""

from __future__ import annotations

import argparse
from pathlib import Path

from bootsentry.detect.attribution import AttributionEngine
from bootsentry.detect.ewma import EWMADriftMonitor
from bootsentry.detect.isolation_forest import IsolationForestDetector
from bootsentry.detect.markov import MarkovSequenceDetector
from bootsentry.telemetry.logger import read_boot_records


def train_all_models(
    data_file: Path | str = "data/telemetry/normal_boots.jsonl",
    models_dir: Path | str = "models",
) -> dict[str, Path]:
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

    # Use only the first 80% for training; the last 20% is reserved for
    # out-of-sample evaluation in evaluate.py (matching its test_normal split).
    train_cutoff = int(len(normal_records) * 0.8)
    train_records = normal_records[:train_cutoff] if len(normal_records) > 12 else normal_records

    print(f"[*] Training BootSentry anomaly models on {len(train_records)} clean baseline boots "
          f"(80% of {len(normal_records)} total, last 20% reserved for evaluation)...")

    # 1. Train Isolation Forest
    print("  [+] Fitting Isolation Forest (n_estimators=200, StandardScaler)...")
    if_detector = IsolationForestDetector(n_estimators=200, contamination="auto", random_state=42)
    if_detector.fit(train_records)
    if_file = models_path / "isolation_forest.joblib"
    if_detector.save(if_file)

    # 2. Train Markov Sequence Model
    print("  [+] Fitting 1st-order Markov Sequence Model (Laplace smoothing)...")
    markov_detector = MarkovSequenceDetector(laplace_alpha=1.0)
    markov_detector.fit(train_records)
    markov_file = models_path / "markov_sequence.joblib"
    markov_detector.save(markov_file)

    # 3. Train EWMA Drift Monitor
    print("  [+] Calibrating EWMA / CUSUM Multi-Boot Drift Monitor...")
    if_scores = [if_detector.score_record(r) for r in train_records]
    ewma_monitor = EWMADriftMonitor(alpha=0.2, cusum_k=0.5, cusum_h=4.0)
    ewma_monitor.fit(train_records, if_scores=if_scores)
    ewma_file = models_path / "ewma_monitor.joblib"
    ewma_monitor.save(ewma_file)

    # 4. Train Attribution Engine (Median / MAD references)
    print("  [+] Computing Median & MAD statistics for 28 continuous features...")
    attribution_engine = AttributionEngine()
    attribution_engine.fit(train_records)
    attr_file = models_path / "attribution_engine.joblib"
    attribution_engine.save(attr_file)

    # 5. Generate and Sign Cryptographic Model Manifest (Gate 1 PQC Sealing)
    from bootsentry.crypto.keys import load_public_key, load_secret_key
    from bootsentry.crypto.model_manifest import create_model_manifest, sign_model_manifest

    s3_priv = Path("config/keys/s3_private.json")
    s3_pub = Path("config/keys/s3_public.json")
    manifest_file = models_path / "model_manifest.json"

    if s3_priv.exists() and s3_pub.exists():
        _, _, pk_bytes = load_public_key(s3_pub)
        _, _, sk_bytes = load_secret_key(s3_priv)
        manifest = create_model_manifest(
            models_dir=models_path,
            signer_public_key_bytes=pk_bytes,
            model_filenames=[
                "isolation_forest.joblib",
                "markov_sequence.joblib",
                "ewma_monitor.joblib",
                "attribution_engine.joblib",
            ],
        )
        signed_manifest = sign_model_manifest(manifest, sk_bytes)
        signed_manifest.save(manifest_file)
        print(f"  [+] Cryptographically signed model manifest saved to {manifest_file}")

    print(f"[OK] All models trained, sealed, and saved to {models_path}")
    return {
        "isolation_forest": if_file,
        "markov": markov_file,
        "ewma": ewma_file,
        "attribution": attr_file,
        "model_manifest": manifest_file,
    }



def main() -> None:
    parser = argparse.ArgumentParser(description="Train BootSentry Anomaly Detection Models")
    parser.add_argument("--data-file", type=str, default="data/telemetry/normal_boots.jsonl")
    parser.add_argument("--models-dir", type=str, default="models")
    args = parser.parse_args()

    train_all_models(data_file=args.data_file, models_dir=args.models_dir)


if __name__ == "__main__":
    main()
