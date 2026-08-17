# CLAUDE.md — Developer & Build Guidelines

## Build & Test Commands
```bash
# Setup environment
pip install -r requirements.txt

# Generate PQC cryptographic keys
python -m bootsentry.crypto.keys --out-dir config/keys

# Sign boot stage manifests
python -m bootsentry.crypto.sign --keys-dir config/keys --stages-dir config/stages

# Run a clean single boot
python -m bootsentry.boot.runner --config config/policy.yaml

# Run unit & integration tests
pytest tests/ -v

# Run test coverage (>80% required)
pytest --cov=src/bootsentry --cov-report=term-missing tests/

# Run linting
ruff check src/ tests/

# Collect real boot telemetry dataset
python -m bootsentry.eval.collector --count 1000 --out-dir data/telemetry

# Train anomaly detection models
python -m bootsentry.eval.trainer --data-dir data/telemetry --models-dir models

# Run full evaluation & generate HTML report
python -m bootsentry.eval.evaluate --models-dir models --out-dir eval

# Run interactive Rich Terminal UI demo
python -m bootsentry.demo.tui --scenario clean

# Run demo-safe replay mode
python -m bootsentry.demo.tui --scenario a1_downgrade --safe-replay
```

## Architectural Guidelines
1. **Zero-Trust Boot Gates**:
   - Gate 1: Cryptographic signature verification (ML-DSA-65) must fail closed.
   - Gate 2: Measurement (PCR extension + Event Log) must independently verify allowlisted digests.
   - Gate 3: Behavioral analysis provides risk attestation; cannot brick independently.
2. **Deterministic Schemas**: All data passing across processes must use structured typed dataclasses (`Manifest`, `BootRecord`, `PcrBank`, `EventLogEntry`, `AttestationQuote`, `PolicyDecision`).
3. **No Synthetic Normal Data**: All training baselines must be captured from genuine OS process executions.
4. **Attribution Transparency**: Every anomaly must output top 3 feature deviations with robust median/MAD metrics.
