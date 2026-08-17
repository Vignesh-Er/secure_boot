# BootSentry Build Status & Milestone Progress

## Project Identity
- **Repository**: `https://github.com/Vignesh-Er/secure_boot.git`
- **Primary Algorithm**: NIST FIPS 204 ML-DSA-65 (Dilithium3)
- **Secondary Algorithm Support**: ML-DSA-44, ML-DSA-87, SLH-DSA-SHA2-128s
- **Python Version**: 3.12 (Cross-platform Linux & Windows AMD64)
- **Target Status**: Autonomous, Tested, Reproducible, Judge-Ready

---

## Milestone Execution Record

| Milestone | Subsystem / Objective | Status | Commit / Notes |
| :--- | :--- | :--- | :--- |
| **M1** | Project Constitution, Skeleton, PQC Crypto Layer | **IN_PROGRESS** | `day1: project bootstrap & pqc crypto layer` |
| **M2** | Measured Boot (PCR, Event Log, Quote) & S0-S3 Boot Chain | PENDING | `day2: measured boot & 4-stage process chain` |
| **M3** | Telemetry, Feature Extraction & Leakage Audit | PENDING | `day3: telemetry engine & 28-feature pipeline` |
| **M4** | Detection Engine (IF, Markov, EWMA, Policy Floor) | PENDING | `day4: 3-layer anomaly detection & policy engine` |
| **M5** | Attack Scenarios (A1-A5) & Benign Controls | PENDING | `day5: attack testbed & held-out A5 evaluation` |
| **M6** | Data Collection, Model Training & HTML Report | PENDING | `day6: 1000-boot dataset & benchmark metrics` |
| **M7** | Rich TUI & Demo-Safe Replay Engine | PENDING | `day7: rich terminal tui & safe replay mode` |
| **M8** | Comprehensive Documentation, CI & Final Push | PENDING | `day8: final documentation & judge release` |

---

## Current Blockers & Warnings
- **None**. Environment is fully operational with Python 3.12, scikit-learn, numpy, pandas, scipy, psutil, rich, and dilithium-py.
