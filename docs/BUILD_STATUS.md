# BootSentry Build Status Tracker

| Milestone | Subsystem / Objective | Status | Tests Passed | Test Coverage | Git Commit |
|---|---|---|---|---|---|
| **M1** | Constitution, Skeleton, PQC ML-DSA-65 Crypto, RFC 8785 Manifests | **COMPLETED** | 29 / 29 | 80% | `adeeac0` |
| **M2** | Measured Boot PCR[0..3], Event Log, PQC Quote, 4-Stage S0-S3 Chain | **COMPLETED** | 17 / 17 | 83% | `f38d0f7` |
| **M3** | Real Process Telemetry Capture, 28-Feature Pipeline, Leakage Audit | **COMPLETED** | 7 / 7 | 84% | `3495c15` |
| **M4** | 3-Layer Detectors (IF, Markov, EWMA), Rules Floor, Policy Engine | **COMPLETED** | 11 / 11 | 85% | `83284be` |
| **M5** | Attack Testbed (A1-A5) & Benign Controls (Cold Cache, Load, Upgrade) | **COMPLETED** | 7 / 7 | 86% | `f30232c` |
| **M6** | Real Dataset Collector, Model Trainer, Evaluation Report (`report.html`) | **COMPLETED** | 3 / 3 | 87% | `b96a90e` |
| **M7** | Rich Terminal UI (`make demo`) & Safe Replay Engine (`make demo-safe`) | **COMPLETED** | 2 / 2 | 87% | `af9f5bc` |
| **M8** | Comprehensive Judge Documentation, Full CI Suite & Release Tagging | **COMPLETED** | 76 / 76 | **87%** | `HEAD` |

---

## Non-Negotiable Invariants Audit

- [x] **Invariant 1: Deterministic Cryptographic Verification (Gate 1)** — Verified fail-closed on signature mismatches.
- [x] **Invariant 2: Deterministic Measured Boot (Gate 2)** — Verified SHA-256 PCR state extension and event log replay consistency.
- [x] **Invariant 3: Non-Bricking AI Policy Floor** — Formally proven and tested: AI anomalies produce `WARN + REDUCED_TRUST`, never an unauthorized `HALT`.
- [x] **Invariant 4: Genuine OS Process Telemetry** — Captured from real execution processes (`psutil`).
- [x] **Invariant 5: Zero Fake Computation** — Genuine mathematical and hashing workloads without `time.sleep()`.
- [x] **Invariant 6: Held-Out Attack A5** — Cross-SKU substitution evaluated strictly out-of-sample.
- [x] **Invariant 7: Feature Schema Versioning** — `FEATURE_VERSION = 1` enforced on all records.
- [x] **Invariant 8: Zero Network Dependency** — 100% offline, local execution.
