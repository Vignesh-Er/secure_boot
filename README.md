# BootSentry: AI-Assisted Secure Boot & Post-Quantum Integrity Verification

[![CI](https://github.com/Vignesh-Er/secure_boot/actions/workflows/ci.yml/badge.svg)](https://github.com/Vignesh-Er/secure_boot/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Coverage: 87%](https://img.shields.io/badge/coverage-87%25-brightgreen.svg)](eval/report.html)
[![PQC: ML--DSA--65](https://img.shields.io/badge/PQC-NIST_FIPS_204_(ML--DSA--65)-purple.svg)](docs/crypto-benchmarks.md)


> **Traditional secure boot answers:** *"Is this component authentic and approved?"*  
> **BootSentry additionally asks:** *"Is this boot behavior normal for this device and boot history?"*

---

## Executive Summary

Standard cryptographic secure boot systems (such as UEFI Secure Boot) verify static digital signatures on executable binaries before transfer of control. While essential, static signatures cannot detect:
1. **Time-of-Check to Time-of-Use (TOCTOU) Config Swaps**: Unsigned or dynamic configuration files loaded post-verification.
2. **Signed Version Downgrades**: Legitimate, older vendor-signed images containing known unpatched zero-days.
3. **In-Memory & Service Reordering**: Legitimate signed services executed out of sequence or diagnostic backdoors inserted at runtime.
4. **Slow-Drip Multi-Boot Stealth Drift**: Minor telemetry deviations accumulated across boots to evade single-boot threshold alarms.
5. **Cross-SKU Image Substitutions**: Validly signed images from adjacent product lines running on improper hardware profiles.

**BootSentry** is a unified, defense-in-depth secure boot architecture combining:
- **Gate 1: Post-Quantum Cryptography (PQC)** — Deterministic NIST FIPS 204 **ML-DSA-65** digital signatures and RFC 8785 canonical JSON manifests.
- **Gate 2: Measured Boot & Attestation** — TPM-style software simulation SHA-256 Platform Configuration Registers (PCRs 0–3), append-only cryptographic event log, and signed attestation quotes.
- **Gate 3: Behavioral AI Anomaly Detection** — 28-feature continuous execution telemetry pipeline, 3-layer anomaly detection ensemble (Isolation Forest, 1st-order Markov Sequence Model, Multi-boot EWMA/CUSUM Drift Monitor), and Robust Median/MAD z-score attribution engine.
- **Deterministic Rule Floor & 3-Level Policy Engine** — Non-bypassable deterministic safety floor enforcing **Invariant 3**: *AI anomaly scores alone never authorize a HALT (no false bricking); HALT strictly requires deterministic rule corroboration.*


---

## Core Security Invariants

| # | Invariant | Enforcement Mechanism | Failure Action |
|---|---|---|---|
| **1** | **Deterministic Cryptographic Verification** | Gate 1 ML-DSA-65 fail-closed signature check on stage manifest & payload | **HALT** (Blocks execution) |
| **2** | **Deterministic Measured Boot** | Gate 2 TPM PCR extension & event log replay verification | **HALT** (Blocks execution) |
| **3** | **Non-Bricking AI Safety Invariant** | Gate 3 ML anomaly scores produce `WARN + REDUCED_TRUST`; cannot independently brick system | **WARN + ATTEST** (Requires deterministic rule for HALT) |
| **4** | **Genuine Process Telemetry Only** | OS process telemetry captured via `psutil` sampling (no synthetic datasets) | Ground-truth reproducibility |
| **5** | **Zero Fake Computation** | Cryptographic hashing, memory table generation, and math workloads (no `time.sleep()`) | Real CPU/Memory/IO profiles |
| **6** | **Strictly Held-Out Attack A5** | Cross-SKU substitution evaluated strictly out-of-sample without hyperparameter tuning | Unbiased generalization test |
| **7** | **Feature Schema Versioning** | Every feature vector and model bundle carries `FEATURE_VERSION = 1`; mismatched models fail closed | Prevents stale model deployment |
| **8** | **Zero Network Dependency** | The security-critical boot path operates completely offline; zero `requests`/`urllib`/`socket` imports | Air-gapped boot integrity |

---

## Architecture Overview

```
 +---------------------------------------------------------------------------------------+
 |                                  BOOTSENTRY CHAIN                                     |
 +---------------------------------------------------------------------------------------+
        |
        v
 [ S0: BootROM ] ---> Gate 1: ML-DSA-65 Verification of S1 Manifest + Payload
        |             Gate 2: SHA-256 Extend PCR0 & Log Event
        v
 [ S1: Bootloader ] -> Gate 1: ML-DSA-65 Verification of S2 Manifest + Payload
        |             Gate 2: SHA-256 Extend PCR1 & Log Event
        v
 [ S2: Kernel ] ----> Gate 1: ML-DSA-65 Verification of S3 Manifest + Payload
        |             Gate 2: SHA-256 Extend PCR2 & Log Event
        v
 [ S3: Init/Svcs ] -> Gate 2: Extend PCR3 for Services (svc_a, svc_b, svc_c, attest, svc_e)
        |             Gate 3: Capture 28-Feature OS Process Telemetry Vector
        v
 +---------------------------------------------------------------------------------------+
 |                           GATE 3: AI & POLICY VERDICT                                 |
 +---------------------------------------------------------------------------------------+
        |
        +---> Isolation Forest (Contamination Auto, StandardScaler) -> Structural Anomaly Score
        +---> Markov Chain (1st-Order Laplace-smoothed) -----------> Sequence Anomaly Score
        +---> EWMA / CUSUM Drift Monitor --------------------------> Multi-Boot Drift Score
        +---> Deterministic Rule Floor -----------------------------> SVN & Allowlist Check
        |
        v
 [ Policy Engine ] ==> PASS | WARN + REDUCED_TRUST (Signed Quote) | HALT
        |
        v
 [ Attribution Engine ] ==> Robust Median / MAD z-score Feature Breakdown (e.g. +5.8σ)
```

---

## Measured PQC Benchmarks (NIST FIPS 204)

Benchmarked on AMD64 Python 3.12:

| Algorithm | Security Level | Public Key | Private Key | Signature | Keygen Latency | Sign Latency | Verify Latency |
|---|---|---|---|---|---|---|---|
| **ML-DSA-44** | NIST Level 2 (AES-128) | 1,312 B | 2,528 B | 2,420 B | 31.4 ms | 52.1 ms | 13.6 ms |
| **ML-DSA-65 (Default)** | NIST Level 3 (AES-192) | 1,952 B | 4,000 B | 3,293 B | 78.2 ms | 150.0 ms | 20.9 ms |
| **ML-DSA-87** | NIST Level 5 (AES-256) | 2,592 B | 4,864 B | 4,595 B | 94.6 ms | 136.7 ms | 33.0 ms |

---

## Attack Matrix & Evaluation Results

Evaluated across 67 test boot cycles, 5 realistic attack scenarios, and 3 benign stress controls:

| Scenario ID | Attack Description | Gate 1 (Crypto) | Gate 2 (PCR) | Gate 3 (AI / Rules) | Policy Verdict | Top Robust-z Attribution |
|---|---|---|---|---|---|---|
| **A1** | Signed Version Downgrade (SVN=3 < 5) | PASS | PASS | **RULE_SVN_ROLLBACK** | `HALT` | `security_version (-4.2σ)` |
| **A2** | TOCTOU Dynamic Config Swap | PASS | PASS | **IF Anomaly (Score=0.89)** | `WARN` | `t_exec_s2 (+5.8σ), rss_mb (+4.9σ)` |
| **A3** | Signed Service Reorder (`svc_e` -> `diag`) | PASS | PASS | **Markov NLL (Score=1.00)** | `WARN` | `unseen_transitions (+5.0σ)` |
| **A4** | Slow-Drip Drift (20 boots, +4ms/boot) | PASS | PASS | **EWMA / CUSUM (Score=0.92)** | `WARN` | `cusum_drift (+5.4σ)` |
| **A5** | Cross-SKU Substitution (Held-Out) | PASS | PASS | **IF Anomaly (Score=0.57)** | `WARN` | `rss_s2_mb (+5.2σ)` |
| **B1** | Benign: Cold Cache Boot | PASS | PASS | Normal Variance (Score=0.40) | `PASS` | `t_total (+1.8σ)` |
| **B2** | Benign: Authorized Upgrade (SVN=6 > 5) | PASS | PASS | Normal Upgrade (Score=0.34) | `PASS` | `security_version (+1.0σ)` |
| **B3** | Benign: Host CPU Background Load | PASS | PASS | Normal Variance (Score=0.39) | `PASS` | `stage_time_ratio (+0.4σ)` |

### Quantitative Metrics (Single Source of Truth: `eval/project_metrics.json`)
- **Multi-Gate System Threat Mitigation (Scenario-Level)**: **100% Threat Separation** (Scenario-Level Benchmark: `ROC-AUC = 1.0000`, `PR-AUC = 1.0000`, `FPR @ 95% TPR = 0.0000` — Evaluates full multi-gate defense combining deterministic cryptographic rules + behavioral detectors across reference attack fixtures)
- **Continuous Behavioral ML Detector (Sample-Level Evaluation)**: **Sample-Level ROC-AUC = 0.9563**, **PR-AUC = 0.9699** (Evaluates continuous sample-level behavioral ML performance across sequential executions without deterministic rule floor)
- **Benign False HALTs**: **0** (Verified 0 false halts across cold cache, legitimate upgrades, and CPU load)
- **Held-Out A5 Evaluation**: **WARN + REDUCED_TRUST** (Evaluated strictly out-of-sample; calibrated cross-SKU memory/I/O profile anomaly with top robust-z: `io_read_write_ratio` $+32000.0\sigma$, `io_bytes_read_kb` $+32.0\sigma$, `rss_s2_mb` $+31.3\sigma$)
- **Test Suite Coverage**: **87%** (116 tests passing / 0 failures)
- **Forensic Audit Reports**: See [evaluation-forensics.md](docs/evaluation-forensics.md) and [attribution_audit.json](eval/forensic/attribution_audit.json).


---

## Quickstart Guide

### 1. Prerequisites & Installation
```bash
# Clone the repository
git clone https://github.com/Vignesh-Er/secure_boot.git
cd secure_boot

# Install dependencies (requires Python 3.10+)
pip install -e .
```

### 2. Comprehensive Judge-Readiness Verification (One-Command Proof)
```bash
# Run full 14-point automated judge verification & consistency audit
make judge-check
```

### 3. Generate Post-Quantum Keys & Stage Manifests
```bash
# Generate ML-DSA-65 keypairs and sign 4 boot stages
make keys
```

### 4. Run a Clean 4-Stage Secure Boot
```bash
# Execute S0 -> S1 -> S2 -> S3 with full telemetry & attestation
make boot
```

### 5. Run the Full Test Suite
```bash
# Run 115 unit, integration, and attack tests with code coverage
make test
```




### 6. Collect Real Process Telemetry Dataset

```bash
# Collect 100 genuine boot records from real OS process execution
make collect N=100
```

### 7. Train Behavioral Anomaly Models
```bash
# Train Isolation Forest, Markov Sequence, EWMA monitor & Attribution engine
make train
```

### 8. Run Comprehensive Benchmark Evaluation
```bash
# Generate interactive eval/report.html and eval/metrics.json
make eval
```

### 9. Launch the Rich Terminal UI Demonstrator
```bash
# Live interactive demo across scenarios
make demo

# Or safe deterministic replay mode (judge presentation ready)
make demo-safe
```


---

## Repository Structure

```
secure_boot/
├── .github/workflows/ci.yml       # GitHub Actions CI workflow
├── config/
│   ├── keys/                      # ML-DSA-65 public/private keypairs
│   └── stages/                    # Stage payloads & RFC 8785 manifests
├── data/telemetry/                # Real process boot telemetry JSONL
├── docs/
│   ├── architecture.md            # In-depth architectural design
│   ├── threat-model.md            # Threat model & security boundary analysis
│   ├── leakage-audit.md           # 28-feature data leakage verification
│   ├── crypto-benchmarks.md       # Measured NIST FIPS 204 benchmarks
│   ├── limitations.md             # Engineering limitations & trade-offs
│   └── security-analysis.md       # Security analysis & safety invariant verification

├── eval/
│   ├── report.html                # Interactive judge evaluation report
│   ├── metrics.json               # Quantitative benchmark metrics
│   └── project_metrics.json       # Machine-readable single source of truth
├── models/                        # Serialized anomaly detection models
├── src/bootsentry/
│   ├── crypto/                    # PQC ML-DSA-65 provider & canonical manifests
│   ├── measure/                   # TPM PCR bank, event log, attestation quote
│   ├── boot/                      # 4 OS process stages (S0, S1, S2, S3)
│   ├── telemetry/                 # Process metric capture & JSONL logger
│   ├── features/                  # 28 continuous feature extractor
│   ├── detect/                    # Isolation Forest, Markov, EWMA, Rules, Policy
│   ├── attacks/                   # Attack testbed (A1-A5 & Benign Controls)
│   ├── eval/                      # Collector, Trainer, Evaluation & Judge-Check Engine
│   └── demo/                      # Rich TUI & Safe Replay Demonstrator
├── c_src/                         # Freestanding C99 embedded inference & PMU driver
│   ├── include/                   # bootsentry_telemetry.h, _crypto.h, _pcr.h
│   ├── src/                       # feature_extractor.c, policy_engine.c, pcr_bank.c, pmu_driver.c
│   └── test/                      # test_c_pipeline.c freestanding test runner
├── tests/                         # 115 comprehensive test cases (>80% cov)
├── Makefile                       # Reproducible CLI targets
├── pyproject.toml                 # Project metadata & dependencies
└── README.md                      # Primary project documentation


```

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
