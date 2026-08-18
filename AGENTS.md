# AGENTS.md — BootSentry Project Constitution & Multi-Agent Log

## Project Purpose
**BootSentry** is an AI-assisted secure boot and integrity verification system that fuses NIST Post-Quantum Cryptography (ML-DSA-65) with TPM-style measured boot and multi-tier process behavioral anomaly detection.

Traditional secure boot verifies: *"Is this component authentic and signed?"*
BootSentry adds: *"Is this boot behavior normal for this device and historical baseline?"*

---

## Non-Negotiable Security Invariants

1. **Cryptographic verification is deterministic and blocking (Gate 1)**
   If a signature check fails $\to$ immediate **HALT**. AI must never override Gate 1.
2. **Measurement verification is deterministic and blocking (Gate 2)**
   If the PCR state or event log violates an allowlisted measurement $\to$ immediate **HALT**. AI must never override Gate 2.
3. **AI cannot independently brick the system (Gate 3)**
   Behavioral anomaly detection produces `PASS` or `WARN + ATTESTATION PENALTY`. An ML anomaly score alone must never authorize `HALT` (prevents DoS exploitation of ML models).
4. **Real process telemetry only**
   All timing and resource observations are recorded from actual OS processes executing genuine computation. No fabricated normal telemetry datasets.
5. **No sleep-based fake computation**
   Stages perform real cryptographic hashing, matrix math, configuration parsing, and I/O.
6. **Held-out attack (A5)**
   Attack A5 (Cross-SKU substitution) is strictly held out during feature engineering and threshold tuning.
7. **Feature versioning**
   Every feature vector carries `FEATURE_VERSION`. Mismatched models fail closed.
8. **No network dependency during boot**
   The security-critical boot path operates completely offline.

---

## Architecture & Subsystems

```
+-------------------------------------------------------------------------+
|                              BOOTSENTRY                                 |
+-------------------------------------------------------------------------+
| S0 BootROM  -->  S1 Bootloader  -->  S2 Kernel  -->  S3 Init / Services |
+-------------------------------------------------------------------------+
| GATE 1: NIST ML-DSA-65 / PQC Signature Verification (Fail-Closed)       |
| GATE 2: TPM-Style SHA-256 PCR Bank + Append-Only Event Log + Quote      |
| GATE 3: Multi-Layer AI Anomaly Detection:                               |
|         - Layer A: Isolation Forest (28 Continuous Process Features)    |
|         - Layer B: 1st-Order Markov Chain (Service Sequence Order)      |
|         - Layer C: EWMA / CUSUM Monitor (Multi-Boot Drift)              |
|         - Attribution: Robust Median/MAD z-scores (Top 3 Features)      |
+-------------------------------------------------------------------------+
| POLICY ENGINE: PASS | WARN + ATTEST | HALT                              |
+-------------------------------------------------------------------------+
```

---

## Multi-Agent Logical Roles

- **ARCHITECT**: System interfaces, contracts, security invariants, directory structure.
- **CRYPTO ENGINEER**: ML-DSA-65 keys, deterministic canonicalization, signing, fail-closed verification, crypto benchmarks.
- **BOOT/MEASUREMENT ENGINEER**: Real 4-stage process chain (S0-S3), PCR extension, event log, signed quote.
- **TELEMETRY ENGINEER**: Real process metrics (RSS, page faults, context switches, IO, monotonic timings), BootRecord schema, atomic JSONL logging.
- **ML ENGINEER**: Isolation Forest, Markov chain, EWMA drift monitor, robust-z attribution, model serialization.
- **ATTACK/SECURITY ENGINEER**: A1 (Rollback), A2 (TOCTOU swap), A3 (Service reorder), A4 (Slow drift), A5 (Cross-SKU held-out), benign controls.
- **QA/VERIFICATION ENGINEER**: Pytest test suite (>80% coverage), failure injection, regression tests, linting.
- **DEMO ENGINEER**: Rich Terminal UI, live mode, demo-safe deterministic replay.
- **RELEASE ENGINEER**: Git workflow, GitHub remote sync, CI actions, judge documentation.

---

## Live Status & Milestone Tracker

| Milestone | Description | Status | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **M1** | Project Constitution, Repo Skeleton & Crypto Layer | COMPLETED | 35 Keygen/Sign/Verify tests |
| **M2** | Measured Boot & 4-Stage Process Chain | COMPLETED | S0-S3 handoffs & PCR verify |
| **M3** | Telemetry, Feature Extraction & Leakage Audit | COMPLETED | BootRecord JSONL & audit doc |
| **M4** | Detection Engine (IF, Markov, EWMA, Policy) | COMPLETED | Detection & attribution tests |
| **M5** | Attack Suite (A1-A5) & Benign Controls | COMPLETED | Scenario execution matrix |
| **M6** | Data Collection, Model Training & Eval Report | COMPLETED | 201 real boots & HTML report |
| **M7** | Rich TUI & Demo-Safe Replay Engine | COMPLETED | `make demo` & `make demo-safe` |
| **M8** | Comprehensive Docs, CI, Git Tags & Judge Polish | COMPLETED | 116 tests, 87% cov, GitHub push |

