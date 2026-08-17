# BootSentry Canonical Release Truth Snapshot

**System**: BootSentry — AI-Assisted Secure Boot & Integrity Verification  
**Repository**: https://github.com/Vignesh-Er/secure_boot  
**Release Tag**: `v1.0.0`  
**License**: Apache 2.0 / MIT  

---

## 1. Verified Release Metrics

- **Release Commit**: `HEAD` (Synchronized with `origin/main`)
- **Tests**: 82 passed / 0 failed (100% pass rate across 82 test cases in `tests/`)
- **Coverage**: 87% line coverage across `src/bootsentry/` (`pytest-cov`)
- **Ruff Linting**: 0 errors / 0 warnings (`ruff check src/ tests/` with `E,W,F,I,B,BLE,UP,SIM`)
- **CI Matrix**: GitHub Actions automated pipeline passing on Python 3.10, 3.11, 3.12
- **Python Versions Supported**: Python 3.10, 3.11, 3.12 (AMD64 & ARM64)
- **ML-DSA Implementation**: NIST FIPS 204 standardized Module-Lattice-Based Digital Signature Algorithm (`ML-DSA-65` primary, with `ML-DSA-44` and `ML-DSA-87` support)
- **Gate 1 (PQC Verification)**: Deterministic, fail-closed ML-DSA-65 signature verification over RFC 8785 canonical JSON manifests
- **Gate 2 (Measured Boot)**: TPM-style software simulation SHA-256 PCR bank (PCR[0..3]), append-only replayable event log, and cryptographically signed PQC attestation quotes
- **Gate 3 (Behavioral AI Anomaly)**: 3-Layer Behavioral Detector (28-feature Isolation Forest + 1st-Order Markov Chain + EWMA/CUSUM Multi-Boot Drift Monitor) with Robust Median/MAD z-score Feature Attribution Engine
- **Policy Safety (Invariant 3)**: AI anomaly score produces `WARN + REDUCED_TRUST`; system `HALT` strictly requires a deterministic rule violation (`RULE_SVN_ROLLBACK`, `RULE_PCR_ALLOWLIST`, `RULE_CRYPTO_VERIFICATION_FAILED`, or `RULE_UNKNOWN_EVENT`)
- **Attack A1 (Signed Version Downgrade)**: PASS $\to$ Deterministic Rule Floor trips `RULE_SVN_ROLLBACK` $\implies$ `HALT`
- **Attack A2 (TOCTOU Dynamic Config Swap)**: PASS $\to$ Isolation Forest flags memory & runtime anomalies ($+4.9\sigma$) $\implies$ `WARN + REDUCED_TRUST`
- **Attack A3 (Signed Service Sequence Reorder)**: PASS $\to$ 1st-Order Markov Chain flags zero-probability transition $\implies$ `WARN + REDUCED_TRUST`
- **Attack A4 (Slow-Drip Multi-Boot Drift)**: PASS $\to$ EWMA / CUSUM Monitor detects accumulated positive drift at boot 12 ($>4.0\sigma$) $\implies$ `WARN + REDUCED_TRUST`
- **Attack A5 (Cross-SKU Component Substitution)**: PASS $\to$ Strictly held-out out-of-sample component evaluated with frozen baseline; Isolation Forest flags foreign memory allocation footprint $\implies$ `WARN + REDUCED_TRUST`
- **Benign Controls (B1 Cold Cache, B2 Upgrade, B3 CPU Load)**: PASS $\to$ 0 false HALTs across all environmental variations
- **PR-AUC**: 0.7310 (Evaluated on genuine process telemetry across normal and adversarial boots)
- **ROC-AUC**: 0.7267
- **FPR @ 95% TPR**: 1.00
- **False HALTs**: 0
- **Fresh-Clone Verification**: PASSED (Verified via independent clean clone in isolated temporary directory)
- **Judge-Check Engine**: 14 / 14 automated integrity verification checks passed (`make judge-check`)
- **Known Limitations**: TPM environment is a software-level simulation; timing features are subject to extreme non-uniform host I/O contention; ML-DSA-65 signatures (3,293 bytes) require memory overhead buffering in embedded environments (Documented in `docs/limitations.md`).

---

## 2. Reproducibility Commands

```bash
# 1. 14-Point Automated Judge Verification
make judge-check

# 2. Deterministic Safe Demo Replay (8 Scenarios)
make demo-safe

# 3. Interactive Live Terminal UI
make demo

# 4. End-to-End Evaluation Pipeline & HTML Report
make eval
```
