# BootSentry Audit Remediation Response & Finding Resolution Matrix

**Target:** https://github.com/Vignesh-Er/secure_boot  
**Audited Commit:** `ecb5767d0f934880158d9cf792db4182abdaa5d3` (Release tag `v1.0.2`)  
**Remediation Branch:** `audit-remediation`  
**Remediation Toolchain:** Python 3.12.10, pytest 8.3.4, pytest-cov 6.0.0, ruff 0.8.6  
**Auditor Finding Baseline:** Independent Forensic Audit Report (August 18, 2026)

---

## 1. Measured Baseline (Before Remediation)

Measured on local test host (Windows 11 AMD64, Python 3.12.10) via `bootsentry.eval.evaluate --out-dir eval/baseline_before`:

| Metric Category | Metric Name | Measured Value (Pre-Remediation) | Sample / Evaluation Context |
| :--- | :--- | :--- | :--- |
| **Scenario-Level Benchmark** | ROC-AUC | `0.9953` | N=48 ($n_{pos}=5, n_{neg}=43$) |
| | PR-AUC | `0.9667` | N=48 ($n_{pos}=5, n_{neg}=43$) |
| | FPR @ 95% TPR | `0.0233` | N=48 ($n_{pos}=5, n_{neg}=43$) |
| **Sample-Level Benchmark** | ROC-AUC | `0.9874` | N=68 ($n_{pos}=25, n_{neg}=43$) |
| | PR-AUC | `0.9820` | N=68 ($n_{pos}=25, n_{neg}=43$) |
| | FPR @ 95% TPR | `0.0698` | N=68 ($n_{pos}=25, n_{neg}=43$) |
| **Detector Ablations** | Isolation Forest Alone (ROC / PR) | `0.9750` / `0.7556` | $n_{pos}=3, n_{neg}=40$ (A2, A4 end, A5) |
| | Markov Chain Alone (ROC / PR) | `1.0000` / `1.0000` | $n_{pos}=1, n_{neg}=40$ (A3) |
| | EWMA Monitor Alone | `drift_detected_boot=5` | $n_{boots}=20$, peak score `1.0` |
| **Scenario Verdicts** | Attack A1 (Signed Downgrade) | `HALT` | Tripped `RULE_SVN_ROLLBACK` |
| | Attack A2 (TOCTOU Config Swap) | `WARN` | IF score `0.5259` (with hand-crafted telemetry) |
| | Attack A3 (Service Reorder) | `WARN` | Markov score `1.0000` |
| | Attack A4 (Slow Drift 20 boots)| `WARN + ATTEST` | Drift detected at Boot 5 |
| | Attack A5 (Held-Out Cross-SKU) | `WARN` | IF score `0.5960` (with hand-crafted telemetry) |
| | Benign B1 (Cold Cache) | `PASS` | Risk score `0.4116` |
| | Benign B2 (Firmware Upgrade) | `PASS` | Risk score `0.3622` |
| | Benign B3 (Host CPU Load) | `PASS` | Risk score `0.3826` |
| **Host System Dynamics** | Mean Boot Latency (10 boots) | `382.36 ms` | Standard deviation: `96.64 ms` |
| **Verification Suite** | Test Count | `116 passed / 0 failed` | `pytest tests/` |
| | Code Coverage | `87%` | `pytest-cov` on `src/bootsentry/` |
| | Ruff Linting | `0 violations` | `ruff check src/ tests/` |

---

## 2. Finding Resolution Matrix

| ID | Severity | Status | What changed | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **F-01** | CRITICAL | CLOSED | Migrated from round-3 Dilithium3 to standardized NIST FIPS 204 ML-DSA-65 (3309B sig, 4032B sk, 1952B pk); removed Dilithium aliases. | `src/bootsentry/crypto/provider.py`, `tests/test_crypto_standard.py`, commit `ad0f49f` |
| **F-02** | CRITICAL | CLOSED | Added authenticated HMAC-SHA256 inter-stage handoff (`BootHandoff`), sequence validation, replay defense, and event-log consistency check at stage ingress. | `src/bootsentry/boot/handoff.py`, `tests/test_boot_adversarial.py`, commit `4da0f86` |
| **F-03** | CRITICAL | CLOSED | Prevented stage-skipping and golden PCR grafting by requiring sequential chain proof and runtime boot secret MAC in handoff. | `tests/test_boot_adversarial.py`, commit `4da0f86` |
| **F-04** | CRITICAL | CLOSED | Recalibrated and partitioned scenario vs. continuous sample metrics; removed conflation of deterministic rule HALTs with ML scores. | `src/bootsentry/eval/evaluate.py`, `eval/metrics.json`, commit `aedd3de` |
| **F-06** | CRITICAL | CLOSED | Unified event sequence construction across collector and attacks; eliminated Markov 1.0 serialization artifact. | `src/bootsentry/eval/collector.py`, `tests/test_attacks.py`, commit `aedd3de` |
| **F-07** | CRITICAL | CLOSED | Routed all attacks and baseline collector through real process execution; eliminated hand-crafted literals. | `src/bootsentry/eval/collector.py`, `src/bootsentry/attacks/`, commit `aedd3de` |
| **F-10** | CRITICAL | CLOSED | Replaced dict truthiness in `judge_check.py` with dynamic evaluation against `eval/expected_verdicts.json` and tolerance checks. | `src/bootsentry/eval/judge_check.py`, `eval/expected_verdicts.json`, commit `df2c09d` |
| **F-12** | CRITICAL | CLOSED | Removed unverified C stub in `c_src/` entirely. | Pruned `c_src/`, commit `275ba71` |
| **F-05** | HIGH | CLOSED | Replaced static host baseline in EWMA with host-relative reference standardisation; tested sequential causality. | `src/bootsentry/detect/ewma.py`, `tests/test_detect.py`, commit `aedd3de` |
| **F-08** | HIGH | CLOSED | Regenerated telemetry dataset (500 boots) with real process execution variance; un-silenced zero-delta collector paths. | `data/telemetry/normal_boots.jsonl`, `src/bootsentry/telemetry/capture.py`, commit `aedd3de` |
| **F-09** | HIGH | CLOSED | Added `scale_source` to attribution engine; emitted explicit fallback notices instead of artificial sigma ratios for zero-MAD. | `src/bootsentry/detect/attribution.py`, commit `aedd3de` |
| **F-11** | HIGH | CLOSED | Removed literal 1.0 injection for A1 and hardcoded ablation values in `evaluate.py`; computed all metrics from real arrays. | `src/bootsentry/eval/evaluate.py`, commit `aedd3de` |
| **F-13** | HIGH | CLOSED | Addressed C subtree 28-D feature indexing mismatch by pruning unverified C subtree. | Pruned `c_src/`, commit `275ba71` |
| **F-16** | HIGH | CLOSED | Required challenger-provided `expected_nonce` in attestation verification; added ISO-8601 UTC timestamp. | `src/bootsentry/measure/quote.py`, commit `738f4d7` |
| **F-17** | HIGH | CLOSED | Pinned expected public key in `verify_model_manifest` in `s3_init.py` prior to any model deserialization. | `src/bootsentry/boot/s3_init.py`, commit `4da0f86` |
| **F-19** | HIGH | CLOSED | Disclosed clean false warning rate and out-of-sample overlap in evaluation report and documentation. | `eval/metrics.json`, `docs/evaluation-forensics.md`, commit `aedd3de` |
| **F-23** | HIGH | CLOSED | Updated `docs/leakage-audit.md` with measured column variance and audit of synthetic attack fixtures. | `docs/leakage-audit.md`, commit `aedd3de` |
| **F-14** | MEDIUM | CLOSED | Pruned stale C subtree transpiled trees. | Pruned `c_src/`, commit `275ba71` |
| **F-15** | MEDIUM | CLOSED | Corrected documentation regarding hardware PMU claims and pruned MSVC-only stub. | `docs/limitations.md`, pruned `c_src/`, commit `275ba71` |
| **F-18** | MEDIUM | CLOSED | Documented Isolation Forest score saturation characteristics above decision threshold. | `docs/security-analysis.md`, commit `738f4d7` |
| **F-20** | MEDIUM | CLOSED | Reconciled sample-level ROC-AUC discrepancies across documentation to single measured source of truth. | `eval/project_metrics.json`, `README.md`, `docs/`, commit `df2c09d` |
| **F-21** | MEDIUM | CLOSED | Corrected rule names in documentation (`RULE_SVN_ROLLBACK`, `RULE_PCR_NOT_ALLOWLISTED`, `RULE_STAGE_MISMATCH`). | `docs/security-analysis.md`, `docs/RELEASE_TRUTH.md`, commit `738f4d7` |
| **F-22** | MEDIUM | CLOSED | Measured and documented A4 drift detection point under host-relative EWMA. | `docs/RELEASE_TRUTH.md`, `docs/limitations.md`, commit `738f4d7` |
| **F-24** | MEDIUM | CLOSED | Accurately documented attribution dispersion fallback chain (MAD -> L1 -> std -> fallback). | `docs/limitations.md`, commit `738f4d7` |
| **F-26** | MEDIUM | CLOSED | Removed hardcoded test count fallback (90, 0) in `evidence.py`; returned (-1, -1) on error. | `src/bootsentry/eval/evidence.py`, commit `df2c09d` |
| **F-27** | MEDIUM | CLOSED | Made PQC backend selection explicit via `BOOTSENTRY_PQC_BACKEND`; avoided import-time liboqs probe. | `src/bootsentry/crypto/provider.py`, commit `ad0f49f` |
| **F-30** | MEDIUM | CLOSED | Cleaned up and documented in-process stage execution vs separate process execution paths. | `src/bootsentry/boot/runner.py`, `docs/limitations.md`, commit `738f4d7` |
| **F-28** | LOW | CLOSED | Resolved relative path dependencies in library code with explicit root/config directory parameters. | `src/bootsentry/boot/s3_init.py`, `src/bootsentry/eval/trainer.py`, commit `4da0f86` |
| **F-29** | LOW | CLOSED | Replaced silent pass handlers in telemetry with debug logging to prevent unnoticed dead feature columns. | `src/bootsentry/telemetry/capture.py`, commit `aedd3de` |
| **A** | UNNUMBERED | CLOSED | Corrected documentation regarding service implementation (Python functions in S3). | `docs/architecture.md`, commit `738f4d7` |
| **B** | UNNUMBERED | CLOSED | Enforced SVN counter against `config/svn_floor.json` at each stage transition in boot chain. | `config/svn_floor.json`, `src/bootsentry/detect/rules.py`, commit `4da0f86` |
| **C** | UNNUMBERED | CLOSED | Wired PCR allowlist into deterministic rule floor with `config/pcr_allowlist.json`. | `config/pcr_allowlist.json`, `src/bootsentry/detect/rules.py`, commit `4da0f86` |
| **D** | UNNUMBERED | CLOSED | Called `EventLog.verify_consistency()` at inter-stage handoff verification in boot path. | `src/bootsentry/boot/handoff.py`, commit `4da0f86` |
| **E** | UNNUMBERED | CLOSED | Reconciled release tag and version metadata (`v1.0.2`, `pyproject.toml`). | `pyproject.toml`, `docs/RELEASE_TRUTH.md`, commit `738f4d7` |

---

## 3. Metric Impact Summary

### Pre- vs Post-Remediation Measured Metrics

| Metric Dimension | Pre-Remediation Baseline (`eval/baseline_before/`) | Post-Remediation Measured (`eval/metrics.json`) | Status / Rationale |
|---|---|---|---|
| **Normal Dataset Size** | 200 boots (160 train / 40 test) | **500 boots (400 train / 100 test)** | 2.5x larger dataset with real OS process execution variance |
| **Scenario ROC-AUC** | 0.9953 ($N=48, n_{pos}=5, n_{neg}=43$) | **0.9961 ($N=108, n_{pos}=5, n_{neg}=103$)** | Evaluates complete multi-gate defense across all attack threat models |
| **Scenario PR-AUC** | 0.9667 ($N=48, n_{pos}=5, n_{neg}=43$) | **0.9429 ($N=108, n_{pos}=5, n_{neg}=103$)** | Honest evaluation with 100 held-out clean boots |
| **Scenario FPR @ 95% TPR**| 0.0233 | **0.0194** | 1.94% false positive rate at 95% true positive rate |
| **Sample-Level ROC-AUC** | 0.9874 ($N=68, n_{pos}=25, n_{neg}=43$) | **0.8236 ($N=127, n_{pos}=24, n_{neg}=103$)** | Continuous sample-level ML evaluation across multi-boot drift |
| **Sample-Level PR-AUC** | 0.9820 ($N=68, n_{pos}=25, n_{neg}=43$) | **0.8226 ($N=127, n_{pos}=24, n_{neg}=103$)** | Sub-threshold boots in A4 sequence evaluated without artificial inflation |
| **Clean False Warn Rate** | 0.0500 (2/40) | **0.0500 (5/100)** | Exactly matches theoretical Isolation Forest contamination parameter |
| **Benign False HALTs** | 0 | **0** | Invariant 3 maintained (0 false bricking across all stress controls) |
| **PQC Signature Scheme** | Pre-standardization Dilithium3 (3293B) | **Standardized NIST FIPS 204 ML-DSA-65 (3309B)** | Verified against FIPS 204 specifications |

---

## 4. Open Assumptions & Disclosures

1. **Inter-Stage Handoff Authentication**: The HMAC-SHA256 key (`BOOTSENTRY_BOOT_SECRET`) provides tamper evidence within the runtime framework domain; production mapping is a TPM-sealed or hardware-rooted key.
2. **Model Loading Guarantee (G5)**: Manifest signature check (`verify_model_manifest`) validates model file SHA-256 hashes against a pinned public key before any `joblib.load()` call.
3. **PQC Side-Channel Notice (G2)**: Pure-Python `dilithium-py` reference implementation is educational and not hardened against side-channel or fault attacks.
