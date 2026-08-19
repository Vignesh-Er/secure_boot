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
| **F-01** | CRITICAL | IN PROGRESS | Migrate from round-3 Dilithium3 to standardized NIST FIPS 204 ML-DSA-65 (3309B sig, 4032B sk, 1952B pk); remove Dilithium aliases. | `src/bootsentry/crypto/provider.py`, `tests/test_crypto_standard.py` |
| **F-02** | CRITICAL | IN PROGRESS | Add authenticated HMAC-SHA256 inter-stage handoff (`BootHandoff`), sequence validation, replay defense, and event-log consistency check at stage ingress. | `src/bootsentry/boot/handoff.py`, `tests/test_boot_adversarial.py` |
| **F-03** | CRITICAL | IN PROGRESS | Prevent stage-skipping and golden PCR grafting by requiring sequential chain proof and runtime boot secret MAC in handoff. | `tests/test_boot_adversarial.py::test_stage_skip_graft_fails` |
| **F-04** | CRITICAL | IN PROGRESS | Recalibrate and partition scenario vs. continuous sample metrics; remove conflation of deterministic rule HALTs with ML scores. | `src/bootsentry/eval/evaluate.py`, `eval/metrics.json` |
| **F-06** | CRITICAL | IN PROGRESS | Unify event sequence construction across collector and attacks via `builder.py`; eliminate Markov 1.0 serialization artifact. | `src/bootsentry/telemetry/builder.py`, `tests/test_no_fixture_leakage.py` |
| **F-07** | CRITICAL | IN PROGRESS | Route all attacks through real process execution and genuine `builder.py` telemetry; eliminate hand-crafted literals. | `src/bootsentry/telemetry/builder.py`, `src/bootsentry/attacks/` |
| **F-10** | CRITICAL | IN PROGRESS | Replace dict truthiness in `judge_check.py` with dynamic evaluation against `eval/expected_verdicts.json` and tolerance checks. | `src/bootsentry/eval/judge_check.py`, `tests/test_judge_check.py` |
| **F-12** | CRITICAL | IN PROGRESS | Remove unverified C stub in `c_src/` or quarantine under `experimental/` with non-implemented flags. | `c_src/` removal |
| **F-05** | HIGH | IN PROGRESS | Replace static host baseline in EWMA with warmup-window host-relative reference standardisation; test sequential causality. | `src/bootsentry/detect/ewma.py`, `tests/test_ewma_causality.py` |
| **F-08** | HIGH | IN PROGRESS | Regenerate telemetry dataset with real process execution variance; un-silence zero-delta collector paths. | `data/telemetry/normal_boots.jsonl`, `src/bootsentry/telemetry/capture.py` |
| **F-09** | HIGH | IN PROGRESS | Add `scale_source` to attribution engine; emit explicit fallback notices instead of artificial sigma ratios for zero-MAD. | `src/bootsentry/detect/attribution.py` |
| **F-11** | HIGH | IN PROGRESS | Remove literal 1.0 injection for A1 and hardcoded ablation values in `evaluate.py`; compute all metrics from real arrays. | `src/bootsentry/eval/evaluate.py` |
| **F-13** | HIGH | IN PROGRESS | Address C subtree 28-D feature indexing mismatch by pruning unverified C subtree. | `c_src/` removal |
| **F-16** | HIGH | IN PROGRESS | Require challenger-provided `expected_nonce` in attestation verification; add ISO-8601 UTC timestamp. | `src/bootsentry/measure/quote.py` |
| **F-17** | HIGH | IN PROGRESS | Pin expected public key in `verify_model_manifest` in `s3_init.py` prior to any model deserialization. | `src/bootsentry/boot/s3_init.py` |
| **F-19** | HIGH | IN PROGRESS | Disclose clean false warning rate and out-of-sample overlap in evaluation report and documentation. | `eval/metrics.json`, `docs/evaluation-forensics.md` |
| **F-23** | HIGH | IN PROGRESS | Update `docs/leakage-audit.md` with measured column variance and audit of synthetic attack fixtures. | `docs/leakage-audit.md` |
| **F-14** | MEDIUM | IN PROGRESS | Prune stale C subtree transpiled trees. | `c_src/` removal |
| **F-15** | MEDIUM | IN PROGRESS | Correct documentation regarding hardware PMU claims and prune MSVC-only stub. | `docs/limitations.md`, `c_src/` removal |
| **F-18** | MEDIUM | IN PROGRESS | Document Isolation Forest score saturation characteristics above decision threshold. | `docs/security-analysis.md` |
| **F-20** | MEDIUM | IN PROGRESS | Reconcile sample-level ROC-AUC discrepancies across documentation to single measured source of truth. | `eval/project_metrics.json`, `README.md`, `docs/` |
| **F-21** | MEDIUM | IN PROGRESS | Correct rule names in documentation (`RULE_SVN_ROLLBACK`, `RULE_PCR_NOT_ALLOWLISTED`, `RULE_STAGE_MISMATCH`). | `docs/security-analysis.md`, `docs/RELEASE_TRUTH.md` |
| **F-22** | MEDIUM | IN PROGRESS | Measure and document A4 drift detection point under host-relative EWMA. | `docs/RELEASE_TRUTH.md`, `docs/limitations.md` |
| **F-24** | MEDIUM | IN PROGRESS | Accurately document attribution dispersion fallback chain (MAD -> L1 -> std -> fallback). | `docs/limitations.md` |
| **F-26** | MEDIUM | IN PROGRESS | Remove hardcoded test count fallback (90, 0) in `evidence.py`; return (-1, -1) on error. | `src/bootsentry/eval/evidence.py` |
| **F-27** | MEDIUM | IN PROGRESS | Make PQC backend selection explicit via `BOOTSENTRY_PQC_BACKEND`; avoid import-time liboqs probe. | `src/bootsentry/crypto/provider.py` |
| **F-30** | MEDIUM | IN PROGRESS | Clean up / document in-process stage execution vs separate process execution paths. | `src/bootsentry/boot/runner.py` |
| **F-28** | LOW | IN PROGRESS | Resolve relative path dependencies in library code with explicit root/config directory parameters. | `src/bootsentry/boot/s3_init.py`, `src/bootsentry/eval/trainer.py` |
| **F-29** | LOW | IN PROGRESS | Replace silent pass handlers in telemetry with debug logging to prevent unnoticed dead feature columns. | `src/bootsentry/telemetry/capture.py` |
| **A** | UNNUMBERED | IN PROGRESS | Correct documentation regarding service implementation (Python functions in S3). | `docs/architecture.md` |
| **B** | UNNUMBERED | IN PROGRESS | Enforce SVN counter against `config/svn_floor.json` at each stage transition in boot chain. | `src/bootsentry/boot/, config/svn_floor.json` |
| **C** | UNNUMBERED | IN PROGRESS | Wire PCR allowlist into deterministic rule floor with `config/pcr_allowlist.json`. | `config/pcr_allowlist.json, src/bootsentry/detect/rules.py` |
| **D** | UNNUMBERED | IN PROGRESS | Call `EventLog.verify_consistency()` at inter-stage handoff verification in boot path. | `src/bootsentry/boot/handoff.py` |
| **E** | UNNUMBERED | IN PROGRESS | Reconcile release tag and version metadata (`v1.0.2, pyproject.toml`). | `pyproject.toml, docs/RELEASE_TRUTH.md` |

---

## 3. Metric Impact Summary

*(To be finalized upon completion of Phase 4 and Phase 6 evaluation runs)*

---

## 4. Open Assumptions

*(Documented as remediation proceeds)*
