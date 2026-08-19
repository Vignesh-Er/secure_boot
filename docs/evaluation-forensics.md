# BootSentry Evaluation Forensics & Metric Discrepancy Analysis

**Investigation Target**: Forensic audit of evaluation metrics, sample-level vs scenario-level partitioning, and attribution scales.  
**Audited Baseline Output**: `eval/baseline_before/metrics.json`  

---

## 1. Metric Semantics & Evaluation Framework

To maintain complete scientific integrity, BootSentry enforces a strict tripartite separation of evaluation metrics:

1. **Scenario-Level Benchmark (`scenario_level`)**:
   - **Unit of Evaluation**: 1 aggregate sample per attack / benign scenario ($N=48$, $n_{pos}=5, n_{neg}=43$).
   - **Score Metric**: `PolicyDecision.risk_score`.
   - **Scope**: Evaluates the complete defense pipeline combining deterministic rule checks (Gate 1 & 2) and behavioral detectors.
   - **Measured Baseline (Pre-Remediation)**: **ROC-AUC = 0.9953**, **PR-AUC = 0.9667**, **FPR @ 95% TPR = 0.0233**.

2. **Continuous Sample-Level Benchmark (`sample_level`)**:
   - **Unit of Evaluation**: 1 sample per individual executed boot record ($N=68$, $n_{pos}=25, n_{neg}=43$).
   - **Scope**: Evaluates continuous ML detector scores directly on individual telemetry records without rule-based HALTs.
   - **Measured Baseline (Pre-Remediation)**: **ROC-AUC = 0.9874**, **PR-AUC = 0.9820**, **FPR @ 95% TPR = 0.0698**.

3. **Detector Ablations (`detector_ablation`)**:
   - **Isolation Forest Alone**: Evaluated on spatial anomaly scenarios (A2, A4 end, A5, $n_{pos}=3, n_{neg}=40$); Measured ROC-AUC = 0.9750, PR-AUC = 0.7556, FPR @ 95% = 0.0500.
   - **Markov Sequence Detector Alone**: Evaluated on service sequence ordering (A3, $n_{pos}=1, n_{neg}=40$); Measured ROC-AUC is 1.0, PR-AUC is 1.0.
   - **EWMA / CUSUM Monitor Alone**: Sequential drift monitor evaluated across 20-boot drift sequence; flags cumulative drift at Boot 5 with peak score 1.0.

---

## 2. Evaluation Protocol Comparison

| Evaluation Dimension | Shipped Baseline Dataset | Pre-Remediation Measured Output | Remediation Target (Phases 3-4) |
|---|---|---|---|
| **Normal Baseline Boots** | 200 process boots | 200 process boots | 500 genuine process boots |
| **Train / Test Split** | 160 Train / 40 Test (80/20) | 160 Train / 40 Test (80/20) | 400 Train / 100 Test (80/20) |
| **A5 Held-Out Guarantee** | Strictly out-of-sample | Evaluated without retraining | Strictly out-of-sample |
| **Scenario ROC-AUC** | Claimed 1.0 (inflated) | **0.9953** ($n_{pos}=5$) | Measured dynamically |
| **Scenario PR-AUC** | Claimed 1.0 (inflated) | **0.9667** ($n_{pos}=5$) | Measured dynamically |
| **Sample-Level ROC-AUC** | Conflicted (0.937 / 0.956) | **0.9874** ($n_{pos}=25$) | Measured dynamically |
| **Sample-Level PR-AUC** | Conflicted (0.945 / 0.969) | **0.9820** ($n_{pos}=25$) | Measured dynamically |
| **Clean False Warning Rate**| Disclosed | **0.0500** (2/40 held-out boots $\ge 0.5$) | Measured dynamically |

---

## 3. Score Distribution & Scenario Breakdown

### Measured Baseline Scores (`eval/baseline_before/metrics.json`):
- **Clean Test Normal Boots ($N=40$)**: Mean $S_{risk} \approx 0.156$, Median $\approx 0.087$, Max $= 0.5735$.
- **Attack A1 (Signed Downgrade)**: Rule `RULE_SVN_ROLLBACK` tripped $\implies$ `HALT`.
- **Attack A2 (TOCTOU Config Swap)**: Isolation Forest $= 0.5259$ $\implies$ `WARN`.
- **Attack A3 (Service Reorder)**: Markov $= 1.0$ $\implies$ `WARN`.
- **Attack A4 (Slow Drift Sequence)**: Drift detected at Boot 5, Peak Drift Score $= 1.0$ $\implies$ `WARN + ATTEST`.
- **Attack A5 (Cross-SKU Held-Out)**: Isolation Forest $= 0.5960$ $\implies$ `WARN`.
- **Benign Controls (B1, B2, B3)**:
  - B1 (Cold Cache): Risk $= 0.4116$ (`PASS`, 0 False Halts)
  - B2 (Firmware Upgrade): Risk $= 0.3622$ (`PASS`, 0 False Halts)
  - B3 (Host CPU Load): Risk $= 0.3826$ (`PASS`, 0 False Halts)

---

## 4. Feature Attribution & Dispersion Fallback Policy (F-09, F-24)

In standard robust statistics, $z = \frac{x - \text{median}}{1.4826 \times \text{MAD}}$. When a feature is invariant on the clean baseline, $\text{MAD} = 0$.
The `AttributionEngine` enforces a 4-tier dispersion policy:
1. **Standard Dispersion ($\text{MAD} > 10^{-6}$)**: $\text{scale} = 1.4826 \times \text{MAD}$ (`scale_source = "mad"`).
2. **Mean Absolute Deviation ($\text{MAD} \le 10^{-6}, S_{L1} > 10^{-6}$)**: $\text{scale} = 1.2533 \times S_{L1}$ (`scale_source = "l1"`).
3. **Standard Deviation ($S_{L1} \le 10^{-6}, \sigma > 10^{-6}$)**: $\text{scale} = \sigma$ (`scale_source = "std"`).
4. **Degenerate Baseline Invariance ($\sigma \le 10^{-6}$)**: Fallback scale $\max(1.0, 0.1 \times |\text{median}|)$ (`scale_source = "degenerate"`).

When `scale_source == "degenerate"`, the attribution engine avoids rendering misleading multi-thousand sigma values and explicitly formats as `"{observed:.3g} vs baseline {median:.3g} (no dispersion in baseline)"`.
