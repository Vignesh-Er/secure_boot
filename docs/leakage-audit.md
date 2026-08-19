# BootSentry Feature Engineering & Telemetry Leakage Audit

**Feature Schema Version**: `FEATURE_VERSION = 1`  
**Total Continuous Features**: 28  
**Audit Objective**: Guarantee that no behavioral feature contains synthetic test-harness artifacts, timestamp leakage, scenario label markers, or artificial injector fingerprints.

---

## 1. Feature Provenance & Observed Variance Analysis

Analysis of 200 boot records in baseline dataset (`data/telemetry/normal_boots.jsonl`):

| # | Feature Name | Units | Metric Source | Baseline Std Dev | Baseline MAD | Status / Notes |
| :- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `t_verify_s0` | ms | Monotonic clock | 2.805 ms | 0.193 ms | Live timing feature (S1 verify) |
| 2 | `t_verify_s1` | ms | Monotonic clock | 2.507 ms | 0.217 ms | Live timing feature (S2 verify) |
| 3 | `t_verify_s2` | ms | Monotonic clock | 3.736 ms | 0.214 ms | Live timing feature (S3 verify) |
| 4 | `t_exec_s0` | ms | Monotonic clock | 2.290 ms | 0.095 ms | Live timing feature (S0 exec) |
| 5 | `t_exec_s1` | ms | Monotonic clock | 3.161 ms | 1.447 ms | Live timing feature (S1 exec) |
| 6 | `t_exec_s2` | ms | Monotonic clock | 2.850 ms | 1.237 ms | Live timing feature (S2 exec) |
| 7 | `t_exec_s3` | ms | Monotonic clock | 65.237 ms | 35.963 ms | Live timing feature (S3 exec) |
| 8 | `t_total_boot` | ms | Monotonic clock | 66.717 ms | 40.854 ms | Live timing feature (Total boot) |
| 9 | `rss_peak_mb` | MB | `psutil.Process` | 0.000 MB | 0.000 MB | Constant in shipped dataset (remediated in Phase 4) |
| 10 | `rss_s0_mb` | MB | `psutil.Process` | 0.000 MB | 0.000 MB | Constant in shipped dataset (remediated in Phase 4) |
| 11 | `rss_s1_mb` | MB | `psutil.Process` | 0.000 MB | 0.000 MB | Constant in shipped dataset (remediated in Phase 4) |
| 12 | `rss_s2_mb` | MB | `psutil.Process` | 0.000 MB | 0.000 MB | Constant in shipped dataset (remediated in Phase 4) |
| 13 | `rss_s3_mb` | MB | `psutil.Process` | 0.000 MB | 0.000 MB | Constant in shipped dataset (remediated in Phase 4) |
| 14 | `ctx_switches_vol` | Count | `psutil.Process` | 0.000 | 0.000 | Zero-delta in shipped dataset |
| 15 | `ctx_switches_invol` | Count | `psutil.Process` | 0.000 | 0.000 | Zero-delta in shipped dataset |
| 16 | `ctx_switch_ratio` | Ratio | Math derived | 0.000 | 0.000 | Zero-delta in shipped dataset |
| 17 | `page_faults_minor` | Count | OS counter | 0.000 | 0.000 | Zero-delta in shipped dataset |
| 18 | `page_faults_major` | Count | OS counter | 0.000 | 0.000 | Zero-delta in shipped dataset |
| 19 | `io_bytes_read_kb` | KB | `psutil.Process` | 0.000 KB | 0.000 KB | Zero-delta in shipped dataset |
| 20 | `io_bytes_write_kb` | KB | `psutil.Process` | 0.000 KB | 0.000 KB | Zero-delta in shipped dataset |
| 21 | `io_read_write_ratio`| Ratio | Math derived | 0.000 | 0.000 | Zero-delta in shipped dataset |
| 22 | `stage_time_ratio_s0`| Ratio | Math derived | 0.023 | 0.017 | Live ratio feature ($t_{\text{S0}} / t_{\text{total}}$) |
| 23 | `stage_time_ratio_s1`| Ratio | Math derived | 0.038 | 0.028 | Live ratio feature ($t_{\text{S1}} / t_{\text{total}}$) |
| 24 | `stage_time_ratio_s2`| Ratio | Math derived | 0.038 | 0.030 | Live ratio feature ($t_{\text{S2}} / t_{\text{total}}$) |
| 25 | `stage_time_ratio_s3`| Ratio | Math derived | 0.104 | 0.078 | Live ratio feature ($t_{\text{S3}} / t_{\text{total}}$) |
| 26 | `verify_time_fraction`| Ratio | Math derived | 0.059 | 0.043 | Live ratio feature ($t_{\text{verify}} / t_{\text{total}}$) |
| 27 | `cpu_user_time_ms` | ms | `psutil.Process` | 0.000 ms | 0.000 ms | Zero-delta in shipped dataset |
| 28 | `cpu_system_time_ms`| ms | `psutil.Process` | 0.000 ms | 0.000 ms | Zero-delta in shipped dataset |

> [!WARNING]
> **Audit Finding (F-08 & F-23)**: In the initial shipped dataset, 15 out of 28 features exhibited zero variance because rapid in-process stage execution returned zero deltas on host process counters. Synthetic attack fixtures populated non-zero values in these zero-variance columns, which inflated model separation. In Phase 4, the collector and all attack scenarios are unified through `telemetry/builder.py` with live execution.

---

## 2. Leakage Defense Invariants

1. **No Wall-Clock Time in Anomaly Vectors**: All timing features use `time.perf_counter_ns()` deltas. No timestamps, dates, or time-of-day information are included in the feature vector.
2. **No Path or String Embeddings**: File paths, process names, and string identifiers are excluded from continuous numerical feature vectors.
3. **Load-Invariance via Ratio Features**: Absolute timings naturally vary depending on CPU frequency scaling and system load. BootSentry includes 6 normalized ratio features (`ctx_switch_ratio`, `io_read_write_ratio`, `stage_time_ratio_s0..s3`, `verify_time_fraction`) to ensure the anomaly model evaluates behavioral structure rather than raw processor clock speeds.
4. **Independent Split Normalization**: Standard scalers and normalization transformations are fitted **exclusively on clean baseline training boots** and never exposed to attack samples or held-out test splits during fitting.
