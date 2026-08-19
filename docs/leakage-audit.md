# BootSentry Feature Engineering & Telemetry Leakage Audit

**Feature Schema Version**: `FEATURE_VERSION = 1`  
**Total Continuous Features**: 28  
**Audit Objective**: Guarantee that no behavioral feature contains synthetic test-harness artifacts, timestamp leakage, scenario label markers, or artificial injector fingerprints.

---

## 1. Feature Provenance & Observed Variance Analysis

Analysis of 500 boot records in live baseline dataset (`data/telemetry/normal_boots.jsonl`):

| # | Feature Name | Units | Metric Source | Baseline Std Dev | Baseline MAD | Status / Notes |
| :- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `t_verify_s0` | ms | Monotonic clock | 2.257 ms | 1.313 ms | Live process measurement |
| 2 | `t_verify_s1` | ms | Monotonic clock | 2.110 ms | 1.071 ms | Live process measurement |
| 3 | `t_verify_s2` | ms | Monotonic clock | 2.458 ms | 1.158 ms | Live process measurement |
| 4 | `t_exec_s0` | ms | Monotonic clock | 0.314 ms | 0.166 ms | Live process measurement |
| 5 | `t_exec_s1` | ms | Monotonic clock | 15.196 ms | 1.636 ms | Live process measurement |
| 6 | `t_exec_s2` | ms | Monotonic clock | 14.527 ms | 1.628 ms | Live process measurement |
| 7 | `t_exec_s3` | ms | Monotonic clock | 77.802 ms | 40.108 ms | Live process measurement |
| 8 | `t_total_boot` | ms | Monotonic clock | 83.477 ms | 43.669 ms | Live process measurement |
| 9 | `rss_peak_mb` | MB | `psutil.Process` | 0.220 MB | 0.100 MB | Live process measurement |
| 10 | `rss_s0_mb` | MB | `psutil.Process` | 0.176 MB | 0.080 MB | Live process measurement |
| 11 | `rss_s1_mb` | MB | `psutil.Process` | 0.198 MB | 0.090 MB | Live process measurement |
| 12 | `rss_s2_mb` | MB | `psutil.Process` | 0.210 MB | 0.100 MB | Live process measurement |
| 13 | `rss_s3_mb` | MB | `psutil.Process` | 0.220 MB | 0.100 MB | Live process measurement |
| 14 | `ctx_switches_vol` | Count | `psutil.Process` | 73.462 | 45.000 | Live process measurement |
| 15 | `ctx_switches_invol` | Count | `psutil.Process` | 0.000 | 0.000 | Zero during normal boot |
| 16 | `ctx_switch_ratio` | Ratio | Math derived | 0.000 | 0.000 | Zero during normal boot |
| 17 | `page_faults_minor` | Count | OS counter | 16.348 | 0.000 | Live process measurement (L1 fallback) |
| 18 | `page_faults_major` | Count | OS counter | 0.000 | 0.000 | Zero during normal boot |
| 19 | `io_bytes_read_kb` | KB | `psutil.Process` | 0.358 KB | 0.012 KB | Live process measurement |
| 20 | `io_bytes_write_kb` | KB | `psutil.Process` | 0.021 KB | 0.019 KB | Live process measurement |
| 21 | `io_read_write_ratio`| Ratio | Math derived | 0.069 | 0.058 | Live process measurement |
| 22 | `stage_time_ratio_s0`| Ratio | Math derived | 0.016 | 0.010 | Live ratio feature ($t_{\text{S0}} / t_{\text{total}}$) |
| 23 | `stage_time_ratio_s1`| Ratio | Math derived | 0.046 | 0.017 | Live ratio feature ($t_{\text{S1}} / t_{\text{total}}$) |
| 24 | `stage_time_ratio_s2`| Ratio | Math derived | 0.046 | 0.017 | Live ratio feature ($t_{\text{S2}} / t_{\text{total}}$) |
| 25 | `stage_time_ratio_s3`| Ratio | Math derived | 0.096 | 0.066 | Live ratio feature ($t_{\text{S3}} / t_{\text{total}}$) |
| 26 | `verify_time_fraction`| Ratio | Math derived | 0.041 | 0.026 | Live ratio feature ($t_{\text{verify}} / t_{\text{total}}$) |
| 27 | `cpu_user_time_ms` | ms | `psutil.Process` | 79.981 ms | 46.870 ms | Live process measurement |
| 28 | `cpu_system_time_ms`| ms | `psutil.Process` | 22.570 ms | 15.630 ms | Live process measurement |

---

## 2. Leakage Defense Invariants

1. **No Wall-Clock Time in Anomaly Vectors**: All timing features use `time.perf_counter_ns()` deltas. No timestamps, dates, or time-of-day information are included in the feature vector.
2. **No Path or String Embeddings**: File paths, process names, and string identifiers are excluded from continuous numerical feature vectors.
3. **Load-Invariance via Ratio Features**: Absolute timings naturally vary depending on CPU frequency scaling and system load. BootSentry includes 6 normalized ratio features (`ctx_switch_ratio`, `io_read_write_ratio`, `stage_time_ratio_s0..s3`, `verify_time_fraction`) to ensure the anomaly model evaluates behavioral structure rather than raw processor clock speeds.
4. **Independent Split Normalization**: Standard scalers and normalization transformations are fitted **exclusively on clean baseline training boots** (first 80% partition, 400 boots) and never exposed to attack samples or held-out test splits during fitting.
