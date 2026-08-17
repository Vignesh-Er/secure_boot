# BootSentry Feature Engineering & Telemetry Leakage Audit

**Feature Schema Version**: `FEATURE_VERSION = 1`  
**Total Continuous Features**: 28  
**Audit Objective**: Guarantee that no behavioral feature contains synthetic test-harness artifacts, timestamp leakage, scenario label markers, or artificial injector fingerprints.

---

## 1. Feature Provenance & Leakage Analysis

| # | Feature Name | Units | Metric Source | Leakage Risk Assessment | Protection / Normalization Applied |
| :- | :--- | :--- | :--- | :--- | :--- |
| 1 | `t_verify_s0` | ms | High-res monotonic counter | Low (Microseconds) | Measures ML-DSA-65 verify duration of S1 manifest. |
| 2 | `t_verify_s1` | ms | High-res monotonic counter | Low (Microseconds) | Measures ML-DSA-65 verify duration of S2 manifest. |
| 3 | `t_verify_s2` | ms | High-res monotonic counter | Low (Microseconds) | Measures ML-DSA-65 verify duration of S3 manifest. |
| 4 | `t_exec_s0` | ms | High-res monotonic counter | Low | BootROM self-test execution time. |
| 5 | `t_exec_s1` | ms | High-res monotonic counter | Low | Bootloader memory & device-tree synthesis time. |
| 6 | `t_exec_s2` | ms | High-res monotonic counter | Low | Kernel task allocation and table init time. |
| 7 | `t_exec_s3` | ms | High-res monotonic counter | Low | Init service suite orchestration time. |
| 8 | `t_total_boot` | ms | Monotonic delta ($t_{\text{end}} - t_{\text{start}}$) | Low | Total wall-time of boot sequence. |
| 9 | `rss_peak_mb` | MB | `psutil.Process.memory_info()` | None | Peak memory residency across boot processes. |
| 10 | `rss_s0_mb` | MB | `psutil.Process.memory_info()` | None | Stage 0 process memory usage. |
| 11 | `rss_s1_mb` | MB | `psutil.Process.memory_info()` | None | Stage 1 process memory usage. |
| 12 | `rss_s2_mb` | MB | `psutil.Process.memory_info()` | None | Stage 2 process memory usage. |
| 13 | `rss_s3_mb` | MB | `psutil.Process.memory_info()` | None | Stage 3 process memory usage. |
| 14 | `ctx_switches_vol` | Count | `num_ctx_switches().voluntary` | None | Voluntary context switch count. |
| 15 | `ctx_switches_invol` | Count | `num_ctx_switches().involuntary`| None | Involuntary context switch count. |
| 16 | `ctx_switch_ratio` | Ratio [0,1] | Math derived | None | Involuntary / Total switches (load-invariant). |
| 17 | `page_faults_minor` | Count | OS page fault counters | None | Minor page faults during stage allocations. |
| 18 | `page_faults_major` | Count | OS page fault counters | None | Major page faults (disk swap events). |
| 19 | `io_bytes_read_kb` | KB | `psutil.Process.io_counters()` | None | Aggregate bytes read from storage. |
| 20 | `io_bytes_write_kb` | KB | `psutil.Process.io_counters()` | None | Aggregate bytes written to storage. |
| 21 | `io_read_write_ratio`| Ratio | Math derived | None | Read/Write balance ratio. |
| 22 | `stage_time_ratio_s0`| Ratio [0,1] | Math derived | None | $t_{\text{S0}} / t_{\text{total}}$ (clock-speed invariant). |
| 23 | `stage_time_ratio_s1`| Ratio [0,1] | Math derived | None | $t_{\text{S1}} / t_{\text{total}}$ (clock-speed invariant). |
| 24 | `stage_time_ratio_s2`| Ratio [0,1] | Math derived | None | $t_{\text{S2}} / t_{\text{total}}$ (clock-speed invariant). |
| 25 | `stage_time_ratio_s3`| Ratio [0,1] | Math derived | None | $t_{\text{S3}} / t_{\text{total}}$ (clock-speed invariant). |
| 26 | `verify_time_fraction`| Ratio [0,1]| Math derived | None | PQC verify time fraction of total boot. |
| 27 | `cpu_user_time_ms` | ms | `cpu_times().user` delta | None | User mode CPU consumption. |
| 28 | `cpu_system_time_ms`| ms | `cpu_times().system` delta | None | Kernel mode CPU consumption. |

---

## 2. Leakage Defense Invariants

1. **No Wall-Clock Time in Anomaly Vectors**: All timing features use `time.perf_counter_ns()` deltas. No timestamps, dates, or time-of-day information are included in the feature vector.
2. **No Path or String Embeddings**: File paths, process names, and string identifiers are excluded from continuous numerical feature vectors.
3. **Load-Invariance via Ratio Features**: Absolute timings naturally vary depending on CPU frequency scaling and system load. BootSentry includes 6 normalized ratio features (`ctx_switch_ratio`, `io_read_write_ratio`, `stage_time_ratio_s0..s3`, `verify_time_fraction`) to ensure the anomaly model evaluates behavioral structure rather than raw processor clock speeds.
4. **Independent Split Normalization**: Standard scalers and normalization transformations are fitted **exclusively on clean baseline training boots** and never exposed to attack samples or held-out test splits during fitting.
