"""Feature engineering and extraction for BootSentry behavioral anomaly detection."""

from __future__ import annotations

from typing import Dict, List, Tuple
import numpy as np

from bootsentry.telemetry.record import FEATURE_VERSION, BootRecord, StageTelemetry

FEATURE_NAMES: List[str] = [
    "t_verify_s0",
    "t_verify_s1",
    "t_verify_s2",
    "t_exec_s0",
    "t_exec_s1",
    "t_exec_s2",
    "t_exec_s3",
    "t_total_boot",
    "rss_peak_mb",
    "rss_s0_mb",
    "rss_s1_mb",
    "rss_s2_mb",
    "rss_s3_mb",
    "ctx_switches_vol",
    "ctx_switches_invol",
    "ctx_switch_ratio",
    "page_faults_minor",
    "page_faults_major",
    "io_bytes_read_kb",
    "io_bytes_write_kb",
    "io_read_write_ratio",
    "stage_time_ratio_s0",
    "stage_time_ratio_s1",
    "stage_time_ratio_s2",
    "stage_time_ratio_s3",
    "verify_time_fraction",
    "cpu_user_time_ms",
    "cpu_system_time_ms",
]

NUM_FEATURES = len(FEATURE_NAMES)  # Exactly 28 features


def extract_feature_dict(record: BootRecord) -> Dict[str, float]:
    """Extract a dictionary of 28 continuous features from a BootRecord."""
    s0 = record.stages.get("S0", StageTelemetry(stage_id="S0"))
    s1 = record.stages.get("S1", StageTelemetry(stage_id="S1"))
    s2 = record.stages.get("S2", StageTelemetry(stage_id="S2"))
    s3 = record.stages.get("S3", StageTelemetry(stage_id="S3"))

    t_verify_s0 = float(s0.t_verify_ms)
    t_verify_s1 = float(s1.t_verify_ms)
    t_verify_s2 = float(s2.t_verify_ms)

    t_exec_s0 = float(s0.t_exec_ms)
    t_exec_s1 = float(s1.t_exec_ms)
    t_exec_s2 = float(s2.t_exec_ms)
    t_exec_s3 = float(s3.t_exec_ms)

    t_total = float(record.total_boot_time_ms)
    if t_total <= 0.0:
        t_total = (
            t_verify_s0
            + t_verify_s1
            + t_verify_s2
            + t_exec_s0
            + t_exec_s1
            + t_exec_s2
            + t_exec_s3
            + 1e-6
        )

    rss_0 = float(s0.rss_mb)
    rss_1 = float(s1.rss_mb)
    rss_2 = float(s2.rss_mb)
    rss_3 = float(s3.rss_mb)
    rss_peak = max(rss_0, rss_1, rss_2, rss_3, 1.0)

    ctx_vol = float(s0.ctx_switches_vol + s1.ctx_switches_vol + s2.ctx_switches_vol + s3.ctx_switches_vol)
    ctx_invol = float(s0.ctx_switches_invol + s1.ctx_switches_invol + s2.ctx_switches_invol + s3.ctx_switches_invol)
    ctx_ratio = ctx_invol / (ctx_vol + ctx_invol + 1e-6)

    pf_minor = float(s0.page_faults_minor + s1.page_faults_minor + s2.page_faults_minor + s3.page_faults_minor)
    pf_major = float(s0.page_faults_major + s1.page_faults_major + s2.page_faults_major + s3.page_faults_major)

    io_read_kb = float(s0.io_bytes_read + s1.io_bytes_read + s2.io_bytes_read + s3.io_bytes_read) / 1024.0
    io_write_kb = float(s0.io_bytes_written + s1.io_bytes_written + s2.io_bytes_written + s3.io_bytes_written) / 1024.0
    io_ratio = (io_read_kb + 1e-3) / (io_write_kb + 1e-3)

    t_s0_tot = s0.t_total_ms if s0.t_total_ms > 0 else (t_verify_s0 + t_exec_s0)
    t_s1_tot = s1.t_total_ms if s1.t_total_ms > 0 else (t_verify_s1 + t_exec_s1)
    t_s2_tot = s2.t_total_ms if s2.t_total_ms > 0 else (t_verify_s2 + t_exec_s2)
    t_s3_tot = s3.t_total_ms if s3.t_total_ms > 0 else t_exec_s3

    ratio_s0 = t_s0_tot / (t_total + 1e-6)
    ratio_s1 = t_s1_tot / (t_total + 1e-6)
    ratio_s2 = t_s2_tot / (t_total + 1e-6)
    ratio_s3 = t_s3_tot / (t_total + 1e-6)

    total_verify = t_verify_s0 + t_verify_s1 + t_verify_s2
    verify_frac = total_verify / (t_total + 1e-6)

    cpu_user = float(s0.cpu_user_ms + s1.cpu_user_ms + s2.cpu_user_ms + s3.cpu_user_ms)
    cpu_sys = float(s0.cpu_system_ms + s1.cpu_system_ms + s2.cpu_system_ms + s3.cpu_system_ms)

    return {
        "t_verify_s0": t_verify_s0,
        "t_verify_s1": t_verify_s1,
        "t_verify_s2": t_verify_s2,
        "t_exec_s0": t_exec_s0,
        "t_exec_s1": t_exec_s1,
        "t_exec_s2": t_exec_s2,
        "t_exec_s3": t_exec_s3,
        "t_total_boot": t_total,
        "rss_peak_mb": rss_peak,
        "rss_s0_mb": rss_0,
        "rss_s1_mb": rss_1,
        "rss_s2_mb": rss_2,
        "rss_s3_mb": rss_3,
        "ctx_switches_vol": ctx_vol,
        "ctx_switches_invol": ctx_invol,
        "ctx_switch_ratio": ctx_ratio,
        "page_faults_minor": pf_minor,
        "page_faults_major": pf_major,
        "io_bytes_read_kb": io_read_kb,
        "io_bytes_write_kb": io_write_kb,
        "io_read_write_ratio": io_ratio,
        "stage_time_ratio_s0": ratio_s0,
        "stage_time_ratio_s1": ratio_s1,
        "stage_time_ratio_s2": ratio_s2,
        "stage_time_ratio_s3": ratio_s3,
        "verify_time_fraction": verify_frac,
        "cpu_user_time_ms": cpu_user,
        "cpu_system_time_ms": cpu_sys,
    }


def extract_feature_vector(record: BootRecord) -> np.ndarray:
    """Extract a 1D numpy array of 28 float features in standard canonical order."""
    feat_dict = extract_feature_dict(record)
    return np.array([feat_dict[k] for k in FEATURE_NAMES], dtype=np.float64)


def extract_feature_matrix(records: List[BootRecord]) -> np.ndarray:
    """Extract a 2D numpy matrix (N, 28) for training/evaluation."""
    rows = [extract_feature_vector(rec) for rec in records]
    return np.array(rows, dtype=np.float64)
