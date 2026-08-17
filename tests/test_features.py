"""Unit tests for the 28-feature extraction pipeline."""

import numpy as np
import pytest
from bootsentry.features.extractor import (
    FEATURE_NAMES,
    NUM_FEATURES,
    extract_feature_dict,
    extract_feature_matrix,
    extract_feature_vector,
)
from bootsentry.telemetry.record import BootRecord, StageTelemetry


class TestFeatureExtractor:
    def test_feature_count_and_names(self):
        assert NUM_FEATURES == 28
        assert len(FEATURE_NAMES) == 28
        assert len(set(FEATURE_NAMES)) == 28  # All unique

    def test_extract_feature_dict_completeness(self):
        record = BootRecord(
            boot_id="test-boot-feat",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=100.0,
            stages={
                "S0": StageTelemetry(
                    "S0", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=10.0,
                    io_bytes_read=1024, io_bytes_written=2048, ctx_switches_vol=5, ctx_switches_invol=1
                ),
                "S1": StageTelemetry(
                    "S1", t_verify_ms=15.0, t_exec_ms=10.0, t_total_ms=25.0, rss_mb=12.0,
                    io_bytes_read=2048, io_bytes_written=4096, ctx_switches_vol=10, ctx_switches_invol=2
                ),
                "S2": StageTelemetry(
                    "S2", t_verify_ms=20.0, t_exec_ms=15.0, t_total_ms=35.0, rss_mb=14.0,
                    io_bytes_read=4096, io_bytes_written=1024, ctx_switches_vol=15, ctx_switches_invol=3
                ),
                "S3": StageTelemetry(
                    "S3", t_verify_ms=0.0, t_exec_ms=25.0, t_total_ms=25.0, rss_mb=16.0,
                    io_bytes_read=1024, io_bytes_written=512, ctx_switches_vol=20, ctx_switches_invol=4
                ),
            },
        )

        f_dict = extract_feature_dict(record)
        assert len(f_dict) == 28
        for name in FEATURE_NAMES:
            assert name in f_dict
            assert isinstance(f_dict[name], (int, float))

        assert f_dict["t_verify_s0"] == 10.0
        assert f_dict["t_verify_s1"] == 15.0
        assert f_dict["t_verify_s2"] == 20.0
        assert f_dict["t_exec_s3"] == 25.0
        assert f_dict["rss_peak_mb"] == 16.0
        assert f_dict["verify_time_fraction"] == pytest.approx(0.45, rel=1e-3)

    def test_extract_feature_vector_numpy(self):
        record = BootRecord(
            boot_id="test-vec",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=50.0,
        )
        vec = extract_feature_vector(record)
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (28,)
        assert not np.isnan(vec).any()

    def test_extract_feature_matrix(self):
        records = [
            BootRecord(boot_id=f"boot-{i}", timestamp_iso="2026-08-17T08:00:00Z", total_boot_time_ms=50.0 + i)
            for i in range(10)
        ]
        mat = extract_feature_matrix(records)
        assert mat.shape == (10, 28)
        assert not np.isnan(mat).any()
