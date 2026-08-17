"""Unit tests for Process Telemetry and JSONL Logger."""

import pytest
from pathlib import Path
from bootsentry.telemetry.capture import ProcessTelemetrySampler
from bootsentry.telemetry.logger import log_boot_record, read_boot_records, iter_boot_records
from bootsentry.telemetry.record import BootRecord, StageTelemetry, FEATURE_VERSION


class TestTelemetryCapture:
    def test_sampler_start_stop(self):
        sampler = ProcessTelemetrySampler()
        sampler.start()
        # Perform some work
        _ = sum(i * i for i in range(100_000))
        telemetry = sampler.stop(stage_id="S1", t_verify_ms=1.5)

        assert telemetry.stage_id == "S1"
        assert telemetry.t_verify_ms == 1.5
        assert telemetry.t_total_ms > 0.0
        assert telemetry.t_exec_ms >= 0.0
        assert telemetry.rss_mb >= 0.0

    def test_boot_record_serialization_roundtrip(self, tmp_path):
        record = BootRecord(
            boot_id="test-boot-1234",
            timestamp_iso="2026-08-17T08:00:00Z",
            feature_version=FEATURE_VERSION,
            label="normal",
            scenario="clean",
            total_boot_time_ms=45.2,
            stages={
                "S0": StageTelemetry("S0", t_verify_ms=2.1, t_exec_ms=1.5, t_total_ms=3.6, rss_mb=12.0),
                "S1": StageTelemetry("S1", t_verify_ms=5.0, t_exec_ms=8.0, t_total_ms=13.0, rss_mb=14.5),
            },
            event_sequence=["S0_INIT", "S1_START", "svc_a"],
            pcr_snapshot={"PCR0": "a" * 64, "PCR1": "b" * 64},
            feature_vector={"t_total_boot": 45.2},
        )

        log_file = tmp_path / "test_telemetry.jsonl"
        log_boot_record(record, log_file)

        records = read_boot_records(log_file)
        assert len(records) == 1
        r = records[0]
        assert r.boot_id == "test-boot-1234"
        assert r.feature_version == FEATURE_VERSION
        assert len(r.stages) == 2
        assert r.stages["S0"].t_verify_ms == 2.1
        assert r.event_sequence == ["S0_INIT", "S1_START", "svc_a"]

    def test_iter_boot_records(self, tmp_path):
        log_file = tmp_path / "multi_telemetry.jsonl"
        for i in range(5):
            rec = BootRecord(
                boot_id=f"boot-{i}",
                timestamp_iso="2026-08-17T08:00:00Z",
                total_boot_time_ms=10.0 + i,
            )
            log_boot_record(rec, log_file)

        streamed = list(iter_boot_records(log_file))
        assert len(streamed) == 5
        assert streamed[2].boot_id == "boot-2"
