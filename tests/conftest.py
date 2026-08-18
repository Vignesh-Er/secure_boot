"""Shared pytest fixtures for the BootSentry test suite."""

import numpy as np
import pytest

from bootsentry.boot.runner import initialize_default_environment
from bootsentry.crypto.manifest import Manifest
from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank
from bootsentry.telemetry.record import BootRecord, StageTelemetry


@pytest.fixture
def boot_env(tmp_path):
    """Provide a clean isolated environment with initialized keys and stage manifests."""
    keys_dir, stages_dir = initialize_default_environment(base_dir=tmp_path)
    return tmp_path, keys_dir, stages_dir


@pytest.fixture
def clean_pcr_bank():
    """Provide a fresh software TPM PCR bank."""
    return PcrBank()


@pytest.fixture
def clean_event_log():
    """Provide a fresh append-only event log."""
    return EventLog()


@pytest.fixture
def sample_manifest():
    """Provide a standard clean S1 boot stage manifest."""
    return Manifest(
        stage_id="S1",
        version="1.0.0",
        security_version_counter=5,
        algorithm="ML-DSA-65",
        payload_sha256="a" * 64,
        payload_size=1024,
        expected_pcr="0" * 64,
        metadata={"description": "Fixture test manifest"},
    )


@pytest.fixture
def sample_boot_record():
    """Provide a realistic sample BootRecord with 4 stages for testing."""
    return BootRecord(
        boot_id="test-boot-001",
        timestamp=1700000000.0,
        stages={
            "S0": StageTelemetry(
                stage_id="S0",
                t_exec_ms=3.0,
                t_verify_ms=1.5,
                rss_mb=12.0,
                cpu_user_ms=2.0,
                cpu_sys_ms=0.5,
                ctx_vol=5,
                ctx_invol=0,
                io_read_kb=10.0,
                io_write_kb=5.0,
                pf_minor=50,
                pf_major=0,
            ),
            "S1": StageTelemetry(
                stage_id="S1",
                t_exec_ms=8.0,
                t_verify_ms=2.0,
                rss_mb=14.0,
                cpu_user_ms=6.0,
                cpu_sys_ms=1.0,
                ctx_vol=10,
                ctx_invol=1,
                io_read_kb=20.0,
                io_write_kb=8.0,
                pf_minor=120,
                pf_major=0,
            ),
            "S2": StageTelemetry(
                stage_id="S2",
                t_exec_ms=25.0,
                t_verify_ms=5.0,
                rss_mb=32.0,
                cpu_user_ms=20.0,
                cpu_sys_ms=3.0,
                ctx_vol=30,
                ctx_invol=2,
                io_read_kb=100.0,
                io_write_kb=40.0,
                pf_minor=350,
                pf_major=1,
            ),
            "S3": StageTelemetry(
                stage_id="S3",
                t_exec_ms=12.0,
                t_verify_ms=0.0,
                rss_mb=18.0,
                cpu_user_ms=9.0,
                cpu_sys_ms=1.5,
                ctx_vol=15,
                ctx_invol=0,
                io_read_kb=15.0,
                io_write_kb=10.0,
                pf_minor=90,
                pf_major=0,
            ),
        },
        label="normal",
        metadata={"scenario": "clean"},
    )


@pytest.fixture
def rng():
    """Provide a deterministic seeded NumPy random generator."""
    return np.random.default_rng(42)
