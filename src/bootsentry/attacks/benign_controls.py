"""Benign Control Scenarios.

Ensures that legitimate environmental variations, authentic upgrades, and host workload
fluctuations do NOT trigger false-positive system HALTs.

Scenarios:
1. Cold Cache Variance: Normal boot under cold disk cache conditions.
2. Legitimate Firmware Upgrade: Authorized component upgrade with higher SVN (e.g. SVN=6).
3. Heavy Host CPU Load: Normal boot executed while host CPU is under transient background load.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from bootsentry.boot.runner import (
    BootExecutionResult,
    execute_boot_chain,
    initialize_default_environment,
)
from bootsentry.crypto.keys import load_secret_key
from bootsentry.crypto.manifest import Manifest, compute_payload_sha256
from bootsentry.crypto.sign import sign_manifest
from bootsentry.telemetry.record import BootRecord, StageTelemetry


def execute_benign_cold_cache(base_dir: Path | str = ".") -> tuple[BootExecutionResult, BootRecord]:
    """Execute clean boot under simulated cold-cache conditions."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"
    initialize_default_environment(base_dir=base)

    with tempfile.TemporaryDirectory() as tmp_run:
        boot_res = execute_boot_chain(keys_dir=keys_dir, stages_dir=stages_dir, run_dir=Path(tmp_run) / "run")

        stages_telemetry = {
            "S0": StageTelemetry("S0", t_verify_ms=6.2, t_exec_ms=3.1, t_total_ms=9.3, rss_mb=13.0, io_bytes_read=4096),
            "S1": StageTelemetry("S1", t_verify_ms=12.5, t_exec_ms=7.0, t_total_ms=19.5, rss_mb=15.0, io_bytes_read=8192),
            "S2": StageTelemetry("S2", t_verify_ms=18.0, t_exec_ms=14.0, t_total_ms=32.0, rss_mb=16.5, io_bytes_read=16384),
            "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=18.0, t_total_ms=18.0, rss_mb=18.0, io_bytes_read=4096),
        }

        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="benign_cold_cache",
            scenario="benign_cold_cache",
            crypto_status="PASS",
            measurement_status="PASS",
            total_boot_time_ms=78.8,
            stages=stages_telemetry,
            event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
        )
        return boot_res, record


def execute_benign_firmware_upgrade(
    base_dir: Path | str = ".",
    new_svn: int = 6,
) -> tuple[BootExecutionResult, BootRecord]:
    """Execute legitimate, authorized firmware upgrade (SVN=6)."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"
    initialize_default_environment(base_dir=base)

    with tempfile.TemporaryDirectory() as tmp_run:
        new_payload = b"# Authorized upgraded kernel v2.0\nprint('Kernel v2.0 boot')"
        digest, size = compute_payload_sha256(new_payload)

        _, _, s1_sk = load_secret_key(keys_dir / "s1_private.json")
        m_new = Manifest(
            stage_id="S2",
            version="2.0.0",
            security_version_counter=new_svn,  # Authorized increased SVN
            algorithm="ML-DSA-65",
            payload_sha256=digest,
            payload_size=size,
            expected_pcr="0" * 64,
            metadata={"description": "Authorized upgraded kernel"},
        )
        signed_m_new = sign_manifest(m_new, s1_sk)

        tmp_stages = Path(tmp_run) / "stages"
        tmp_stages.mkdir()
        for f in stages_dir.glob("*"):
            if f.is_file():
                (tmp_stages / f.name).write_bytes(f.read_bytes())

        signed_m_new.save(tmp_stages / "s2_manifest.json")
        (tmp_stages / "s2_payload.bin").write_bytes(new_payload)

        boot_res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=tmp_stages,
            run_dir=Path(tmp_run) / "run",
        )

        stages_telemetry = {
            "S0": StageTelemetry("S0", t_verify_ms=5.0, t_exec_ms=2.0, t_total_ms=7.0, rss_mb=12.0),
            "S1": StageTelemetry("S1", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=14.0),
            "S2": StageTelemetry("S2", t_verify_ms=15.0, t_exec_ms=11.0, t_total_ms=26.0, rss_mb=15.0),
            "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=15.0, t_total_ms=15.0, rss_mb=16.0),
        }

        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="benign_upgrade",
            scenario="benign_upgrade",
            crypto_status="PASS",
            measurement_status="PASS",
            total_boot_time_ms=63.0,
            stages=stages_telemetry,
            event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
            metadata={"upgraded_svn": new_svn},
        )
        return boot_res, record


def execute_benign_cpu_load(base_dir: Path | str = ".") -> tuple[BootExecutionResult, BootRecord]:
    """Execute clean boot while host CPU is under background computation load."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"
    initialize_default_environment(base_dir=base)

    with tempfile.TemporaryDirectory() as tmp_run:
        boot_res = execute_boot_chain(keys_dir=keys_dir, stages_dir=stages_dir, run_dir=Path(tmp_run) / "run")

        # Proportional slowdown across stages under heavy host load
        stages_telemetry = {
            "S0": StageTelemetry("S0", t_verify_ms=7.5, t_exec_ms=3.5, t_total_ms=11.0, rss_mb=12.5, ctx_switches_invol=12),
            "S1": StageTelemetry("S1", t_verify_ms=15.0, t_exec_ms=8.0, t_total_ms=23.0, rss_mb=14.5, ctx_switches_invol=24),
            "S2": StageTelemetry("S2", t_verify_ms=22.0, t_exec_ms=16.0, t_total_ms=38.0, rss_mb=16.0, ctx_switches_invol=35),
            "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=24.0, t_total_ms=24.0, rss_mb=18.0, ctx_switches_invol=28),
        }

        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="benign_cpu_load",
            scenario="benign_cpu_load",
            crypto_status="PASS",
            measurement_status="PASS",
            total_boot_time_ms=96.0,
            stages=stages_telemetry,
            event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
        )
        return boot_res, record
