"""Attack A5: Cross-SKU Substitution (Held-Out Generalization Evaluation).

In accordance with Security Invariant 6:
- Attack A5 is strictly held out during feature engineering, threshold tuning, and model selection.
- Evaluates whether the behavioral anomaly detector generalizes to unauthorized cross-hardware
  component transplantation without explicit prior training on that specific SKU profile.

Traditional Verification:
- Gate 1 (Crypto): PASS (Valid signature with OEM root key)
- Gate 2 (Measurement): PASS (Valid measurement structure)

BootSentry Defense:
- Evaluated strictly out-of-sample on the held-out test split.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Tuple

from bootsentry.boot.runner import BootExecutionResult, execute_boot_chain, initialize_default_environment
from bootsentry.crypto.keys import load_secret_key
from bootsentry.crypto.manifest import Manifest, compute_payload_sha256
from bootsentry.crypto.sign import sign_manifest
from bootsentry.telemetry.record import BootRecord, StageTelemetry


def execute_attack_a5(
    base_dir: Path | str = ".",
    foreign_sku_name: str = "SKU-SERVER-RACK-8P",
) -> Tuple[BootExecutionResult, BootRecord]:
    """Execute Held-Out Attack A5 (Cross-SKU component transplantation)."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"

    initialize_default_environment(base_dir=base)

    with tempfile.TemporaryDirectory() as tmp_run:
        # Cross-SKU kernel payload designed for server class with larger thread tables
        sku_payload = (
            f"# Firmware image compiled for foreign hardware profile {foreign_sku_name}\n"
            "print('Initializing 128-core CPU NUMA topology...')"
        ).encode("utf-8")
        digest, size = compute_payload_sha256(sku_payload)

        # Authentically signed by OEM root key
        _, _, s1_sk = load_secret_key(keys_dir / "s1_private.json")
        m_sku = Manifest(
            stage_id="S2",
            version="6.1.0-server",
            security_version_counter=5,
            algorithm="ML-DSA-65",
            payload_sha256=digest,
            payload_size=size,
            expected_pcr="0" * 64,
            metadata={"target_sku": foreign_sku_name, "architecture": "x86_64_numa"},
        )
        signed_m_sku = sign_manifest(m_sku, s1_sk)

        tmp_stages = Path(tmp_run) / "stages"
        tmp_stages.mkdir()
        for f in stages_dir.glob("*"):
            if f.is_file():
                (tmp_stages / f.name).write_bytes(f.read_bytes())

        signed_m_sku.save(tmp_stages / "s2_manifest.json")
        (tmp_stages / "s2_payload.bin").write_bytes(sku_payload)

        boot_res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=tmp_stages,
            run_dir=Path(tmp_run) / "run",
        )

        # Telemetry reflecting server-kernel memory footprint mismatch on edge target
        stages_telemetry = {
            "S0": StageTelemetry("S0", t_verify_ms=5.0, t_exec_ms=2.0, t_total_ms=7.0, rss_mb=12.0),
            "S1": StageTelemetry("S1", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=14.0),
            "S2": StageTelemetry(
                "S2",
                t_verify_ms=15.0,
                t_exec_ms=38.0,  # NUMA table setup overhead on edge CPU
                t_total_ms=53.0,
                rss_mb=64.0,   # Server kernel large memory allocation
                io_bytes_read=32768,
                ctx_switches_vol=28,
                ctx_switches_invol=8,
            ),
            "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=15.0, t_total_ms=15.0, rss_mb=20.0),
        }

        total_time = boot_res.total_boot_time_ms + 23.0
        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="a5_cross_sku",
            scenario="a5_cross_sku",
            crypto_status="PASS",
            measurement_status="PASS",
            total_boot_time_ms=total_time,
            stages=stages_telemetry,
            event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
            metadata={"foreign_sku": foreign_sku_name, "held_out_evaluation": True},
        )

        return boot_res, record
