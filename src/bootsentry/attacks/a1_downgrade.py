"""Attack A1: Signed Version Downgrade / Rollback.

An attacker replaces the current authentic firmware component (SVN=5) with a
previously issued, authentic, cryptographically valid firmware component (SVN=3).

Traditional Verification:
- Gate 1 (Crypto): PASS (Valid ML-DSA-65 signature with vendor key)
- Gate 2 (Measurement): PASS (Valid standalone component)

BootSentry Defense:
- Deterministic Security Rule Floor: RULE_SVN_ROLLBACK triggers -> HALT
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
from bootsentry.telemetry.record import BootRecord


def execute_attack_a1(
    base_dir: Path | str = ".",
    trusted_min_svn: int = 5,
    downgrade_svn: int = 3,
) -> tuple[BootExecutionResult, BootRecord, int]:
    """Execute Attack A1 (Signed Downgrade) on Stage 2 Kernel."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"

    # Ensure baseline keys exist
    initialize_default_environment(base_dir=base)

    with tempfile.TemporaryDirectory() as tmp_run:
        # Create a legitimate OLD kernel payload and signed manifest with SVN=3
        old_payload = b"# Authentic Legacy Kernel v1.2 (contains known historical vulnerability)\nprint('Kernel v1.2 loaded')"
        digest, size = compute_payload_sha256(old_payload)

        # Sign with authentic S1 key
        _, _, s1_sk = load_secret_key(keys_dir / "s1_private.json")
        m_old = Manifest(
            stage_id="S2",
            version="1.2.0",
            security_version_counter=downgrade_svn,  # Downgraded SVN
            algorithm="ML-DSA-65",
            payload_sha256=digest,
            payload_size=size,
            expected_pcr="0" * 64,
            metadata={"description": "Legacy signed kernel component"},
        )
        signed_m_old = sign_manifest(m_old, s1_sk)

        # Temporary stages dir with downgraded S2
        tmp_stages = Path(tmp_run) / "stages"
        tmp_stages.mkdir()
        for f in stages_dir.glob("*"):
            if f.is_file():
                (tmp_stages / f.name).write_bytes(f.read_bytes())

        signed_m_old.save(tmp_stages / "s2_manifest.json")
        (tmp_stages / "s2_payload.bin").write_bytes(old_payload)

        # Execute boot chain
        boot_res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=tmp_stages,
            run_dir=Path(tmp_run) / "run",
        )

        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="a1_downgrade",
            scenario="a1_downgrade",
            crypto_status="PASS" if boot_res.status == "COMPLETED" else "FAIL",
            measurement_status="PASS",
            total_boot_time_ms=boot_res.total_boot_time_ms,
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
            event_sequence=[e.stage_id for e in boot_res.event_log.entries],
        )

        return boot_res, record, downgrade_svn
