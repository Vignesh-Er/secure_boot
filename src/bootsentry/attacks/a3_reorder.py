"""Attack A3: Signed Service Reorder Attack.

An attacker manipulates the Stage 3 init service execution order, launching
services in an abnormal sequence or inserting an unexpected diagnostic service.

Traditional Verification:
- Gate 1 (Crypto): PASS (Every individual service binary is authentic and signed)
- Gate 2 (Measurement): PASS (Individual measurements valid)

BootSentry Defense:
- Gate 3 (Markov Chain Sequence Model): Detects zero-support / anomalous state transition
- Policy: WARN + REDUCED TRUST Attestation
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Tuple

from bootsentry.boot.runner import BootExecutionResult, execute_boot_chain, initialize_default_environment
from bootsentry.telemetry.record import BootRecord, StageTelemetry


def execute_attack_a3(
    base_dir: Path | str = ".",
    reordered_sequence: Optional[List[str]] = None,
) -> Tuple[BootExecutionResult, BootRecord]:
    """Execute Attack A3 (Signed Service Reorder)."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"

    initialize_default_environment(base_dir=base)

    # Abnormal sequence: svc_e executed before svc_a, plus diagnostic service inserted
    seq = reordered_sequence or ["svc_e", "svc_diag", "svc_a", "svc_c", "svc_attest"]

    with tempfile.TemporaryDirectory() as tmp_run:
        boot_res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=Path(tmp_run) / "run",
            service_sequence=seq,
        )

        stages_telemetry = {
            "S0": StageTelemetry("S0", t_verify_ms=5.0, t_exec_ms=2.0, t_total_ms=7.0, rss_mb=12.0),
            "S1": StageTelemetry("S1", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=14.0),
            "S2": StageTelemetry("S2", t_verify_ms=15.0, t_exec_ms=10.0, t_total_ms=25.0, rss_mb=16.0),
            "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=25.0, t_total_ms=25.0, rss_mb=18.0),
        }

        # Sequence recorded from event log
        event_seq = [
            e.event_data.get("service_name", e.stage_id)
            for e in boot_res.event_log.entries
        ]

        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="a3_reorder",
            scenario="a3_reorder",
            crypto_status="PASS",
            measurement_status="PASS",
            total_boot_time_ms=boot_res.total_boot_time_ms,
            stages=stages_telemetry,
            event_sequence=event_seq,
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
        )

        return boot_res, record
