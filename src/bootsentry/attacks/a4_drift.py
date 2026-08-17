"""Attack A4: Slow-Drip Behavioral Implant (Multi-Boot Drift).

An attacker introduces a progressive, slowly accumulating behavioral overhead across 20 sequential boots.
Each individual boot remains close to the variance threshold, defeating single-shot memoryless verifiers,
but triggering the EWMA and CUSUM sequential drift monitor.

Traditional Verification:
- Gate 1 (Crypto): PASS (Every boot uses valid PQC signatures)
- Gate 2 (Measurement): PASS

BootSentry Defense:
- Gate 3 (EWMA / CUSUM Drift Monitor): Recognizes sustained directional drift across boots
- Policy: WARN + REDUCED TRUST Attestation
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Tuple

from bootsentry.boot.runner import BootExecutionResult, execute_boot_chain, initialize_default_environment
from bootsentry.telemetry.record import BootRecord, StageTelemetry


def execute_attack_a4_sequence(
    base_dir: Path | str = ".",
    num_boots: int = 20,
    drift_step_ms: float = 4.0,
) -> List[Tuple[BootExecutionResult, BootRecord]]:
    """Execute a 20-boot sequential Slow-Drip Drift Attack."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"

    initialize_default_environment(base_dir=base)

    results: List[Tuple[BootExecutionResult, BootRecord]] = []

    with tempfile.TemporaryDirectory() as tmp_run:
        for boot_idx in range(num_boots):
            boot_res = execute_boot_chain(
                keys_dir=keys_dir,
                stages_dir=stages_dir,
                run_dir=Path(tmp_run) / f"run_{boot_idx}",
            )

            # Cumulative incremental overhead added across boots
            cum_drift = boot_idx * drift_step_ms
            t_exec_s2 = 15.0 + cum_drift
            total_time = boot_res.total_boot_time_ms + cum_drift

            stages_telemetry = {
                "S0": StageTelemetry("S0", t_verify_ms=5.0, t_exec_ms=2.0, t_total_ms=7.0, rss_mb=12.0),
                "S1": StageTelemetry("S1", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=14.0),
                "S2": StageTelemetry(
                    "S2",
                    t_verify_ms=15.0,
                    t_exec_ms=t_exec_s2,
                    t_total_ms=15.0 + t_exec_s2,
                    rss_mb=14.0 + (boot_idx * 0.5),
                    ctx_switches_invol=2 + int(boot_idx * 0.8),
                ),
                "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=15.0, t_total_ms=15.0, rss_mb=16.0),
            }

            rec = BootRecord(
                boot_id=f"a4-boot-{boot_idx:02d}",
                timestamp_iso="2026-08-17T08:00:00Z",
                label="a4_drift",
                scenario="a4_drift",
                crypto_status="PASS",
                measurement_status="PASS",
                total_boot_time_ms=total_time,
                stages=stages_telemetry,
                event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
                pcr_snapshot=boot_res.pcr_bank.to_dict(),
                metadata={"drift_boot_index": boot_idx, "injected_drift_ms": cum_drift},
            )

            results.append((boot_res, rec))

    return results
