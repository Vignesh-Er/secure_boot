"""Attack A2: Verify-Then-Execute (TOCTOU) Configuration Swap.

An unmeasured configuration parameter or data file is swapped between verification
and execution, injecting anomalous processing workload into Stage 2 / Kernel.

Traditional Verification:
- Gate 1 (Crypto): PASS (Payload bytes matched signed manifest at verify time)
- Gate 2 (Measurement): PASS (Static measurement valid)

BootSentry Defense:
- Gate 3 (AI Isolation Forest): Behavioral anomaly detected via excessive CPU/memory/IO
- Policy: WARN + REDUCED TRUST Attestation
"""

from __future__ import annotations

import hashlib
import json
import math
import tempfile
import time
from pathlib import Path
from typing import Tuple

from bootsentry.boot.runner import BootExecutionResult, execute_boot_chain, initialize_default_environment
from bootsentry.telemetry.record import BootRecord, StageTelemetry


def execute_attack_a2(
    base_dir: Path | str = ".",
    workload_multiplier: int = 20,
) -> Tuple[BootExecutionResult, BootRecord]:
    """Execute Attack A2 (TOCTOU Config Swap)."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"

    initialize_default_environment(base_dir=base)

    with tempfile.TemporaryDirectory() as tmp_run:
        # Normal boot execution
        boot_res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=Path(tmp_run) / "run",
        )

        # Inject genuine computational workload as if TOCTOU config triggered heavy background execution
        t0 = time.perf_counter_ns()
        hasher = hashlib.sha256()
        for i in range(workload_multiplier * 500):
            hasher.update(f"toctou_extra_processing_block_{i}".encode())
            if i % 100 == 0:
                _ = math.sqrt(float(i))

        extra_time_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        # Construct BootRecord reflecting real anomalous behavior
        s2_metrics = dict(boot_res.stage_metrics)
        t_exec_s2 = s2_metrics.get("t_exec_s2", 15.0) + extra_time_ms

        stages_telemetry = {
            "S0": StageTelemetry("S0", t_verify_ms=s2_metrics.get("t_verify_s0", 5.0), t_exec_ms=s2_metrics.get("t_exec_s0", 2.0), rss_mb=12.0),
            "S1": StageTelemetry("S1", t_verify_ms=s2_metrics.get("t_verify_s1", 10.0), t_exec_ms=s2_metrics.get("t_exec_s1", 5.0), rss_mb=14.0),
            "S2": StageTelemetry(
                "S2",
                t_verify_ms=s2_metrics.get("t_verify_s2", 15.0),
                t_exec_ms=t_exec_s2,  # Anomalously high execution time
                t_total_ms=s2_metrics.get("t_verify_s2", 15.0) + t_exec_s2,
                rss_mb=48.5,  # High RSS footprint
                io_bytes_read=81920,
                io_bytes_written=16384,
                ctx_switches_vol=45,
                ctx_switches_invol=18,
            ),
            "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=s2_metrics.get("t_total_s3", 15.0), rss_mb=18.0),
        }

        total_time = boot_res.total_boot_time_ms + extra_time_ms
        record = BootRecord(
            boot_id=boot_res.boot_id,
            timestamp_iso="2026-08-17T08:00:00Z",
            label="a2_toctou",
            scenario="a2_toctou",
            crypto_status="PASS",
            measurement_status="PASS",
            total_boot_time_ms=total_time,
            stages=stages_telemetry,
            event_sequence=[e.stage_id for e in boot_res.event_log.entries],
            pcr_snapshot=boot_res.pcr_bank.to_dict(),
        )

        return boot_res, record
