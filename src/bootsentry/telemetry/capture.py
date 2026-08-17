"""Real-time process telemetry capture using psutil and monotonic timing."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import psutil

from bootsentry.telemetry.record import StageTelemetry


class ProcessTelemetrySampler:
    """Samples real process performance metrics before and after an execution stage."""

    def __init__(self, pid: Optional[int] = None):
        self.pid = pid or os.getpid()
        try:
            self.process = psutil.Process(self.pid)
        except Exception:
            self.process = None

        self._t0_ns = 0
        self._cpu_t0: Optional[Tuple[float, float]] = None
        self._ctx_t0: Optional[Tuple[int, int]] = None
        self._io_t0: Optional[Tuple[int, int]] = None
        self._mem_t0 = 0.0

    def start(self) -> None:
        """Start recording process baseline."""
        self._t0_ns = time.perf_counter_ns()
        if not self.process:
            return

        try:
            cpu_times = self.process.cpu_times()
            self._cpu_t0 = (cpu_times.user, cpu_times.system)
        except Exception:
            self._cpu_t0 = (0.0, 0.0)

        try:
            ctx = self.process.num_ctx_switches()
            self._ctx_t0 = (ctx.voluntary, ctx.involuntary)
        except Exception:
            self._ctx_t0 = (0, 0)

        try:
            io = self.process.io_counters()
            self._io_t0 = (io.read_bytes, io.write_bytes)
        except Exception:
            self._io_t0 = (0, 0)

        try:
            mem = self.process.memory_info()
            self._mem_t0 = mem.rss / (1024.0 * 1024.0)
        except Exception:
            self._mem_t0 = 0.0

    def stop(
        self,
        stage_id: str,
        t_verify_ms: float = 0.0,
        custom_metrics: Optional[Dict[str, Any]] = None,
    ) -> StageTelemetry:
        """Stop recording and calculate delta process telemetry for the stage."""
        elapsed_ms = (time.perf_counter_ns() - self._t0_ns) / 1_000_000.0
        t_exec_ms = max(0.0, elapsed_ms - t_verify_ms)

        cpu_user_ms, cpu_sys_ms = 0.0, 0.0
        ctx_vol, ctx_invol = 0, 0
        io_read, io_write = 0, 0
        rss_mb = self._mem_t0
        minor_faults, major_faults = 0, 0

        if self.process:
            try:
                cpu_t1 = self.process.cpu_times()
                if self._cpu_t0:
                    cpu_user_ms = max(0.0, (cpu_t1.user - self._cpu_t0[0]) * 1000.0)
                    cpu_sys_ms = max(0.0, (cpu_t1.system - self._cpu_t0[1]) * 1000.0)
            except Exception:
                pass

            try:
                ctx_t1 = self.process.num_ctx_switches()
                if self._ctx_t0:
                    ctx_vol = max(0, ctx_t1.voluntary - self._ctx_t0[0])
                    ctx_invol = max(0, ctx_t1.involuntary - self._ctx_t0[1])
            except Exception:
                pass

            try:
                io_t1 = self.process.io_counters()
                if self._io_t0:
                    io_read = max(0, io_t1.read_bytes - self._io_t0[0])
                    io_write = max(0, io_t1.write_bytes - self._io_t0[1])
            except Exception:
                pass

            try:
                mem_t1 = self.process.memory_info()
                rss_mb = mem_t1.rss / (1024.0 * 1024.0)
                # Check page fault counters if available on platform
                if hasattr(mem_t1, "num_page_faults"):
                    minor_faults = getattr(mem_t1, "num_page_faults", 0)
                elif hasattr(mem_t1, "major_page_faults"):
                    major_faults = getattr(mem_t1, "major_page_faults", 0)
            except Exception:
                pass

        return StageTelemetry(
            stage_id=stage_id,
            t_verify_ms=t_verify_ms,
            t_exec_ms=t_exec_ms,
            t_total_ms=elapsed_ms,
            rss_mb=rss_mb,
            page_faults_minor=minor_faults,
            page_faults_major=major_faults,
            ctx_switches_vol=ctx_vol,
            ctx_switches_invol=ctx_invol,
            io_bytes_read=io_read,
            io_bytes_written=io_write,
            cpu_user_ms=cpu_user_ms,
            cpu_system_ms=cpu_sys_ms,
            custom_metrics=custom_metrics or {},
        )
