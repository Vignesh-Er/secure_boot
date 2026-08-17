"""BootRecord schema and telemetry models."""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from typing import Any

FEATURE_VERSION = 1


@dataclass
class StageTelemetry:
    stage_id: str
    t_verify_ms: float = 0.0
    t_exec_ms: float = 0.0
    t_total_ms: float = 0.0
    rss_mb: float = 0.0
    page_faults_minor: int = 0
    page_faults_major: int = 0
    ctx_switches_vol: int = 0
    ctx_switches_invol: int = 0
    io_bytes_read: int = 0
    io_bytes_written: int = 0
    cpu_user_ms: float = 0.0
    cpu_system_ms: float = 0.0
    custom_metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class BootRecord:
    boot_id: str
    timestamp_iso: str
    feature_version: int = FEATURE_VERSION
    label: str = "normal"  # "normal", "a1_downgrade", "a2_toctou", "a3_reorder", "a4_drift", "a5_cross_sku", "benign_load"
    scenario: str = "clean"
    crypto_status: str = "PASS"  # "PASS" or "FAIL"
    measurement_status: str = "PASS"  # "PASS" or "FAIL"
    total_boot_time_ms: float = 0.0
    stages: dict[str, StageTelemetry] = field(default_factory=dict)
    event_sequence: list[str] = field(default_factory=list)
    pcr_snapshot: dict[str, str] = field(default_factory=dict)
    feature_vector: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BootRecord:
        stages_data = data.get("stages", {})
        stages_obj = {k: StageTelemetry(**v) for k, v in stages_data.items()}

        return cls(
            boot_id=str(data["boot_id"]),
            timestamp_iso=str(data.get("timestamp_iso", datetime.datetime.now(datetime.timezone.utc).isoformat())),
            feature_version=int(data.get("feature_version", FEATURE_VERSION)),
            label=str(data.get("label", "normal")),
            scenario=str(data.get("scenario", "clean")),
            crypto_status=str(data.get("crypto_status", "PASS")),
            measurement_status=str(data.get("measurement_status", "PASS")),
            total_boot_time_ms=float(data.get("total_boot_time_ms", 0.0)),
            stages=stages_obj,
            event_sequence=list(data.get("event_sequence", [])),
            pcr_snapshot=dict(data.get("pcr_snapshot", {})),
            feature_vector=dict(data.get("feature_vector", {})),
            metadata=dict(data.get("metadata", {})),
        )
