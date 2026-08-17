"""Inter-stage boot handoff state protocol."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank


@dataclass
class BootHandoff:
    boot_id: str
    current_stage: str
    next_stage: str
    pcr_state: Dict[str, str]
    event_log_data: List[Dict[str, Any]]
    status: str = "RUNNING"
    error_message: Optional[str] = None
    stage_metrics: Dict[str, Any] = field(default_factory=dict)
    quote_data: Optional[Dict[str, Any]] = None

    def get_pcr_bank(self) -> PcrBank:
        return PcrBank.from_dict(self.pcr_state)

    def get_event_log(self) -> EventLog:
        return EventLog.from_list(self.event_log_data)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, file_path: Path | str) -> None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        temp_path.replace(path)

    @classmethod
    def load(cls, file_path: Path | str) -> BootHandoff:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Handoff file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            boot_id=str(data["boot_id"]),
            current_stage=str(data["current_stage"]),
            next_stage=str(data["next_stage"]),
            pcr_state=dict(data["pcr_state"]),
            event_log_data=list(data["event_log_data"]),
            status=str(data.get("status", "RUNNING")),
            error_message=data.get("error_message"),
            stage_metrics=dict(data.get("stage_metrics", {})),
            quote_data=data.get("quote_data"),
        )
