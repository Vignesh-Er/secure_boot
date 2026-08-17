"""Append-Only Measured Boot Event Log with Replay Verification."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from bootsentry.measure.pcr import PcrBank


@dataclass(frozen=True)
class EventLogEntry:
    sequence_number: int
    stage_id: str
    event_type: str
    pcr_index: int
    digest: str
    version: str
    timestamp_ns: int
    event_data: Dict[str, Any] = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        data = {
            "sequence_number": self.sequence_number,
            "stage_id": self.stage_id,
            "event_type": self.event_type,
            "pcr_index": self.pcr_index,
            "digest": self.digest,
            "version": self.version,
            "timestamp_ns": self.timestamp_ns,
            "event_data": self.event_data,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> EventLogEntry:
        return cls(
            sequence_number=int(d["sequence_number"]),
            stage_id=str(d["stage_id"]),
            event_type=str(d["event_type"]),
            pcr_index=int(d["pcr_index"]),
            digest=str(d["digest"]),
            version=str(d["version"]),
            timestamp_ns=int(d["timestamp_ns"]),
            event_data=dict(d.get("event_data", {})),
        )


@dataclass
class EventLog:
    """Append-only tamper-evident event log."""

    entries: List[EventLogEntry] = field(default_factory=list)

    def record_event(
        self,
        stage_id: str,
        event_type: str,
        pcr_index: int,
        digest: str,
        version: str = "1.0.0",
        event_data: Optional[Dict[str, Any]] = None,
        timestamp_ns: Optional[int] = None,
    ) -> EventLogEntry:
        """Append a new event and return the created entry."""
        seq = len(self.entries)
        ts = timestamp_ns if timestamp_ns is not None else time.perf_counter_ns()
        entry = EventLogEntry(
            sequence_number=seq,
            stage_id=stage_id,
            event_type=event_type,
            pcr_index=pcr_index,
            digest=digest,
            version=version,
            timestamp_ns=ts,
            event_data=event_data or {},
        )
        self.entries.append(entry)
        return entry

    def cumulative_digest(self) -> str:
        """Compute rolling cryptographic hash of all event log entries in sequence."""
        rolling = "0" * 64
        for entry in self.entries:
            hasher = hashlib.sha256(bytes.fromhex(rolling))
            hasher.update(entry.canonical_bytes())
            rolling = hasher.hexdigest()
        return rolling

    def replay_pcrs(self, num_registers: int = 8) -> PcrBank:
        """Replay all logged events into a fresh PCR bank."""
        bank = PcrBank(num_registers=num_registers)
        for entry in self.entries:
            bank.extend(entry.pcr_index, entry.digest)
        return bank

    def verify_consistency(self, pcr_bank: PcrBank) -> Tuple[bool, str]:
        """Verify that the event log accurately reproduces the PCR bank's register state."""
        replayed_bank = self.replay_pcrs(num_registers=pcr_bank.num_registers)
        for idx, actual_val in pcr_bank.snapshot().items():
            expected_val = replayed_bank.read(idx)
            if actual_val != expected_val:
                return (
                    False,
                    f"PCR[{idx}] mismatch: actual={actual_val[:12]}..., replayed={expected_val[:12]}...",
                )
        return True, "Event log perfectly reproduces PCR bank state."

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries]

    @classmethod
    def from_list(cls, data: List[Dict[str, Any]]) -> EventLog:
        return cls(entries=[EventLogEntry.from_dict(d) for d in data])
