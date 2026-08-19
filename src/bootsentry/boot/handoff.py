"""Inter-stage boot handoff state protocol with HMAC-SHA256 authentication."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank


class BootHandoffError(Exception):
    """Base exception for boot handoff errors."""


class BootHandoffSecurityError(BootHandoffError):
    """Raised when HMAC authentication on an inter-stage handoff token fails."""


def _canonical_payload_bytes(data: dict[str, Any]) -> bytes:
    """Return deterministic canonical UTF-8 JSON bytes excluding the HMAC signature."""
    payload = {k: v for k, v in data.items() if k != "mac"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_handoff_mac(data: dict[str, Any], secret: bytes | str) -> str:
    """Compute HMAC-SHA256 over canonical handoff dictionary."""
    sec_bytes = (
        secret
        if isinstance(secret, bytes)
        else (bytes.fromhex(secret) if len(secret) == 64 else secret.encode("utf-8"))
    )
    return hmac.new(sec_bytes, _canonical_payload_bytes(data), hashlib.sha256).hexdigest()


@dataclass
class BootHandoff:
    boot_id: str
    current_stage: str
    next_stage: str
    pcr_state: dict[str, str]
    event_log_data: list[dict[str, Any]]
    status: str = "RUNNING"
    error_message: str | None = None
    stage_metrics: dict[str, Any] = field(default_factory=dict)
    quote_data: dict[str, Any] | None = None
    mac: str | None = None

    def get_pcr_bank(self) -> PcrBank:
        return PcrBank.from_dict(self.pcr_state)

    def get_event_log(self) -> EventLog:
        return EventLog.from_list(self.event_log_data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, file_path: Path | str, secret: bytes | str | None = None) -> None:
        """Sign-then-write: Compute HMAC-SHA256 over handoff state and save atomically."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self.to_dict()
        effective_secret = secret or os.environ.get("BOOTSENTRY_BOOT_SECRET")
        if effective_secret:
            data["mac"] = compute_handoff_mac(data, effective_secret)
            self.mac = data["mac"]

        temp_path = path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        temp_path.replace(path)

    @classmethod
    def load(
        cls,
        file_path: Path | str,
        secret: bytes | str | None = None,
        verify_mac: bool = True,
    ) -> BootHandoff:
        """Load handoff state and verify HMAC-SHA256 authentication token (fail-closed)."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Handoff file not found: {path}")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        effective_secret = secret or os.environ.get("BOOTSENTRY_BOOT_SECRET")
        if verify_mac and effective_secret:
            token_mac = data.get("mac")
            if not token_mac:
                raise BootHandoffSecurityError("Inter-stage handoff token is missing required HMAC signature (F-02)")
            expected_mac = compute_handoff_mac(data, effective_secret)
            if not hmac.compare_digest(token_mac, expected_mac):
                raise BootHandoffSecurityError("Inter-stage handoff HMAC verification failed: tampered token (F-02)")

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
            mac=data.get("mac"),
        )
