"""Boot stage manifest format and RFC 8785 deterministic canonicalization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Manifest:
    stage_id: str
    version: str
    security_version_counter: int
    algorithm: str
    payload_sha256: str
    payload_size: int
    expected_pcr: str
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: str | None = None

    def canonical_dict(self) -> dict[str, Any]:
        """Return the dictionary representation for signing (signature excluded)."""
        d = asdict(self)
        d.pop("signature", None)
        return d

    def canonical_bytes(self) -> bytes:
        """Deterministic RFC 8785 JSON canonical representation for hashing/signing."""
        canonical_str = json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return canonical_str.encode("utf-8")

    def canonical_digest(self) -> str:
        """SHA-256 hex digest of the canonical manifest bytes."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_json(self, indent: int = 2) -> str:
        """Serialize complete manifest including signature to JSON string."""
        return json.dumps(asdict(self), indent=indent, sort_keys=True)

    def save(self, path: Path | str) -> None:
        """Save manifest to a JSON file."""
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        """Construct Manifest from a dictionary."""
        return cls(
            stage_id=str(data["stage_id"]),
            version=str(data["version"]),
            security_version_counter=int(data["security_version_counter"]),
            algorithm=str(data.get("algorithm", "ML-DSA-65")),
            payload_sha256=str(data["payload_sha256"]),
            payload_size=int(data["payload_size"]),
            expected_pcr=str(data.get("expected_pcr", "0" * 64)),
            metadata=dict(data.get("metadata", {})),
            signature=data.get("signature"),
        )

    @classmethod
    def load(cls, path: Path | str) -> Manifest:
        """Load manifest from a JSON file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Manifest file not found: {file_path}")
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


def compute_payload_sha256(payload_data_or_path: bytes | str | Path) -> tuple[str, int]:
    """Compute (sha256_hex, size_bytes) for payload bytes or file."""
    if isinstance(payload_data_or_path, str | Path):
        p = Path(payload_data_or_path)

        if not p.exists():
            raise FileNotFoundError(f"Payload not found: {p}")
        data = p.read_bytes()
    else:
        data = payload_data_or_path

    digest = hashlib.sha256(data).hexdigest()
    return digest, len(data)
