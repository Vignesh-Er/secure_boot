"""Signed PQC Attestation Quote Generation and Verification."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from bootsentry.crypto.provider import CryptoError, get_provider
from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank


@dataclass
class AttestationQuote:
    boot_id: str
    pcr_snapshot: dict[str, str]
    pcr_composite_digest: str
    event_log_digest: str
    nonce: str
    timestamp_ns: int
    algorithm: str = "ML-DSA-65"
    signature: str | None = None

    def canonical_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature", None)
        return d

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttestationQuote:
        return cls(
            boot_id=str(data["boot_id"]),
            pcr_snapshot=dict(data["pcr_snapshot"]),
            pcr_composite_digest=str(data["pcr_composite_digest"]),
            event_log_digest=str(data["event_log_digest"]),
            nonce=str(data["nonce"]),
            timestamp_ns=int(data["timestamp_ns"]),
            algorithm=str(data.get("algorithm", "ML-DSA-65")),
            signature=data.get("signature"),
        )


def generate_attestation_quote(
    pcr_bank: PcrBank,
    event_log: EventLog,
    attestation_secret_key_bytes: bytes,
    nonce: str | None = None,
    boot_id: str | None = None,
    algorithm: str = "ML-DSA-65",
) -> AttestationQuote:
    """Generate and cryptographically sign a TPM-style attestation quote."""
    fresh_nonce = nonce or secrets.token_hex(16)
    bid = boot_id or str(uuid.uuid4())
    ts = time.perf_counter_ns()

    quote = AttestationQuote(
        boot_id=bid,
        pcr_snapshot=pcr_bank.to_dict(),
        pcr_composite_digest=pcr_bank.composite_digest(),
        event_log_digest=event_log.cumulative_digest(),
        nonce=fresh_nonce,
        timestamp_ns=ts,
        algorithm=algorithm,
    )

    provider = get_provider(algorithm)
    sig_bytes = provider.sign(attestation_secret_key_bytes, quote.canonical_bytes())
    quote.signature = sig_bytes.hex()
    return quote


def verify_attestation_quote(
    quote: AttestationQuote,
    attestation_public_key_bytes: bytes,
    expected_nonce: str | None = None,
) -> tuple[bool, str]:
    """Verify an attestation quote's cryptographic signature and freshness nonce."""
    if not quote.signature:
        return False, "Attestation quote is unsigned"

    if expected_nonce is not None and quote.nonce != expected_nonce:
        return False, f"Nonce mismatch: expected {expected_nonce}, got {quote.nonce}"

    try:
        sig_bytes = bytes.fromhex(quote.signature)
    except ValueError:
        return False, "Invalid signature hex format"

    try:
        provider = get_provider(quote.algorithm)
        is_valid = provider.verify(
            attestation_public_key_bytes, quote.canonical_bytes(), sig_bytes
        )
        if not is_valid:
            return False, "PQC signature verification failed for attestation quote"
        return True, "Attestation quote cryptographically verified"
    except (CryptoError, ValueError, TypeError, KeyError, OSError, RuntimeError, AttributeError, IndexError) as exc:
        return False, f"Attestation verification error: {exc}"

