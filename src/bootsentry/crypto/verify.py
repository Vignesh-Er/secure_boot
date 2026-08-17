"""Deterministic Fail-Closed Signature Verification (Gate 1)."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass

from bootsentry.crypto.manifest import Manifest
from bootsentry.crypto.provider import CryptoError, get_provider


@dataclass(frozen=True)
class CryptoVerifyResult:
    success: bool
    stage_id: str
    algorithm: str
    reason: str
    digest: str
    latency_ms: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def verify_manifest(
    manifest: Manifest,
    public_key_bytes: bytes,
    payload_bytes: bytes | None = None,
    expected_stage_id: str | None = None,
) -> CryptoVerifyResult:
    """Deterministically verify a stage manifest and optional payload.

    Security Rules Enforced:
    1. Fail-closed: Any exception, missing signature, or format mismatch returns success=False.
    2. Stage binding: If expected_stage_id is provided, it must strictly match manifest.stage_id.
    3. PQC signature: Validates signature over RFC 8785 canonical manifest bytes.
    4. Payload binding: If payload_bytes is given, verifies SHA-256 and byte length match.
    """
    t0 = time.perf_counter_ns()
    stage_id = getattr(manifest, "stage_id", "UNKNOWN")
    algorithm = getattr(manifest, "algorithm", "UNKNOWN")

    try:
        # Check 1: Stage binding
        if expected_stage_id and manifest.stage_id != expected_stage_id:
            latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            return CryptoVerifyResult(
                success=False,
                stage_id=stage_id,
                algorithm=algorithm,
                reason=f"Stage ID mismatch: expected '{expected_stage_id}', got '{manifest.stage_id}'",
                digest=manifest.canonical_digest(),
                latency_ms=latency_ms,
            )

        # Check 2: Signature presence
        if not manifest.signature:
            latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            return CryptoVerifyResult(
                success=False,
                stage_id=stage_id,
                algorithm=algorithm,
                reason="Manifest is unsigned (missing signature field)",
                digest=manifest.canonical_digest(),
                latency_ms=latency_ms,
            )

        # Check 3: Signature format
        try:
            sig_bytes = bytes.fromhex(manifest.signature)
        except ValueError:
            latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            return CryptoVerifyResult(
                success=False,
                stage_id=stage_id,
                algorithm=algorithm,
                reason="Signature field contains invalid hexadecimal encoding",
                digest=manifest.canonical_digest(),
                latency_ms=latency_ms,
            )

        # Check 4: Payload verification if provided
        if payload_bytes is not None:
            calc_digest = hashlib.sha256(payload_bytes).hexdigest()
            if calc_digest != manifest.payload_sha256:
                latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
                return CryptoVerifyResult(
                    success=False,
                    stage_id=stage_id,
                    algorithm=algorithm,
                    reason=f"Payload SHA-256 digest mismatch (calculated {calc_digest[:12]}..., manifest {manifest.payload_sha256[:12]}...)",
                    digest=manifest.canonical_digest(),
                    latency_ms=latency_ms,
                )

            if len(payload_bytes) != manifest.payload_size:
                latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
                return CryptoVerifyResult(
                    success=False,
                    stage_id=stage_id,
                    algorithm=algorithm,
                    reason=f"Payload size mismatch (calculated {len(payload_bytes)} bytes, manifest {manifest.payload_size} bytes)",
                    digest=manifest.canonical_digest(),
                    latency_ms=latency_ms,
                )

        # Check 5: Post-Quantum Cryptographic verification
        provider = get_provider(manifest.algorithm)
        canonical_bytes = manifest.canonical_bytes()
        is_valid = provider.verify(public_key_bytes, canonical_bytes, sig_bytes)

        latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        if is_valid:
            return CryptoVerifyResult(
                success=True,
                stage_id=stage_id,
                algorithm=manifest.algorithm,
                reason="Cryptographic signature and integrity verified successfully",
                digest=manifest.canonical_digest(),
                latency_ms=latency_ms,
            )
        else:
            return CryptoVerifyResult(
                success=False,
                stage_id=stage_id,
                algorithm=manifest.algorithm,
                reason="PQC signature verification failed: invalid signature for key/payload",
                digest=manifest.canonical_digest(),
                latency_ms=latency_ms,
            )

    except (CryptoError, ValueError, TypeError, KeyError, OSError, json.JSONDecodeError, RuntimeError, AttributeError, IndexError) as exc:
        # Strict Fail-Closed behavior: any unexpected error results in failure
        latency_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CryptoVerifyResult(
            success=False,
            stage_id=stage_id,
            algorithm=algorithm,
            reason=f"Verification failed closed due to exception: {type(exc).__name__}: {exc}",
            digest="",
            latency_ms=latency_ms,
        )

