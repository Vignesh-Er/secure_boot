"""Cryptographic model manifest creation, signing, and verification for Gate 3 models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from bootsentry.crypto.manifest import canonicalize_json
from bootsentry.crypto.provider import CryptoError, VerificationError, get_provider


@dataclass(frozen=True)
class ModelManifest:
    model_version: int
    algorithm: str
    model_files: dict[str, dict[str, Any]]  # filename -> {"sha256": hex, "size_bytes": int}
    composite_model_digest: str
    signer_public_key_hex: str
    signature_hex: str = ""

    def payload_dict(self) -> dict[str, Any]:
        """Return the canonical payload dictionary excluding the signature."""
        return {
            "algorithm": self.algorithm,
            "composite_model_digest": self.composite_model_digest,
            "model_files": self.model_files,
            "model_version": self.model_version,
            "signer_public_key_hex": self.signer_public_key_hex,
        }

    def canonical_bytes(self) -> bytes:
        """Return deterministic RFC 8785 canonical bytes for signing/verifying."""
        return canonicalize_json(self.payload_dict())

    def to_dict(self) -> dict[str, Any]:
        """Convert full manifest including signature to dictionary."""
        return asdict(self)

    def save(self, file_path: Path | str) -> None:
        """Save manifest to JSON file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)

    @classmethod
    def load(cls, file_path: Path | str) -> ModelManifest:
        """Load manifest from JSON file."""
        path = Path(file_path)
        if not path.exists():
            raise CryptoError(f"Model manifest file not found: {path}")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


def compute_file_sha256(file_path: Path | str) -> tuple[str, int]:
    """Compute SHA-256 digest and byte size of a file."""
    path = Path(file_path)
    if not path.exists():
        raise CryptoError(f"Target model file not found: {path}")
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def create_model_manifest(
    models_dir: Path | str,
    signer_public_key_bytes: bytes,
    algorithm: str = "ML-DSA-65",
    model_version: int = 2,
    model_filenames: list[str] | None = None,
) -> ModelManifest:
    """Scan models directory and construct an unsigned model manifest."""
    dir_path = Path(models_dir)
    if not dir_path.exists():
        raise CryptoError(f"Models directory not found: {dir_path}")

    if model_filenames is None:
        model_filenames = [
            "isolation_forest.joblib",
            "markov_sequence.joblib",
            "ewma_monitor.joblib",
            "attribution_engine.joblib",
        ]

    files_meta: dict[str, dict[str, Any]] = {}
    composite_hasher = hashlib.sha256()

    for fname in sorted(model_filenames):
        fpath = dir_path / fname
        if fpath.exists():
            digest, size = compute_file_sha256(fpath)
            files_meta[fname] = {"sha256": digest, "size_bytes": size}
            composite_hasher.update(digest.encode("utf-8"))

    if not files_meta:
        raise CryptoError(f"No valid model files found in {dir_path} matching {model_filenames}")

    composite_digest = composite_hasher.hexdigest()

    return ModelManifest(
        model_version=model_version,
        algorithm=algorithm,
        model_files=files_meta,
        composite_model_digest=composite_digest,
        signer_public_key_hex=signer_public_key_bytes.hex(),
        signature_hex="",
    )


def sign_model_manifest(
    manifest: ModelManifest,
    signer_secret_key_bytes: bytes,
) -> ModelManifest:
    """Sign model manifest using PQC secret key."""
    provider = get_provider(manifest.algorithm)
    canonical_data = manifest.canonical_bytes()
    sig_bytes = provider.sign(signer_secret_key_bytes, canonical_data)
    return ModelManifest(
        model_version=manifest.model_version,
        algorithm=manifest.algorithm,
        model_files=manifest.model_files,
        composite_model_digest=manifest.composite_model_digest,
        signer_public_key_hex=manifest.signer_public_key_hex,
        signature_hex=sig_bytes.hex(),
    )


def verify_model_manifest(
    manifest: ModelManifest,
    models_dir: Path | str | None = None,
    expected_public_key_bytes: bytes | None = None,
) -> bool:
    """Verify cryptographic signature and file hashes for model manifest."""
    if not manifest.signature_hex:
        raise VerificationError("Model manifest is unsigned (empty signature_hex)")

    provider = get_provider(manifest.algorithm)
    pk_bytes = bytes.fromhex(manifest.signer_public_key_hex)

    if expected_public_key_bytes is not None and pk_bytes != expected_public_key_bytes:
        raise VerificationError("Signer public key does not match expected trusted key")

    canonical_data = manifest.canonical_bytes()
    sig_bytes = bytes.fromhex(manifest.signature_hex)

    if not provider.verify(pk_bytes, canonical_data, sig_bytes):
        raise VerificationError("Model manifest signature verification failed (invalid ML-DSA signature)")


    # If models_dir is provided, verify on-disk files match the manifest digests
    if models_dir is not None:
        dir_path = Path(models_dir)
        composite_hasher = hashlib.sha256()
        for fname in sorted(manifest.model_files.keys()):
            fpath = dir_path / fname
            if not fpath.exists():
                raise VerificationError(f"Declared model file missing on disk: {fname}")
            actual_digest, actual_size = compute_file_sha256(fpath)
            expected_digest = manifest.model_files[fname]["sha256"]
            if actual_digest != expected_digest:
                raise VerificationError(
                    f"Model file digest mismatch for '{fname}': expected {expected_digest[:16]}..., got {actual_digest[:16]}..."
                )
            composite_hasher.update(actual_digest.encode("utf-8"))

        if composite_hasher.hexdigest() != manifest.composite_model_digest:
            raise VerificationError("Composite model digest mismatch across model files")

    return True
