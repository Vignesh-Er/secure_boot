"""Post-Quantum Cryptography (PQC) Provider Abstraction.

Implements standardized NIST FIPS 204 ML-DSA-65 (primary) with support
for ML-DSA-44 and ML-DSA-87 algorithms.
"""

from __future__ import annotations

import abc
import os
from typing import ClassVar

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


class CryptoError(Exception):
    """Base exception for all cryptographic operations."""


class AlgorithmNotFoundError(CryptoError):
    """Raised when an unsupported algorithm is requested."""


class VerificationError(CryptoError):
    """Raised when signature verification explicitly fails."""


class MalformedKeyError(CryptoError):
    """Raised when public or private key material is corrupted or wrong size."""


class PQCProvider(abc.ABC):
    """Abstract Base Class for PQC Signature Schemes."""

    algorithm_name: ClassVar[str]
    public_key_size: ClassVar[int]
    secret_key_size: ClassVar[int]
    signature_size: ClassVar[int]

    @abc.abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Generate (public_key_bytes, secret_key_bytes)."""

    @abc.abstractmethod
    def sign(self, secret_key: bytes, message: bytes, deterministic: bool = True) -> bytes:
        """Sign message using secret_key and return raw signature bytes."""

    @abc.abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature over message using public_key."""


# -------------------------------------------------------------------------
# NIST FIPS 204 ML-DSA Provider Implementations (via dilithium-py)
# -------------------------------------------------------------------------


class MLDSA65Provider(PQCProvider):
    """ML-DSA-65 Provider per NIST FIPS 204."""

    algorithm_name = "ML-DSA-65"
    public_key_size = 1952
    secret_key_size = 4032
    signature_size = 3309

    def keygen(self) -> tuple[bytes, bytes]:
        return ML_DSA_65.keygen()

    def sign(self, secret_key: bytes, message: bytes, deterministic: bool = True) -> bytes:
        if len(secret_key) != self.secret_key_size:
            raise MalformedKeyError(
                f"Invalid ML-DSA-65 secret key length: {len(secret_key)} (expected {self.secret_key_size})"
            )
        # G4: deterministic=True produces byte-reproducible artifacts for committed manifests.
        return ML_DSA_65.sign(secret_key, message, ctx=b"", deterministic=deterministic)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.public_key_size:
            return False
        if len(signature) != self.signature_size:
            return False
        try:
            return bool(ML_DSA_65.verify(public_key, message, signature, ctx=b""))
        except (ValueError, TypeError, IndexError, KeyError, RuntimeError, CryptoError):
            return False


class MLDSA44Provider(PQCProvider):
    """ML-DSA-44 Provider per NIST FIPS 204."""

    algorithm_name = "ML-DSA-44"
    public_key_size = 1312
    secret_key_size = 2560
    signature_size = 2420

    def keygen(self) -> tuple[bytes, bytes]:
        return ML_DSA_44.keygen()

    def sign(self, secret_key: bytes, message: bytes, deterministic: bool = True) -> bytes:
        if len(secret_key) != self.secret_key_size:
            raise MalformedKeyError(
                f"Invalid ML-DSA-44 secret key length: {len(secret_key)} (expected {self.secret_key_size})"
            )
        return ML_DSA_44.sign(secret_key, message, ctx=b"", deterministic=deterministic)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.public_key_size or len(signature) != self.signature_size:
            return False
        try:
            return bool(ML_DSA_44.verify(public_key, message, signature, ctx=b""))
        except (ValueError, TypeError, IndexError, KeyError, RuntimeError, CryptoError):
            return False


class MLDSA87Provider(PQCProvider):
    """ML-DSA-87 Provider per NIST FIPS 204."""

    algorithm_name = "ML-DSA-87"
    public_key_size = 2592
    secret_key_size = 4896
    signature_size = 4627

    def keygen(self) -> tuple[bytes, bytes]:
        return ML_DSA_87.keygen()

    def sign(self, secret_key: bytes, message: bytes, deterministic: bool = True) -> bytes:
        if len(secret_key) != self.secret_key_size:
            raise MalformedKeyError(
                f"Invalid ML-DSA-87 secret key length: {len(secret_key)} (expected {self.secret_key_size})"
            )
        return ML_DSA_87.sign(secret_key, message, ctx=b"", deterministic=deterministic)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.public_key_size or len(signature) != self.signature_size:
            return False
        try:
            return bool(ML_DSA_87.verify(public_key, message, signature, ctx=b""))
        except (ValueError, TypeError, IndexError, KeyError, RuntimeError, CryptoError):
            return False


# Compatibility Aliases
MLDSA65DilithiumProvider = MLDSA65Provider
MLDSA44DilithiumProvider = MLDSA44Provider
MLDSA87DilithiumProvider = MLDSA87Provider


# -------------------------------------------------------------------------
# Native LibOQS Provider (Lazy / Explicit Opt-In Backend)
# -------------------------------------------------------------------------


class LibOQSProvider(PQCProvider):
    """Native liboqs wrapper for optional C execution when explicitly enabled."""

    def __init__(self, alg_name: str):
        import oqs  # Lazy import only when LibOQS backend requested

        self.algorithm_name = alg_name
        self._oqs_name = self._map_to_oqs_name(alg_name)
        self._oqs = oqs

    @staticmethod
    def _map_to_oqs_name(alg: str) -> str:
        mapping = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SPHINCS+-SHA2-128s-simple",
        }
        return mapping.get(alg, alg)

    def keygen(self) -> tuple[bytes, bytes]:
        with self._oqs.Signature(self._oqs_name) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
            return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes, deterministic: bool = True) -> bytes:
        with self._oqs.Signature(self._oqs_name, secret_key=secret_key) as signer:
            return signer.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            with self._oqs.Signature(self._oqs_name) as verifier:
                return verifier.verify(message, signature, public_key)
        except (ImportError, RuntimeError, ValueError, TypeError, CryptoError):
            return False


# -------------------------------------------------------------------------
# Provider Registry & Factory
# -------------------------------------------------------------------------

_REGISTRY: dict[str, type[PQCProvider]] = {
    "ML-DSA-65": MLDSA65Provider,
    "ML-DSA-44": MLDSA44Provider,
    "ML-DSA-87": MLDSA87Provider,
}


def get_backend_name() -> str:
    """Return the active backend id: 'dilithium-py' or 'liboqs'.

    Reads env BOOTSENTRY_PQC_BACKEND; defaults to 'dilithium-py'.
    Never probes liboqs at import time (see G3).
    """
    return os.environ.get("BOOTSENTRY_PQC_BACKEND", "dilithium-py").lower()


def get_provider(algorithm: str = "ML-DSA-65") -> PQCProvider:
    """Factory to retrieve the PQC provider for an algorithm."""
    # Round-3 legacy aliases must explicitly fail with informative error
    if algorithm in ("Dilithium2", "Dilithium3", "Dilithium5"):
        raise AlgorithmNotFoundError(
            "Dilithium (round-3) is not supported; this build uses NIST FIPS 204 ML-DSA."
        )

    backend = get_backend_name()
    if backend == "liboqs":
        try:
            return LibOQSProvider(algorithm)
        except Exception as err:
            raise CryptoError(f"Failed to initialize liboqs backend for {algorithm}: {err}") from err

    provider_cls = _REGISTRY.get(algorithm)
    if not provider_cls:
        raise AlgorithmNotFoundError(
            f"Algorithm '{algorithm}' is not supported. Supported algorithms: {list_supported_algorithms()}"
        )
    return provider_cls()


def list_supported_algorithms() -> list[str]:
    """List all supported PQC signature algorithms at runtime."""
    return sorted(_REGISTRY.keys())
