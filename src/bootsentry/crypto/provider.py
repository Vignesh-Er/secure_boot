"""Post-Quantum Cryptography (PQC) Provider Abstraction.

Implements NIST FIPS 204 ML-DSA-65 (primary) with runtime fallbacks and support
for ML-DSA-44, ML-DSA-87, and SLH-DSA algorithms.
"""

from __future__ import annotations

import abc
import hashlib
import time
from typing import ClassVar, Dict, List, Tuple, Type


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
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate (public_key_bytes, secret_key_bytes)."""

    @abc.abstractmethod
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign message using secret_key and return raw signature bytes."""

    @abc.abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature over message using public_key."""


# -------------------------------------------------------------------------
# Dilithium-py NIST FIPS 204 ML-DSA Implementations
# -------------------------------------------------------------------------

try:
    from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

    DILITHIUM_PY_AVAILABLE = True
except ImportError:
    DILITHIUM_PY_AVAILABLE = False


class MLDSA65DilithiumProvider(PQCProvider):
    """ML-DSA-65 (Dilithium3) Provider via pure-python standard library."""

    algorithm_name = "ML-DSA-65"
    public_key_size = 1952
    secret_key_size = 4000
    signature_size = 3293

    def keygen(self) -> Tuple[bytes, bytes]:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        return Dilithium3.keygen()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        if len(secret_key) != self.secret_key_size:
            raise MalformedKeyError(
                f"Invalid ML-DSA-65 secret key length: {len(secret_key)} (expected {self.secret_key_size})"
            )
        return Dilithium3.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        if len(public_key) != self.public_key_size:
            return False
        if len(signature) != self.signature_size:
            return False
        try:
            return bool(Dilithium3.verify(public_key, message, signature))
        except Exception:
            return False


class MLDSA44DilithiumProvider(PQCProvider):
    """ML-DSA-44 (Dilithium2) Provider."""

    algorithm_name = "ML-DSA-44"
    public_key_size = 1312
    secret_key_size = 2528
    signature_size = 2420

    def keygen(self) -> Tuple[bytes, bytes]:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        return Dilithium2.keygen()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        if len(secret_key) != self.secret_key_size:
            raise MalformedKeyError(
                f"Invalid ML-DSA-44 secret key length: {len(secret_key)} (expected {self.secret_key_size})"
            )
        return Dilithium2.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        if len(public_key) != self.public_key_size:
            return False
        if len(signature) != self.signature_size:
            return False
        try:
            return bool(Dilithium2.verify(public_key, message, signature))
        except Exception:
            return False


class MLDSA87DilithiumProvider(PQCProvider):
    """ML-DSA-87 (Dilithium5) Provider."""

    algorithm_name = "ML-DSA-87"
    public_key_size = 2592
    secret_key_size = 4864
    signature_size = 4595

    def keygen(self) -> Tuple[bytes, bytes]:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        return Dilithium5.keygen()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        if len(secret_key) != self.secret_key_size:
            raise MalformedKeyError(
                f"Invalid ML-DSA-87 secret key length: {len(secret_key)} (expected {self.secret_key_size})"
            )
        return Dilithium5.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not DILITHIUM_PY_AVAILABLE:
            raise CryptoError("dilithium-py backend is not installed.")
        if len(public_key) != self.public_key_size:
            return False
        if len(signature) != self.signature_size:
            return False
        try:
            return bool(Dilithium5.verify(public_key, message, signature))
        except Exception:
            return False


# -------------------------------------------------------------------------
# Native LibOQS Provider (when available)
# -------------------------------------------------------------------------

LIBOQS_AVAILABLE = False
try:
    import oqs
    # Test if liboqs backend can actually be instantiated
    _test_sig = oqs.Signature("ML-DSA-65")
    _test_sig.free()
    LIBOQS_AVAILABLE = True
except (ImportError, Exception, SystemExit, BaseException):
    LIBOQS_AVAILABLE = False



class LibOQSProvider(PQCProvider):
    """Native liboqs wrapper for high-performance C execution."""

    def __init__(self, alg_name: str):
        self.algorithm_name = alg_name
        self._oqs_name = self._map_to_oqs_name(alg_name)

    @staticmethod
    def _map_to_oqs_name(alg: str) -> str:
        mapping = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "Dilithium2": "Dilithium2",
            "Dilithium3": "Dilithium3",
            "Dilithium5": "Dilithium5",
            "SLH-DSA-SHA2-128s": "SPHINCS+-SHA2-128s-simple",
        }
        return mapping.get(alg, alg)

    def keygen(self) -> Tuple[bytes, bytes]:
        with oqs.Signature(self._oqs_name) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
            return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(self._oqs_name, secret_key=secret_key) as signer:
            return signer.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            with oqs.Signature(self._oqs_name) as verifier:
                return verifier.verify(message, signature, public_key)
        except Exception:
            return False


# -------------------------------------------------------------------------
# Provider Registry & Factory
# -------------------------------------------------------------------------

_REGISTRY: Dict[str, Type[PQCProvider]] = {
    "ML-DSA-65": MLDSA65DilithiumProvider,
    "ML-DSA-44": MLDSA44DilithiumProvider,
    "ML-DSA-87": MLDSA87DilithiumProvider,
    "Dilithium3": MLDSA65DilithiumProvider,
    "Dilithium2": MLDSA44DilithiumProvider,
    "Dilithium5": MLDSA87DilithiumProvider,
}


def get_provider(algorithm: str = "ML-DSA-65") -> PQCProvider:
    """Factory to retrieve the best available PQC provider for an algorithm.

    Prefers native LibOQS if available, seamlessly falls back to dilithium-py.
    """
    if LIBOQS_AVAILABLE:
        try:
            return LibOQSProvider(algorithm)
        except Exception:
            pass

    provider_cls = _REGISTRY.get(algorithm)
    if not provider_cls:
        raise AlgorithmNotFoundError(
            f"Algorithm '{algorithm}' is not supported. Supported algorithms: {list_supported_algorithms()}"
        )
    return provider_cls()


def list_supported_algorithms() -> List[str]:
    """List all supported PQC signature algorithms at runtime."""
    algs = list(_REGISTRY.keys())
    if LIBOQS_AVAILABLE:
        try:
            algs.extend(oqs.get_enabled_sig_mechanisms())
        except Exception:
            pass
    return sorted(list(set(algs)))
