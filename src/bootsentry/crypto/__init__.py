"""BootSentry Cryptographic Subsystem."""

from bootsentry.crypto.benchmark import CryptoBenchmarkResult, benchmark_algorithm, run_all_benchmarks
from bootsentry.crypto.keys import (
    PQCKeypair,
    generate_all_system_keys,
    generate_stage_keypair,
    load_public_key,
    load_secret_key,
    save_keypair,
)
from bootsentry.crypto.manifest import Manifest, compute_payload_sha256
from bootsentry.crypto.provider import (
    CryptoError,
    MalformedKeyError,
    PQCProvider,
    VerificationError,
    get_provider,
    list_supported_algorithms,
)
from bootsentry.crypto.sign import sign_manifest, sign_stage_manifest_file
from bootsentry.crypto.verify import CryptoVerifyResult, verify_manifest

__all__ = [
    "CryptoBenchmarkResult",
    "CryptoError",
    "CryptoVerifyResult",
    "MalformedKeyError",
    "Manifest",
    "PQCKeypair",
    "PQCProvider",
    "VerificationError",
    "benchmark_algorithm",
    "compute_payload_sha256",
    "generate_all_system_keys",
    "generate_stage_keypair",
    "get_provider",
    "list_supported_algorithms",
    "load_public_key",
    "load_secret_key",
    "run_all_benchmarks",
    "save_keypair",
    "sign_manifest",
    "sign_stage_manifest_file",
    "verify_manifest",
]
