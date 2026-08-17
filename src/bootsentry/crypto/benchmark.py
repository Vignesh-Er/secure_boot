"""Post-Quantum Cryptography Benchmarking Suite.

Measures key sizes, signature sizes, sign latency, and verify latency
for NIST ML-DSA-44, ML-DSA-65, and ML-DSA-87.
"""

from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import dataclass

from bootsentry.crypto.provider import CryptoError, get_provider


@dataclass
class CryptoBenchmarkResult:
    algorithm: str
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    keygen_ms_mean: float
    keygen_ms_median: float
    sign_ms_mean: float
    sign_ms_median: float
    verify_ms_mean: float
    verify_ms_median: float
    iterations: int


def benchmark_algorithm(algorithm: str, iterations: int = 10) -> CryptoBenchmarkResult:
    """Benchmark keygen, sign, and verify latency for an algorithm."""
    provider = get_provider(algorithm)
    message = b"BootSentry stage integrity manifest canonical test payload measurement string"

    keygen_times: list[float] = []
    sign_times: list[float] = []
    verify_times: list[float] = []

    pk_bytes, sk_bytes, sig_bytes = b"", b"", b""

    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        pk, sk = provider.keygen()
        t_kg = (time.perf_counter_ns() - t0) / 1_000_000.0
        keygen_times.append(t_kg)
        pk_bytes, sk_bytes = pk, sk

        t0 = time.perf_counter_ns()
        sig = provider.sign(sk, message)
        t_sign = (time.perf_counter_ns() - t0) / 1_000_000.0
        sign_times.append(t_sign)
        sig_bytes = sig

        t0 = time.perf_counter_ns()
        valid = provider.verify(pk, message, sig)
        t_vf = (time.perf_counter_ns() - t0) / 1_000_000.0
        verify_times.append(t_vf)
        if not valid:
            raise RuntimeError(f"Signature verification failed during benchmark of {algorithm}")

    return CryptoBenchmarkResult(
        algorithm=algorithm,
        public_key_bytes=len(pk_bytes),
        secret_key_bytes=len(sk_bytes),
        signature_bytes=len(sig_bytes),
        keygen_ms_mean=statistics.mean(keygen_times),
        keygen_ms_median=statistics.median(keygen_times),
        sign_ms_mean=statistics.mean(sign_times),
        sign_ms_median=statistics.median(sign_times),
        verify_ms_mean=statistics.mean(verify_times),
        verify_ms_median=statistics.median(verify_times),
        iterations=iterations,
    )


def run_all_benchmarks(iterations: int = 10) -> list[CryptoBenchmarkResult]:
    """Run benchmarks across all available ML-DSA algorithms."""
    algorithms = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    results = []
    for alg in algorithms:
        try:
            res = benchmark_algorithm(alg, iterations=iterations)
            results.append(res)
        except (CryptoError, ValueError, TypeError, OSError, RuntimeError) as exc:
            print(f"[-] Benchmark failed for {alg}: {exc}")
    return results



def main() -> None:
    parser = argparse.ArgumentParser(description="PQC Crypto Benchmarking")
    parser.add_argument("--iterations", type=int, default=10, help="Number of benchmark iterations")
    args = parser.parse_args()

    print("==================================================================================")
    print("                    BOOTSENTRY PQC CRYPTO BENCHMARKS (NIST FIPS 204)               ")
    print("==================================================================================")
    print(f"{'Algorithm':<12} | {'PK (B)':<7} | {'SK (B)':<7} | {'Sig (B)':<7} | {'Sign (ms)':<10} | {'Verify (ms)':<10}")
    print("-" * 82)

    results = run_all_benchmarks(iterations=args.iterations)
    for r in results:
        print(
            f"{r.algorithm:<12} | {r.public_key_bytes:<7} | {r.secret_key_bytes:<7} | "
            f"{r.signature_bytes:<7} | {r.sign_ms_mean:<10.2f} | {r.verify_ms_mean:<10.2f}"
        )
    print("==================================================================================")


if __name__ == "__main__":
    main()
