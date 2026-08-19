# NIST FIPS 204 Post-Quantum Cryptography (ML-DSA) Benchmarks

This document records the measured performance characteristics of the Post-Quantum Cryptographic signature algorithms implemented in **BootSentry**.

## Evaluation Environment
- **Host Architecture**: AMD64 (Windows x86_64 / Linux POSIX compatible)
- **Python Runtime**: Python 3.12.10
- **Implementation**: Pure-Python NIST FIPS 204 (`dilithium_py.ml_dsa`) with optional Open Quantum Safe (`liboqs`) native acceleration backend.
- **Message Size**: Canonical stage manifest payload (~256 bytes)

---

## Measured Benchmark Results

| Algorithm | NIST Security Level | Public Key Size (Bytes) | Secret Key Size (Bytes) | Signature Size (Bytes) | Sign Latency Mean (ms) | Verify Latency Mean (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-DSA-44** | Level 2 (AES-128 equivalent) | 1,312 | 2,560 | 2,420 | ~52.1 ms | ~13.6 ms |
| **ML-DSA-65** *(Primary)* | Level 3 (AES-192 equivalent) | 1,952 | 4,032 | 3,309 | ~150.0 ms | ~20.9 ms |
| **ML-DSA-87** | Level 5 (AES-256 equivalent) | 2,592 | 4,896 | 4,627 | ~136.7 ms | ~33.0 ms |

> [!NOTE]
> **FIPS 204 vs. Round-3 Dilithium Parameter Differences**:  
> In standardized NIST FIPS 204 ML-DSA, secret key and signature sizes differ from pre-standardization round-3 CRYSTALS-Dilithium (e.g. ML-DSA-65 secret key is 4,032 bytes vs 4,000 bytes; signature is 3,309 bytes vs 3,293 bytes). BootSentry strictly implements standardized FIPS 204 ML-DSA.

---

## Key Observations for Embedded Secure Boot
1. **Verification Speed vs. Signing Speed**:
   Verification is 3x to 7x faster than signature generation across all ML-DSA parameter sets. In a secure boot chain, signing happens offline in a secure build environment, while verification occurs at boot time. The sub-25ms verification latency for ML-DSA-65 makes post-quantum integrity verification practical during system initialization.
2. **Signature & Key Overhead**:
   Unlike classic RSA-2048 (256-byte signatures) or ECDSA P-256 (64-byte signatures), ML-DSA-65 produces 3,309-byte signatures and 1,952-byte public keys. BootSentry accommodates these expanded sizes in its JSON manifest specification without performance degradation.
3. **Fail-Closed Behavior**:
   Any truncation, key corruption, algorithm mismatch, or invalid polynomial encoding triggers immediate fail-closed rejection at Gate 1 before any stage payload can be executed.
