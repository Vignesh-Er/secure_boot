# BootSentry Engineering Limitations & Design Trade-offs

In accordance with rigorous autonomous engineering principles, this document provides an honest, comprehensive disclosure of the operational assumptions, architectural boundaries, and known limitations of the BootSentry prototype.

---

## 1. Post-Quantum Cryptography Overhead

### Key and Signature Size Trade-offs
NIST FIPS 204 (ML-DSA) requires significantly larger key and signature sizes compared to classical elliptic curve algorithms (e.g. Ed25519 or ECDSA P-256):
- **ECDSA P-256**: Public Key = 64 B, Signature = 64 B
- **ML-DSA-65**: Public Key = 1,952 B (30.5× larger), Signature = 3,293 B (51.5× larger)

**Impact**: In embedded microcontrollers with strict ROM constraints (e.g., < 32 KB BootROM), storing multiple PQC public keys and buffering signatures requires dedicated SRAM allocation.

---

## 2. Telemetry Environment Noise & Load-Invariant Normalization

### Host Background Noise
While BootSentry utilizes ratio features ($\frac{t_{stage}}{t_{total}}$ and $\frac{t_{verify}}{t_{exec}}$) that remain invariant under uniform CPU frequency scaling, non-uniform I/O contention (e.g. simultaneous background disk writes) can induce localized latency spikes in individual stages.

**Mitigation**:
- The policy engine enforces **Invariant 3**: Behavioral anomalies produce `WARN + REDUCED_TRUST`, never a false `HALT`.
- The attribution engine provides median/MAD z-score decomposition so administrators can distinguish between I/O contention and code tampering.

---

## 3. Cold-Start Model Baseline Requirements

### Initial Baseline Training
Behavioral anomaly detection requires a clean baseline distribution ($N \ge 50$ authentic boots) to establish robust median and MAD parameters.

**Deployment Consideration**:
In factory provisioning, new device SKUs must undergo automated golden boot cycles during initial burn-in to initialize baseline reference statistics.

---

## 4. Software TPM Emulation vs. Discrete Hardware TPM

In this implementation, the software TPM PCR bank is emulated using SHA-256 cryptographic state extension in Python memory. In a production deployment:
- PCR registers should be physically hosted on a discrete TPM 2.0 or integrated into a hardware-isolated Secure Enclave / TrustZone.
- Attestation quotes should be signed by an Endorsement Key (EK) protected by hardware-enforced physical tamper resistance.
