# BootSentry Engineering Limitations & Design Trade-offs

In accordance with rigorous autonomous engineering principles, this document provides an honest, comprehensive disclosure of the operational assumptions, architectural boundaries, and known limitations of the BootSentry prototype.

---

## 1. Post-Quantum Cryptography Overhead & Side-Channel Boundary

### Key and Signature Size Trade-offs
NIST FIPS 204 (ML-DSA) requires significantly larger key and signature sizes compared to classical elliptic curve algorithms (e.g. Ed25519 or ECDSA P-256):
- **ECDSA P-256**: Public Key = 64 B, Secret Key = 32 B, Signature = 64 B
- **ML-DSA-65 (NIST FIPS 204)**: Public Key = 1,952 B (30.5× larger), Secret Key = 4,032 B (126× larger), Signature = 3,309 B (51.7× larger)

**Impact**: In embedded microcontrollers with strict ROM constraints (e.g., < 32 KB BootROM), storing multiple PQC public keys and buffering signatures requires dedicated SRAM allocation.

### Side-Channel Security Notice (G2)
> [!CAUTION]
> The primary PQC provider in this repository utilizes `dilithium-py`, which is an educational software implementation. As documented by its authors, it has not been hardened against physical side-channel attacks (differential power analysis, electromagnetic emissions, or microarchitectural timing channels). Production deployments require a side-channel resistant implementation (e.g., hardware-accelerated crypto-engine or masked liboqs builds).

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

---

## 5. Host OS Counter Sampling Granularity & Dispersion Fallbacks (F-24)

### Sampling Granularity on Host Platforms
On host operating systems (Windows/Linux), rapid in-process stage execution (sub-10ms) means certain OS process counters (context switches, minor page faults, disk bytes read/written) report zero deltas via standard `psutil` sampling due to OS timer resolution limitations.

**Attribution Dispersion Fallback Chain**:
When baseline feature variance is zero, MAD evaluates to 0.0. To prevent division-by-zero, the attribution engine executes the following tiered fallback chain:
1. Median Absolute Deviation ($1.4826 \cdot \text{MAD}$)
2. Mean Absolute Deviation (L1 norm)
3. Sample Standard Deviation ($\sigma$)
4. Degenerate fallback scale: $\max(1.0, |\text{median}| \times 0.1)$ with explicit `scale_source = "degenerate"` tagging.

---

## 6. Host Telemetry Trust Boundary & Out-of-Band Collection (SEC-BS-01)

### In-Process vs. Out-of-Band Telemetry
In this software reference prototype, process telemetry is captured from Python user-space (`psutil` / OS process counters). If an adversary achieves unconstrained Ring 0 / root kernel execution prior to boot telemetry collection, they could theoretically intercept or spoof system metrics (`resource.getrusage` / `/proc/self/stat`).

**Production Architecture Requirement**:
- In commercial bare-metal or cloud infrastructure deployments, telemetry collectors must execute out-of-band:
  - Inside a Baseboard Management Controller (BMC) or OpenBMC service processor.
  - Within a hardware-isolated Hypervisor / Virtual Machine Monitor (VMM).
  - Inside a hardware Secure Enclave (ARM TrustZone, Intel SGX/TDX, AMD SEV-SNP).
- Gate 3 acts as an auxiliary tripwire and defense-in-depth telemetry observer; it is strictly subordinate to Gate 1 (cryptographic signature verification) and Gate 2 (TPM PCR hardware measurements).

---

## 7. Reference Benchmark Separation vs. Production Operational Jitter (ML-BS-02)

### Benchmark Separation vs. Real-World Stochasticity
Scenario-level metrics evaluate clean decision separation on defined reference benchmark scenarios (A1–A5 and B1–B3 controls). In those reference scenarios, attacks exhibit distinct delta signatures against baseline environments:
- **Scenario-Level (Pre-Remediation Measured)**: ROC-AUC = 0.9953, PR-AUC = 0.9667 ($N=48, n_{pos}=5$)
- **Continuous Sample-Level (Pre-Remediation Measured)**: ROC-AUC = 0.9874, PR-AUC = 0.9820 ($N=68, n_{pos}=25$)

**Continuous Behavioral Reality**:
In production fleet deployments with heavy, non-uniform background I/O contention or variable virtualization scheduling jitter, the separation boundary naturally narrows. BootSentry addresses this through robust Median/MAD feature attribution and ratio-invariant feature engineering rather than relying on uncalibrated threshold rigidity.

---

## 8. Multi-Boot Sequential Drift Dynamics & Time-to-Detect (ML-BS-03, F-22)

### Sequential Monitoring vs. Static Binary Classification
Attack A4 (Slow-Drip Multi-Boot Drift) is an accumulating temporal sequence (+4ms/boot across 20 successive boots).

**Principled Temporal Evaluation**:
- Multi-boot drift detection is fundamentally governed by **Mean Time To Detect (MTTD)** and sequential CUSUM state recursion.
- On the pre-remediation reference sequence, drift is flagged at **Boot 5**. Under the host-relative sequential monitor (Phase 4), detection point depends on host warmup calibration without fixed host assumptions.

---

## 9. Sub-Threshold In-Distribution Evasion Boundary

Behavioral anomaly detection is fundamentally statistical. If an attacker possesses full knowledge of the baseline feature distribution and intentionally bounds their malicious payload's execution overhead within the learned normal envelope ($\le 1.5\sigma$), behavioral anomaly detection will not trigger. This limitation is formally acknowledged and validated in `tests/test_boot_adversarial.py::test_evasion_inside_normal_distribution`. Security against such attacks rests strictly on Gate 1 (Cryptographic Signatures) and Gate 2 (Measured Boot PCR Allowlisting).
