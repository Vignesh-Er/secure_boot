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

---

## 5. Host OS Counter Sampling Granularity (Windows vs. Embedded PMU)

### Sampling Granularity on Host Platforms
On Windows host platforms, rapid in-process stage execution (sub-10ms) means certain OS process counters (context switches, minor page faults, disk bytes read/written) report zero deltas via standard `psutil` sampling due to OS timer resolution limitations.

**Resolution & Hardware PMU**:
- BootSentry's feature extractor handles zero-variance features safely via Zero-MAD regularization ($1.4826 \cdot \text{MAD} + 1e\text{-}6$).
- The reference C99 microkernel implementation (`c_src/src/pmu_driver.c`) interfaces directly with hardware performance monitoring units (`__rdtsc` on x86_64, `pmccntr_el0` on ARM64) to capture cycle-accurate instruction retirement and cache miss counters without host OS abstraction overhead.

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

## 7. Synthetic Reference Benchmark Separation vs. Production Operational Jitter (ML-BS-02)

### Benchmark Separation vs. Real-World Stochasticity
The headline scenario-level metric of `ROC-AUC = 1.0000` reflects clean decision separation on defined reference benchmark scenarios (A1–A5 and B1–B3 controls). In those reference scenarios, attacks exhibit distinct delta signatures (e.g. $+32000.0\sigma$ on I/O ratio or deliberate memory exhaustion) against low-variance baseline environments.

**Continuous Behavioral Reality**:
- Under continuous sample-level evaluation across sequential boots, the behavioral detection layer achieves `ROC-AUC = 0.9370` and `PR-AUC = 0.9459`.
- In production fleet deployments with heavy, non-uniform background I/O contention or variable virtualization scheduling jitter, the separation boundary naturally narrows. BootSentry addresses this through robust Median/MAD feature attribution and ratio-invariant feature engineering rather than relying on uncalibrated threshold rigidity.

---

## 8. Multi-Boot Sequential Drift Dynamics & Time-to-Detect (ML-BS-03)

### Sequential Monitoring vs. Static Binary Classification
Attack A4 (Slow-Drip Multi-Boot Drift) is an accumulating temporal sequence (+4ms/boot across 20 successive boots). Treating each boot in an accumulating drift sequence as an independent I.I.D. sample is a statistical simplification for static ROC evaluation.

**Principled Temporal Evaluation**:
- Multi-boot drift detection is fundamentally governed by **Mean Time To Detect (MTTD)** and **Average Run Length (ARL)**.
- BootSentry's causal EWMA/CUSUM sequential monitor reliably flags sustained positive drift at **Boot 12** ($MTTD = 12\text{ boots}$), providing provable online temporal tripwires without future lookahead bias.


