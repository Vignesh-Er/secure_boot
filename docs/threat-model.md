# BootSentry Threat Model & Security Boundaries

## 1. System Scope & Trust Boundaries

BootSentry protects the system initialization pipeline against local, persistent, and advanced adversaries attempting to compromise system integrity prior to full OS initialization.

### Trust Boundaries
1. **Hardware Root of Trust (Immutable)**: Contains the OEM Root Public Key $K_{root}^{pub}$ burned into write-once fused registers or immutable ROM.
2. **TPM Security Boundary**: The PCR bank and Quote signing engine execute within an isolated cryptographic coprocessor environment.
3. **Execution Environment Boundary**: Each stage executes in its own process space, enforcing strict inter-stage validation.

---

## 2. Adversary Model & Capabilities

We consider an adversary with the following capabilities:
- **Arbitrary Local Storage Access**: Can modify flash memory, configuration files, and filesystem contents between boot cycles.
- **Legacy Image Access**: Possesses validly signed older firmware and kernel images from official vendor repositories.
- **Quantum Cryptanalytic Capability**: Has access to Cryptographically Relevant Quantum Computers (CRQCs) capable of breaking classical RSA/ECC schemes via Shor's Algorithm.
- **Dynamic File Interposition**: Can perform local filesystem race conditions or swap unmeasured secondary configuration files post-signature verification (TOCTOU).
- **Service Reordering Capability**: Can modify system startup configuration scripts (e.g. init tables) to reorder or add non-critical service binaries.

### Non-Capabilities (Out of Scope)
- **Direct Physical Micro-Probing of Silicon Dies**: Sub-micron electron microscopy and focused ion beam (FIB) attacks on physical silicon are out of scope.
- **Compromised OEM Private Key**: An adversary with full write access to the vendor's private key signing infrastructure is considered an architectural breach.

---

## 3. Attack Scenarios & Mitigations

```
+----+-------------------------------+-----------------------------------+-----------------------------------+
| ID | Attack Name                   | Traditional Secure Boot Outcome   | BootSentry Multi-Gate Mitigation  |
+----+-------------------------------+-----------------------------------+-----------------------------------+
| A1 | Signed Version Downgrade      | BOOTS (Vulnerable)                | Deterministic Rule Floor (HALT)   |
| A2 | TOCTOU Config Swap            | BOOTS (Vulnerable)                | Isolation Forest Anomaly (WARN)   |
| A3 | Signed Service Reorder        | BOOTS (Vulnerable)                | Markov Sequence Detector (WARN)   |
| A4 | Multi-Boot Slow-Drip Drift    | BOOTS (Vulnerable)                | EWMA / CUSUM Drift Monitor (WARN) |
| A5 | Cross-SKU Substitution        | BOOTS (Vulnerable)                | Out-of-Sample IF Anomaly (WARN)   |
+----+-------------------------------+-----------------------------------+-----------------------------------+
```

### Scenario A1: Signed Version Downgrade
- **Mechanism**: Attacker replaces authentic Stage 2 Kernel v2.0 ($\text{SVN}=5$) with an authentic, officially signed Stage 2 Kernel v1.2 ($\text{SVN}=3$) known to contain an exploitable buffer overflow.
- **Traditional Vulnerability**: Signature verification succeeds because the image was signed with the genuine OEM private key.
- **BootSentry Defense**: Gate 1 verifies the cryptographic signature; Gate 3 Deterministic Rule Floor evaluates `RULE_SVN_ROLLBACK` ($\text{SVN}_{observed}=3 < \text{SVN}_{min}=5$), triggering an immediate, deterministic `HALT`.

### Scenario A2: TOCTOU Configuration Swap
- **Mechanism**: Attacker leaves signed executable payloads untouched but modifies an unmeasured dynamic runtime configuration file loaded by the kernel during initialization, causing memory bloat and anomalous computational loops.
- **Traditional Vulnerability**: Binary signatures match static hashes; execution continues unrestricted.
- **BootSentry Defense**: Gate 3 telemetry capture captures anomalous $t_{exec\_s2}$ (+5.8σ) and $\text{RSS}_{peak}$ (+4.9σ); Isolation Forest flags a multi-dimensional spatial outlier ($\text{score} = 0.89$), producing a `WARN + REDUCED_TRUST` attestation verdict.

### Scenario A3: Signed Service Reordering
- **Mechanism**: Attacker alters the init service manifest sequence to start a non-critical diagnostic logging daemon (`svc_diag`) before the security attestation service (`svc_attest`).
- **Traditional Vulnerability**: All service binaries are legitimate and signed; traditional boot ignores execution ordering.
- **BootSentry Defense**: 1st-order Markov Sequence Detector observes zero-support state transitions ($P(\text{svc\_diag} \mid \text{svc\_e}) = 0$), yielding a sequence anomaly score of $1.00$ and triggering `WARN + REDUCED_TRUST`.

### Scenario A4: Slow-Drip Multi-Boot Drift
- **Mechanism**: Stealth malware injects a tiny +4ms latency per boot cycle over 20 successive boots to remain below single-boot anomaly thresholds.
- **Traditional Vulnerability**: No single boot deviates sufficiently from the mean to trip single-instance filters.
- **BootSentry Defense**: Gate 3 EWMA / CUSUM Multi-Boot Drift Monitor maintains an online exponential moving average and cumulative sum detector, accumulating persistent positive shift and raising an alarm at boot 12 ($\text{CUSUM} > 4.0\sigma$).

### Scenario A5: Cross-SKU Component Substitution (Held-Out)
- **Mechanism**: Attacker boots an authentic, vendor-signed server-profile kernel component on an edge IoT device.
- **Traditional Vulnerability**: Signatures validate against shared OEM root keys.
- **BootSentry Defense**: Evaluated strictly out-of-sample; foreign NUMA allocation table routines and memory footprint trigger spatial isolation forest anomaly detection (+5.2σ on RSS memory allocation), resulting in `WARN + REDUCED_TRUST`.
