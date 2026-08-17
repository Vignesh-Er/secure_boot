# BootSentry System Architecture

## 1. Architectural Philosophy & Dual-Assurance Model

Traditional secure boot solutions enforce a single binary question at boot time:
$$\text{Is Component } C_i \text{ authentically signed by Root of Trust } K_{pub}?$$

While essential to prevent unauthenticated code injection, this static gate cannot reason about:
1. Validly signed legacy components containing exploitable vulnerabilities (Rollback attacks).
2. Unmeasured configuration parameters loaded post-verification (TOCTOU attacks).
3. Memory corruption or unauthorized service execution order.
4. Subtle performance degradation or long-term operational drift.

**BootSentry** implements a **Dual-Assurance Security Model**:
- **Static Gate Assurance (Gates 1 & 2)**: Deterministic, fail-closed post-quantum cryptographic signature and TPM measured boot checks.
- **Dynamic Behavioral Assurance (Gate 3)**: Continuous multi-dimensional process execution telemetry analysis via an anomaly detection ensemble with a deterministic safety rule floor.

```
                   +-------------------------------------------------------------+
                   |                 BOOTSENTRY BOOT CHAIN PIPELINE              |
                   +-------------------------------------------------------------+
                                                  |
           +--------------------------------------+--------------------------------------+
           |                                                                             |
           v                                                                             v
+-----------------------+                                                     +-----------------------+
|  GATE 1: CRYPTO PQC   |                                                     |  GATE 2: MEASURED PCR |
+-----------------------+                                                     +-----------------------+
| • NIST ML-DSA-65      |                                                     | • SHA-256 PCR Bank    |
| • RFC 8785 JSON       |                                                     | • Append-only EventLog|
| • Fail-Closed Verify  |                                                     | • Attestation Quote   |
+-----------+-----------+                                                     +-----------+-----------+
            |                                                                             |
            +--------------------------------------+--------------------------------------+
                                                   |
                                                   v
                                        +-----------------------+
                                        |  GATE 3: BEHAVIORAL   |
                                        +-----------------------+
                                        | • 28 Continuous Feats |
                                        | • Isolation Forest    |
                                        | • 1st-Order Markov    |
                                        | • EWMA / CUSUM Drift  |
                                        | • Robust Median / MAD |
                                        +-----------+-----------+
                                                   |
                                                   v
                                        +-----------------------+
                                        |  3-TIER POLICY ENGINE |
                                        +-----------------------+
                                        | PASS | WARN+ATTEST | HALT
                                        +-----------------------+
```

---

## 2. Boot Chain Stage Progression (S0 through S3)

BootSentry decomposes boot execution into 4 distinct OS process stages:

### Stage 0: BootROM (`s0_bootrom.py`)
- **Trust Anchor**: Immutable hardware root of trust containing OEM Root Public Key $K_{root}^{pub}$.
- **Responsibilities**:
  1. Initializes software TPM PCR bank with initial zero-state: $\text{PCR}[0..3] = 0x00^{32}$.
  2. Verifies S1 Bootloader manifest and payload using ML-DSA-65.
  3. Extends $\text{PCR}[0]$: $\text{PCR}[0] \leftarrow \text{SHA256}(\text{PCR}[0] \parallel \text{digest}(S1))$.
  4. Records event to append-only Event Log.
  5. Passes verified execution handoff to Stage 1 via atomic state token.

### Stage 1: Bootloader (`s1_bootloader.py`)
- **Responsibilities**:
  1. Validates handoff token from S0.
  2. Initializes early device trees and virtual memory mappings.
  3. Verifies S2 Kernel manifest and payload using ML-DSA-65.
  4. Extends $\text{PCR}[1]$: $\text{PCR}[1] \leftarrow \text{SHA256}(\text{PCR}[1] \parallel \text{digest}(S2))$.
  5. Passes handoff token to Stage 2.

### Stage 2: Kernel (`s2_kernel.py`)
- **Responsibilities**:
  1. Validates handoff token from S1.
  2. Initializes kernel task tables, scheduler, and memory subsystems.
  3. Verifies S3 Init manifest and payload using ML-DSA-65.
  4. Extends $\text{PCR}[2]$: $\text{PCR}[2] \leftarrow \text{SHA256}(\text{PCR}[2] \parallel \text{digest}(S3))$.
  5. Passes handoff token to Stage 3.

### Stage 3: Init & Computational Services (`s3_init.py` & `services.py`)
- **Responsibilities**:
  1. Launches user-space services in deterministic sequence: `[svc_a, svc_b, svc_c, svc_attest, svc_e]`.
  2. Executes genuine computation workloads (prime sieves, matrix permutations, SHA-256 trees).
  3. Extends $\text{PCR}[3]$ for each individual service payload.
  4. Generates signed post-quantum Attestation Quote ($\text{PCR}[0..3]$ + Nonce + Event Log digest).
  5. Emits `BootRecord` containing full telemetry vector to Gate 3.

---

## 3. Post-Quantum Cryptography & Canonical Manifests

### Manifest Schema (RFC 8785 Canonical JSON)
Manifests are serialized using RFC 8785 canonical JSON formatting (strictly sorted keys, whitespace-free, standard float representation) to guarantee bit-exact signature verification across heterogeneous platforms:

```json
{
  "stage_id": "S1",
  "version": "1.0.0",
  "security_version": 5,
  "algorithm": "ML-DSA-65",
  "public_key_fingerprint": "a3f89b...",
  "payload_sha256": "e2c7a1...",
  "payload_size_bytes": 1024,
  "measured_pcr_index": 1,
  "signature": "3c91a0..."
}
```

The digital signature covers the canonical JSON bytes of all fields **excluding** `"signature"`.

---

## 4. 28-Feature Telemetry Extraction Engine

The continuous feature extraction pipeline computes 28 continuous metrics across 5 operational dimensions:

1. **Timing & Latency Features** (8 features): Stage execution times ($t_{S0}, t_{S1}, t_{S2}, t_{S3}$), verification times ($t_{v0}, t_{v1}, t_{v2}$), and total boot latency $t_{total}$.
2. **Timing Ratio Features (Load-Invariant)** (6 features): Stage fraction ratios ($\frac{t_{S0}}{t_{total}}, \frac{t_{S1}}{t_{total}}, \frac{t_{S2}}{t_{total}}, \frac{t_{S3}}{t_{total}}$) and verify-to-exec ratios ($\frac{t_{v1}}{t_{exec1}}, \frac{t_{v2}}{t_{exec2}}$).
3. **Memory Footprint Features** (5 features): Peak Resident Set Size ($\text{RSS}_{peak}$), per-stage RSS ($\text{RSS}_{S0..S3}$), and heap expansion delta.
4. **Context Switching & System Dynamics** (5 features): Voluntary context switches, involuntary context switches, voluntary switch ratio ($\frac{\text{vol}}{\text{vol}+\text{invol}}$), open file descriptor count, and thread concurrency.
5. **Markov Transition & Process Graph Features** (4 features): 1st-order Markov negative log-likelihood ($\text{NLL}_{seq}$), unseen transition count, sequence length, and service invocation entropy.

---

## 5. 3-Layer Behavioral Anomaly Ensemble

### Layer 1: Isolation Forest
- Fits an ensemble of 200 isolation trees on StandardScaler-normalized 28-feature baseline vectors.
- Yields a normalized anomaly score $S_{IF} \in [0, 1]$ measuring spatial feature dispersion.

### Layer 2: 1st-Order Markov Sequence Detector
- Models the state transition probabilities $P(E_{i} \mid E_{i-1})$ across the boot event sequence.
- Incorporates Laplace smoothing ($\alpha = 1.0$) to handle novel transitions gracefully:
$$P(w_i \mid w_{i-1}) = \frac{C(w_{i-1}, w_i) + \alpha}{C(w_{i-1}) + \alpha \cdot |V|}$$
- Computes the average Negative Log-Likelihood ($\text{NLL}$) and flags structural reordering attacks (e.g. Attack A3).

### Layer 3: EWMA / CUSUM Multi-Boot Drift Monitor
- Tracks slow multi-boot parameter shifts:
$$z_t = \alpha \cdot x_t + (1 - \alpha) \cdot z_{t-1}$$
- Runs a two-sided Cumulative Sum (CUSUM) detector:
$$S_t^+ = \max(0, S_{t-1}^+ + x_t - \mu_0 - k \cdot \sigma)$$
- Triggers when $S_t^+ > h \cdot \sigma$, defeating slow-drip stealth accumulation (Attack A4).

---

## 6. Deterministic Rule Floor & Policy Engine

### Deterministic Rule Floor (`rules.py`)
Enforces hard hardware invariants:
1. `RULE_SVN_ROLLBACK`: Observed $\text{SVN} < \text{MinTrustedSVN}$
2. `RULE_PCR_ALLOWLIST`: Final PCR state not present in golden allowlist
3. `RULE_STAGE_ID_MISMATCH`: Execution sequence violates $S0 \to S1 \to S2 \to S3$
4. `RULE_CRYPTO_VERIFICATION_FAILED`: Gate 1 signature verification failed
5. `RULE_MEASUREMENT_VERIFICATION_FAILED`: Gate 2 PCR extension verification failed

### 3-Level Policy Decision (`policy.py`)
- **HALT**: Triggered if and only if a deterministic security rule fails ($\text{passed} = \text{False}$). Halts execution immediately.
- **WARN + REDUCED_TRUST**: Triggered when all deterministic rules pass, but ML anomaly score $S_{risk} \ge \tau_{warn}$. Signs an attestation quote with `"REDUCED_TRUST"` warning metadata.
- **PASS**: Triggered when deterministic rules pass and behavioral risk is nominal ($S_{risk} < \tau_{warn}$). Signs a full `"TRUSTED"` quote.
