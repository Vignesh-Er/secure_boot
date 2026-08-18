# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Non-Negotiable Security Invariants

BootSentry enforces 8 formal security invariants that must never be bypassed by configuration or AI decision layers:

1. **Gate 1 Fail-Closed Cryptography**: If NIST ML-DSA-65 signature check fails $\to$ immediate deterministic `HALT`.
2. **Gate 2 Fail-Closed Measured Boot**: If PCR state or event log violates an allowlisted measurement $\to$ immediate deterministic `HALT`.
3. **Gate 3 Non-Bricking AI Guarantee**: AI behavioral anomaly detection produces `PASS` or `WARN + REDUCED_TRUST`. An ML score alone can never authorize a system `HALT` (prevents Denial of Service exploitation against ML models).
4. **Authentic Hardware/Kernel Telemetry**: All timing and resource observations are recorded from actual OS processes executing genuine computation.
5. **No Sleep-Based Workloads**: Boot stages execute real cryptographic hashing (SHA-256), PBKDF2 iterations, device tree synthesis, and matrix arithmetic.
6. **Held-Out Out-of-Sample Evaluation**: Attack A5 (Cross-SKU substitution) is strictly held out during feature engineering and threshold calibration.
7. **Feature Schema Versioning**: Every feature vector carries `FEATURE_VERSION = 1`. Mismatched versions fail closed.
8. **Zero Network Dependency in Critical Boot Path**: The security-critical boot sequence operates completely offline.

## Demo Keys Notice

Keys stored under `config/keys/` and `models/` are non-production test vectors generated for standalone demonstration and evaluation reproducibility. Never deploy these sample keys to production hardware roots of trust.

## Reporting a Vulnerability

If you discover a security vulnerability within BootSentry, please submit a responsible disclosure report to the core security engineering team:

- **Email**: `security@bootsentry.org` (or open a private security advisory on GitHub)
- **Response Window**: Initial acknowledgment within 24 hours; remediation within 72 hours.
- Please include reproducible steps, attack scenario configuration, and observed vs expected gate behaviors.
