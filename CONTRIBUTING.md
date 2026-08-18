# Contributing to BootSentry

Thank you for your interest in contributing to **BootSentry**! We welcome contributions that uphold our dual-assurance security architecture (NIST FIPS 204 Post-Quantum Cryptography + Multi-Tier AI Behavioral Anomaly Detection).

---

## Development Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Vignesh-Er/secure_boot.git
   cd secure_boot
   ```

2. **Install in Editable Mode with Development Dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

3. **Verify Installation**:
   ```bash
   make judge-check
   ```

---

## Code Quality & Testing Standards

All pull requests must satisfy our automated verification pipeline:

1. **Strict Linting & Formatting**:
   ```bash
   make lint
   # Runs ruff check src/ tests/ with rules E, W, F, I, B, BLE, UP, SIM
   ```

2. **Full Test Suite & Coverage**:
   ```bash
   make test
   make coverage
   # All tests must pass with >= 80% line coverage across src/bootsentry/
   ```

3. **Attack Testbed Verification**:
   ```bash
   make attack
   # Evaluates scenarios A1-A5 and benign controls B1-B3
   ```

4. **Judge-Readiness Audit**:
   ```bash
   make judge-check
   # All 14 automated verification gates must pass
   ```

---

## Architectural Guidelines

- **Respect the 8 Security Invariants** outlined in `AGENTS.md` and `SECURITY.md`.
- **Never add network dependencies** to the critical boot path (`src/bootsentry/boot/`).
- **Never use `time.sleep()`** for stage workloads; implement genuine compute (crypto hashing, matrix math, table lookups).
- **Gate 1 & Gate 2 must always remain fail-closed**.
- **Gate 3 AI decisions must never authorize `HALT`** independently.
