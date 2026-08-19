"""Adversarial and security invariant tests for Boot Chain Integrity (Phase 3).

Tests:
1. Bit-flip in handoff MAC fails closed (F-02)
2. Missing handoff MAC fails closed (F-02)
3. Tampered stage_id in handoff fails closed (F-02)
4. Tampered pcr_state in handoff fails closed (F-02)
5. Replayed handoff token from previous boot fails closed with different secret (F-02)
6. SVN rollback below floor triggers RULE_SVN_ROLLBACK and HALT (F-03)
7. SVN equal to floor passes (F-03)
8. SVN above floor passes (F-03)
9. Missing stage in svn_floor defaults to minimum 1 (F-03)
10. Non-allowlisted PCR state triggers RULE_PCR_NOT_ALLOWLISTED and HALT (F-04)
11. Allowlisted PCR state passes (F-04)
12. Tampered PCR3 alone triggers RULE_PCR_NOT_ALLOWLISTED (F-04)
13. Quote verification with matching nonce passes (F-05)
14. Quote verification with mismatched nonce fails (F-05)
15. Model load with tampered manifest fails before joblib.load (F-06, G5)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from bootsentry.boot.handoff import (
    BootHandoff,
    BootHandoffSecurityError,
    compute_handoff_mac,
)
from bootsentry.crypto.keys import load_public_key, load_secret_key
from bootsentry.crypto.model_manifest import (
    create_model_manifest,
    sign_model_manifest,
    verify_model_manifest,
)
from bootsentry.crypto.provider import VerificationError
from bootsentry.detect.policy import BootPolicyEngine
from bootsentry.detect.rules import DeterministicRuleFloor
from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank
from bootsentry.measure.quote import (
    generate_attestation_quote,
    verify_attestation_quote,
)
from bootsentry.telemetry.record import BootRecord


@pytest.fixture
def clean_record():
    return BootRecord(
        boot_id="test-boot-001",
        timestamp_iso="2026-08-19T00:00:00Z",
        crypto_status="PASS",
        measurement_status="PASS",
        total_boot_time_ms=50.0,
    )


class TestHandoffMACSecurity:
    """Tests 1-5: Inter-Stage BootHandoff HMAC-SHA256 Authentication (F-02)."""

    def test_1_bit_flip_in_handoff_mac_fails_closed(self, tmp_path):
        secret = os.urandom(32)
        h = BootHandoff(
            boot_id="b1",
            current_stage="S0",
            next_stage="S1",
            pcr_state={"PCR0": "00" * 32},
            event_log_data=[],
        )
        h_file = tmp_path / "handoff.json"
        h.save(h_file, secret=secret)

        # Bit flip in the saved MAC
        data = json.loads(h_file.read_text(encoding="utf-8"))
        mac_chars = list(data["mac"])
        mac_chars[0] = "0" if mac_chars[0] != "0" else "1"
        data["mac"] = "".join(mac_chars)
        h_file.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(BootHandoffSecurityError, match="HMAC verification failed"):
            BootHandoff.load(h_file, secret=secret)

    def test_2_missing_handoff_mac_fails_closed(self, tmp_path):
        secret = os.urandom(32)
        h_file = tmp_path / "handoff_no_mac.json"
        raw_data = {
            "boot_id": "b1",
            "current_stage": "S0",
            "next_stage": "S1",
            "pcr_state": {"PCR0": "00" * 32},
            "event_log_data": [],
        }
        h_file.write_text(json.dumps(raw_data), encoding="utf-8")

        with pytest.raises(BootHandoffSecurityError, match="missing required HMAC signature"):
            BootHandoff.load(h_file, secret=secret)

    def test_3_tampered_stage_id_in_handoff_fails_closed(self, tmp_path):
        secret = os.urandom(32)
        h = BootHandoff(
            boot_id="b1",
            current_stage="S0",
            next_stage="S1",
            pcr_state={"PCR0": "00" * 32},
            event_log_data=[],
        )
        h_file = tmp_path / "handoff.json"
        h.save(h_file, secret=secret)

        # Tamper stage ID post-sign
        data = json.loads(h_file.read_text(encoding="utf-8"))
        data["next_stage"] = "S3"
        h_file.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(BootHandoffSecurityError):
            BootHandoff.load(h_file, secret=secret)

    def test_4_tampered_pcr_state_in_handoff_fails_closed(self, tmp_path):
        secret = os.urandom(32)
        h = BootHandoff(
            boot_id="b1",
            current_stage="S0",
            next_stage="S1",
            pcr_state={"PCR0": "00" * 32},
            event_log_data=[],
        )
        h_file = tmp_path / "handoff.json"
        h.save(h_file, secret=secret)

        # Tamper PCR state
        data = json.loads(h_file.read_text(encoding="utf-8"))
        data["pcr_state"]["PCR0"] = "ff" * 32
        h_file.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(BootHandoffSecurityError):
            BootHandoff.load(h_file, secret=secret)

    def test_5_replayed_handoff_from_previous_boot_fails(self, tmp_path):
        secret_boot_1 = os.urandom(32)
        secret_boot_2 = os.urandom(32)

        h = BootHandoff(
            boot_id="b1",
            current_stage="S0",
            next_stage="S1",
            pcr_state={"PCR0": "00" * 32},
            event_log_data=[],
        )
        h_file = tmp_path / "handoff.json"
        h.save(h_file, secret=secret_boot_1)

        # Loading with boot 2's secret must fail
        with pytest.raises(BootHandoffSecurityError):
            BootHandoff.load(h_file, secret=secret_boot_2)


class TestSVNFloorSecurity:
    """Tests 6-9: Security Version Counter (SVN) Floor Enforcement (F-03)."""

    def test_6_svn_rollback_below_floor_triggers_halt(self, clean_record):
        floor = DeterministicRuleFloor(min_trusted_svn={"S1": 1, "S2": 5, "S3": 1})
        result = floor.evaluate(clean_record, observed_svn=3, manifest_stage_id="S2")
        assert result.passed is False
        assert "RULE_SVN_ROLLBACK" in result.rules_triggered

        policy = BootPolicyEngine()
        decision = policy.decide(result)
        assert decision.verdict == "HALT"

    def test_7_svn_equal_to_floor_passes(self, clean_record):
        floor = DeterministicRuleFloor(min_trusted_svn={"S1": 1, "S2": 5, "S3": 1})
        result = floor.evaluate(clean_record, observed_svn=5, manifest_stage_id="S2")
        assert result.passed is True
        assert "RULE_SVN_ROLLBACK" not in result.rules_triggered

    def test_8_svn_above_floor_passes(self, clean_record):
        floor = DeterministicRuleFloor(min_trusted_svn={"S1": 1, "S2": 5, "S3": 1})
        result = floor.evaluate(clean_record, observed_svn=6, manifest_stage_id="S2")
        assert result.passed is True
        assert "RULE_SVN_ROLLBACK" not in result.rules_triggered

    def test_9_missing_stage_in_svn_floor_defaults_to_minimum(self, clean_record):
        floor = DeterministicRuleFloor(min_trusted_svn={"S2": 5})
        # Stage S4 not in map -> defaults to 1
        result_pass = floor.evaluate(clean_record, observed_svn=1, manifest_stage_id="S4")
        assert result_pass.passed is True

        result_fail = floor.evaluate(clean_record, observed_svn=0, manifest_stage_id="S4")
        assert result_fail.passed is False
        assert "RULE_SVN_ROLLBACK" in result_fail.rules_triggered


class TestPCRAllowlistSecurity:
    """Tests 10-12: Measured Boot PCR Allowlist Enforcement (F-04)."""

    def test_10_non_allowlisted_pcr_state_triggers_halt(self, clean_record):
        allowlist = {"golden_composite_hash_12345"}
        floor = DeterministicRuleFloor(allowlisted_pcrs=allowlist)
        result = floor.evaluate(clean_record, pcr_composite_digest="unauthorized_tampered_pcr_state")
        assert result.passed is False
        assert "RULE_PCR_NOT_ALLOWLISTED" in result.rules_triggered

        policy = BootPolicyEngine()
        decision = policy.decide(result)
        assert decision.verdict == "HALT"

    def test_11_allowlisted_pcr_state_passes(self, clean_record):
        allowlist = {"golden_composite_hash_12345"}
        floor = DeterministicRuleFloor(allowlisted_pcrs=allowlist)
        result = floor.evaluate(clean_record, pcr_composite_digest="golden_composite_hash_12345")
        assert result.passed is True
        assert "RULE_PCR_NOT_ALLOWLISTED" not in result.rules_triggered

    def test_12_tampered_pcr3_alone_triggers_not_allowlisted(self, clean_record):
        bank = PcrBank()
        bank.extend(0, "hash0")
        bank.extend(1, "hash1")
        bank.extend(2, "hash2")
        bank.extend(3, "hash3_golden")
        golden_digest = bank.composite_digest()

        floor = DeterministicRuleFloor(allowlisted_pcrs={golden_digest})

        # Tamper PCR3
        bank.extend(3, "hash3_tampered_extra_service")
        tampered_digest = bank.composite_digest()

        result = floor.evaluate(clean_record, pcr_composite_digest=tampered_digest)
        assert result.passed is False
        assert "RULE_PCR_NOT_ALLOWLISTED" in result.rules_triggered


class TestQuoteNonceAndModelAnchor:
    """Tests 13-15: Freshness Nonce in Quotes & Model Verification Anchor (F-05, F-06, G5)."""

    def test_13_quote_verification_with_matching_nonce_passes(self):
        bank = PcrBank()
        event_log = EventLog()
        _, _, sk_bytes = load_secret_key("config/keys/attest_private.json")
        _, _, pk_bytes = load_public_key("config/keys/attest_public.json")

        nonce_chall = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        quote = generate_attestation_quote(
            pcr_bank=bank,
            event_log=event_log,
            attestation_secret_key_bytes=sk_bytes,
            nonce=nonce_chall,
        )

        valid, reason = verify_attestation_quote(
            quote,
            attestation_public_key_bytes=pk_bytes,
            expected_nonce=nonce_chall,
        )
        assert valid is True
        assert "verified" in reason

    def test_14_quote_verification_with_mismatched_nonce_fails(self):
        bank = PcrBank()
        event_log = EventLog()
        _, _, sk_bytes = load_secret_key("config/keys/attest_private.json")
        _, _, pk_bytes = load_public_key("config/keys/attest_public.json")

        quote = generate_attestation_quote(
            pcr_bank=bank,
            event_log=event_log,
            attestation_secret_key_bytes=sk_bytes,
            nonce="original_nonce_1234",
        )

        valid, reason = verify_attestation_quote(
            quote,
            attestation_public_key_bytes=pk_bytes,
            expected_nonce="attacker_replayed_nonce_5678",
        )
        assert valid is False
        assert "Nonce mismatch" in reason

    def test_15_model_load_with_tampered_manifest_fails_before_load(self, tmp_path):
        # Setup models dir with dummy model file
        models_dir = tmp_path / "models"
        models_dir.mkdir()
        (models_dir / "isolation_forest.joblib").write_bytes(b"MODEL_BYTES")

        _, _, s3_sk = load_secret_key("config/keys/s3_private.json")
        _, _, s3_pk = load_public_key("config/keys/s3_public.json")

        manifest = create_model_manifest(
            models_dir=models_dir,
            signer_public_key_bytes=s3_pk,
            model_filenames=["isolation_forest.joblib"],
        )
        signed = sign_model_manifest(manifest, s3_sk)

        # Attacker modifies model file on disk
        (models_dir / "isolation_forest.joblib").write_bytes(b"MALICIOUS_PICKLE_EXPLOIT")

        # G5 check: verify_model_manifest fails before joblib.load is called
        with pytest.raises(VerificationError, match="Model file digest mismatch"):
            verify_model_manifest(
                signed,
                models_dir=models_dir,
                expected_public_key_bytes=s3_pk,
            )
