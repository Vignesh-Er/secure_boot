"""Unit tests for Measured Boot (PCR, Event Log, Attestation Quote)."""

import pytest

from bootsentry.crypto.keys import generate_stage_keypair
from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank
from bootsentry.measure.quote import (
    generate_attestation_quote,
    verify_attestation_quote,
)


class TestPcrBank:
    def test_pcr_initialization_zeros(self):
        bank = PcrBank(num_registers=8)
        assert len(bank.registers) == 8
        for i in range(8):
            assert bank.read(i) == "0" * 64

    def test_pcr_extend_sha256(self):
        bank = PcrBank()
        # Initial is 000...000
        # Extend with "test_payload"
        d1 = bank.extend(0, "test_payload")
        assert len(d1) == 64
        assert bank.read(0) == d1

        # Second extend modifies the state deterministically
        d2 = bank.extend(0, "another_payload")
        assert d2 != d1
        assert bank.read(0) == d2

    def test_pcr_composite_digest_determinism(self):
        bank1 = PcrBank()
        bank2 = PcrBank()

        bank1.extend(0, "payload_a")
        bank1.extend(1, "payload_b")

        bank2.extend(0, "payload_a")
        bank2.extend(1, "payload_b")

        assert bank1.composite_digest() == bank2.composite_digest()

    def test_pcr_out_of_bounds(self):
        bank = PcrBank(num_registers=8)
        with pytest.raises(IndexError):
            bank.extend(99, "bad_index")
        with pytest.raises(IndexError):
            bank.read(99)

    def test_pcr_serialization_roundtrip(self):
        bank = PcrBank()
        bank.extend(0, "sample_measurement")
        bank.extend(3, "service_measurement")

        d = bank.to_dict()
        restored = PcrBank.from_dict(d)
        assert restored.snapshot() == bank.snapshot()


class TestEventLog:
    def test_event_log_append_and_replay(self):
        log = EventLog()
        log.record_event("S0", "ROM_INIT", 0, "abcd" * 16, "1.0.0")
        log.record_event("S1", "STAGE_MEASUREMENT", 1, "1234" * 16, "1.0.0")
        log.record_event("S2", "KERNEL_INIT", 2, "5678" * 16, "1.0.0")

        assert len(log.entries) == 3
        assert log.entries[0].sequence_number == 0
        assert log.entries[1].sequence_number == 1
        assert log.entries[2].sequence_number == 2

        # Replay into PCR bank
        replayed_bank = log.replay_pcrs()
        is_consistent, msg = log.verify_consistency(replayed_bank)
        assert is_consistent is True
        assert "reproduces PCR bank state" in msg

    def test_event_log_tamper_detection(self):
        log = EventLog()
        log.record_event("S0", "ROM_INIT", 0, "abcd" * 16)
        replayed_bank = log.replay_pcrs()

        # Malicious actor tampers with a PCR directly
        replayed_bank.extend(0, "unlogged_tamper_event")

        is_consistent, msg = log.verify_consistency(replayed_bank)
        assert is_consistent is False
        assert "mismatch" in msg

    def test_event_log_cumulative_digest(self):
        log1 = EventLog()
        log1.record_event("S0", "EVENT1", 0, "1111" * 16, timestamp_ns=100)
        log1.record_event("S1", "EVENT2", 1, "2222" * 16, timestamp_ns=200)

        log2 = EventLog()
        log2.record_event("S0", "EVENT1", 0, "1111" * 16, timestamp_ns=100)
        log2.record_event("S1", "EVENT2", 1, "2222" * 16, timestamp_ns=200)

        assert log1.cumulative_digest() == log2.cumulative_digest()


class TestAttestationQuote:
    @pytest.fixture
    def attest_keys(self):
        return generate_stage_keypair("ATTEST", "ML-DSA-65")

    def test_generate_and_verify_quote_happy_path(self, attest_keys):
        bank = PcrBank()
        bank.extend(0, "stage0_measurement")
        bank.extend(1, "stage1_measurement")

        log = EventLog()
        log.record_event("S0", "STAGE_0", 0, "stage0_measurement")
        log.record_event("S1", "STAGE_1", 1, "stage1_measurement")

        nonce = "fedcba9876543210"
        quote = generate_attestation_quote(
            pcr_bank=bank,
            event_log=log,
            attestation_secret_key_bytes=attest_keys.secret_key_bytes,
            nonce=nonce,
            algorithm="ML-DSA-65",
        )
        assert quote.signature is not None
        assert quote.nonce == nonce

        # Verify quote
        valid, reason = verify_attestation_quote(
            quote=quote,
            attestation_public_key_bytes=attest_keys.public_key_bytes,
            expected_nonce=nonce,
        )
        assert valid is True
        assert "verified" in reason

    def test_verify_quote_wrong_nonce(self, attest_keys):
        bank = PcrBank()
        log = EventLog()
        quote = generate_attestation_quote(
            pcr_bank=bank,
            event_log=log,
            attestation_secret_key_bytes=attest_keys.secret_key_bytes,
            nonce="correct_nonce",
        )

        valid, reason = verify_attestation_quote(
            quote=quote,
            attestation_public_key_bytes=attest_keys.public_key_bytes,
            expected_nonce="wrong_challenge_nonce",
        )
        assert valid is False
        assert "Nonce mismatch" in reason

    def test_verify_quote_tampered_pcr_state(self, attest_keys):
        bank = PcrBank()
        log = EventLog()
        quote = generate_attestation_quote(
            pcr_bank=bank,
            event_log=log,
            attestation_secret_key_bytes=attest_keys.secret_key_bytes,
        )

        # Attacker modifies PCR snapshot after signature
        quote.pcr_snapshot["PCR0"] = "f" * 64
        valid, reason = verify_attestation_quote(
            quote=quote,
            attestation_public_key_bytes=attest_keys.public_key_bytes,
        )
        assert valid is False
        assert "verification failed" in reason
