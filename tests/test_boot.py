"""Integration tests for the 4-Stage Secure Boot Chain (S0 -> S1 -> S2 -> S3)."""

import pytest

from bootsentry.boot.handoff import BootHandoff
from bootsentry.boot.runner import execute_boot_chain, initialize_default_environment
from bootsentry.crypto.manifest import Manifest


@pytest.fixture
def boot_env(tmp_path):
    keys_dir, stages_dir = initialize_default_environment(base_dir=tmp_path)
    return tmp_path, keys_dir, stages_dir


class TestBootChainExecution:
    def test_clean_4_stage_boot_success(self, boot_env):
        tmp_path, keys_dir, stages_dir = boot_env
        run_dir = tmp_path / "run"

        res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
        )

        assert res.status == "COMPLETED"
        assert res.error_message is None
        assert res.quote is not None
        assert res.quote.signature is not None

        # Verify PCR extensions
        assert res.pcr_bank.read(0) != "0" * 64
        assert res.pcr_bank.read(1) != "0" * 64
        assert res.pcr_bank.read(2) != "0" * 64
        assert res.pcr_bank.read(3) != "0" * 64

        # Verify event log replay
        is_consistent, msg = res.event_log.verify_consistency(res.pcr_bank)
        assert is_consistent is True

        # Verify handoff states
        h3_file = run_dir / res.boot_id / "handoff_s3.json"
        assert h3_file.exists()
        h3 = BootHandoff.load(h3_file)
        assert h3.status == "COMPLETED"

    def test_boot_halt_on_s1_tampered_payload(self, boot_env):
        tmp_path, keys_dir, stages_dir = boot_env
        run_dir = tmp_path / "run"

        # Attacker modifies S1 payload binary
        s1_payload = stages_dir / "s1_payload.bin"
        s1_payload.write_bytes(b"MALICIOUS_BOOTLOADER_OVERWRITE")

        res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
        )

        # Invariant 1: Gate 1 Cryptographic failure must halt at S0
        assert res.status == "HALTED"
        assert "Gate 1 Cryptographic failure in S0 verifying S1" in res.error_message

    def test_boot_halt_on_s2_tampered_manifest(self, boot_env):
        tmp_path, keys_dir, stages_dir = boot_env
        run_dir = tmp_path / "run"

        # Attacker modifies S2 manifest security version counter
        s2_manifest_file = stages_dir / "s2_manifest.json"
        m = Manifest.load(s2_manifest_file)
        m.security_version_counter = 999  # Tamper after signing
        m.save(s2_manifest_file)

        res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
        )

        assert res.status == "HALTED"
        assert "Gate 1 Cryptographic failure in S1 verifying S2" in res.error_message

    def test_boot_halt_on_missing_stage_manifest(self, boot_env):
        tmp_path, keys_dir, stages_dir = boot_env
        run_dir = tmp_path / "run"

        # Delete S3 manifest
        s3_manifest_file = stages_dir / "s3_manifest.json"
        s3_manifest_file.unlink()

        res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
        )

        assert res.status == "HALTED"
        assert "Stage 3 Init manifest not found" in res.error_message

    def test_boot_custom_service_sequence(self, boot_env):
        tmp_path, keys_dir, stages_dir = boot_env
        run_dir = tmp_path / "run"

        custom_seq = ["svc_a", "svc_c", "svc_e"]
        res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
            service_sequence=custom_seq,
        )

        assert res.status == "COMPLETED"
        services_run = res.stage_metrics.get("services", {})
        assert set(services_run.keys()) == {"svc_a", "svc_c", "svc_e"}

    def test_boot_halt_on_unknown_service(self, boot_env):
        tmp_path, keys_dir, stages_dir = boot_env
        run_dir = tmp_path / "run"

        bad_seq = ["svc_a", "svc_unregistered_malicious"]
        res = execute_boot_chain(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
            service_sequence=bad_seq,
        )

        assert res.status == "HALTED"
        assert "Unknown service requested" in res.error_message
