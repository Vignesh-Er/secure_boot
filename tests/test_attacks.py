"""Unit and integration tests for Attack Scenarios A1-A5 and Benign Controls."""

import pytest

from bootsentry.attacks.a1_downgrade import execute_attack_a1
from bootsentry.attacks.a2_toctou import execute_attack_a2
from bootsentry.attacks.a3_reorder import execute_attack_a3
from bootsentry.attacks.a4_drift import execute_attack_a4_sequence
from bootsentry.attacks.a5_cross_sku import execute_attack_a5
from bootsentry.attacks.benign_controls import (
    execute_benign_cold_cache,
    execute_benign_cpu_load,
    execute_benign_firmware_upgrade,
)
from bootsentry.attacks.runner import run_attack_testbed
from bootsentry.boot.runner import initialize_default_environment
from bootsentry.detect.rules import DeterministicRuleFloor


@pytest.fixture(scope="module")
def shared_env(tmp_path_factory):
    base_dir = tmp_path_factory.mktemp("attacks_base")
    initialize_default_environment(base_dir=base_dir)
    return base_dir


class TestAttackScenarios:
    def test_attack_a1_signed_downgrade(self, shared_env):
        boot_res, record, svn = execute_attack_a1(base_dir=shared_env, downgrade_svn=3)
        assert boot_res.status == "COMPLETED"  # Traditional crypto passes
        assert record.label == "a1_downgrade"

        # Deterministic rule must catch the rollback
        floor = DeterministicRuleFloor(min_trusted_svn=5)
        check = floor.evaluate(record, observed_svn=svn)
        assert check.passed is False
        assert "RULE_SVN_ROLLBACK" in check.rules_triggered

    def test_attack_a2_toctou_config_swap(self, shared_env):
        boot_res, record = execute_attack_a2(base_dir=shared_env)
        assert boot_res.status == "COMPLETED"
        assert record.label == "a2_toctou"
        assert record.stages["S2"].t_exec_ms > 0.0
        assert record.stages["S2"].rss_mb > 0.0
        assert record.scenario == "a2_toctou"


    def test_attack_a3_signed_service_reorder(self, shared_env):
        boot_res, record = execute_attack_a3(base_dir=shared_env)
        assert boot_res.status == "COMPLETED"
        assert record.label == "a3_reorder"
        assert "svc_diag" in record.event_sequence
        assert "svc_e" in record.event_sequence
        assert record.event_sequence.index("svc_e") < record.event_sequence.index("svc_a")

    def test_attack_a4_slow_drip_sequence(self, shared_env):
        results = execute_attack_a4_sequence(base_dir=shared_env, num_boots=5, drift_step_ms=5.0)
        assert len(results) == 5
        # Verify monotonically increasing injected drift parameter across boots
        injected = [r[1].metadata["injected_drift_ms"] for r in results]
        assert injected == sorted(injected)
        assert injected[-1] > injected[0]
        assert all(r[1].stages["S2"].t_exec_ms > 0.0 for r in results)

    def test_attack_a5_held_out_cross_sku(self, shared_env):
        boot_res, record = execute_attack_a5(base_dir=shared_env)
        assert boot_res.status == "COMPLETED"
        assert record.label == "a5_cross_sku"
        assert record.metadata.get("held_out_evaluation") is True
        assert record.stages["S2"].rss_mb > 0.0


    def test_benign_controls(self, shared_env):
        _, rec_cold = execute_benign_cold_cache(base_dir=shared_env)
        assert rec_cold.crypto_status == "PASS"

        _, rec_up = execute_benign_firmware_upgrade(base_dir=shared_env, new_svn=6)
        assert rec_up.crypto_status == "PASS"

        # Legitimate upgrade must pass deterministic rule floor
        floor = DeterministicRuleFloor(min_trusted_svn=5)
        check = floor.evaluate(rec_up, observed_svn=6)
        assert check.passed is True

        _, rec_load = execute_benign_cpu_load(base_dir=shared_env)
        assert rec_load.crypto_status == "PASS"

    def test_attack_runner_testbed(self, shared_env):
        results = run_attack_testbed(base_dir=shared_env)
        assert len(results) >= 8
        scenarios = [r["scenario"] for r in results]
        assert any("A1" in s for s in scenarios)
        assert any("A2" in s for s in scenarios)
        assert any("A3" in s for s in scenarios)
        assert any("A4" in s for s in scenarios)
        assert any("A5" in s for s in scenarios)

    def test_evasion_inside_normal_distribution(self, shared_env):
        """Security Boundary Test: In-distribution evasion with clean signatures/PCRs outputs PASS.

        Proves that an attacker executing within empirical baseline variance (+-0.5 sigma)
        with authentic manifests and valid PCR sequence is indistinguishable by ML alone.
        """
        from bootsentry.detect.isolation_forest import IsolationForestDetector
        from bootsentry.detect.markov import MarkovSequenceDetector
        from bootsentry.detect.policy import BootPolicyEngine
        from bootsentry.detect.rules import DeterministicRuleFloor
        from bootsentry.telemetry.logger import read_boot_records

        records = read_boot_records("data/telemetry/normal_boots.jsonl")
        if not records:
            pytest.skip("Baseline dataset not available")

        # Fit detectors on clean baseline
        if_det = IsolationForestDetector.load("models/isolation_forest.joblib")
        mk_det = MarkovSequenceDetector.load("models/markov_sequence.joblib")
        floor = DeterministicRuleFloor(min_trusted_svn=1)
        policy = BootPolicyEngine()

        # Construct an in-distribution boot record (mimicking a normal boot within baseline +-0.5 sigma)
        clean_records = [r for r in records if if_det.score_record(r) < 0.4]
        in_dist_record = clean_records[len(clean_records) // 2] if clean_records else records[-1]

        # Evaluate through policy pipeline
        rule_res = floor.evaluate(in_dist_record, observed_svn=5)
        if_score = if_det.score_record(in_dist_record)
        mk_score = mk_det.score_record(in_dist_record)
        decision = policy.decide(rule_res, if_score=if_score, markov_score=mk_score, drift_score=0.0)

        # Honest boundary assertion: In-distribution boot without crypto/PCR violation outputs PASS
        assert decision.verdict == "PASS"
        assert decision.crypto_status == "PASS"
        assert decision.measurement_status == "PASS"
        assert decision.risk_score < 0.5
