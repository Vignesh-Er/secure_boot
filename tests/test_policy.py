"""Unit tests for Deterministic Rules and Policy Engine (Invariant 3 validation)."""

import pytest

from bootsentry.detect.attribution import FeatureAttribution
from bootsentry.detect.policy import BootPolicyEngine
from bootsentry.detect.rules import DeterministicRuleFloor, RuleCheckResult
from bootsentry.telemetry.record import BootRecord


class TestDeterministicRuleFloor:
    def test_clean_rules_pass(self):
        floor = DeterministicRuleFloor(min_trusted_svn=5)
        rec = BootRecord(
            boot_id="rec-1",
            timestamp_iso="2026-08-17T08:00:00Z",
            crypto_status="PASS",
            measurement_status="PASS",
        )
        res = floor.evaluate(rec, observed_svn=5)
        assert res.passed is True
        assert len(res.rules_triggered) == 0

    def test_svn_rollback_triggers_rule(self):
        floor = DeterministicRuleFloor(min_trusted_svn=5)
        rec = BootRecord(
            boot_id="rec-2",
            timestamp_iso="2026-08-17T08:00:00Z",
            crypto_status="PASS",
            measurement_status="PASS",
        )
        # Attacker downgraded to authentic SVN=3
        res = floor.evaluate(rec, observed_svn=3)
        assert res.passed is False
        assert "RULE_SVN_ROLLBACK" in res.rules_triggered

    def test_pcr_allowlist_mismatch_triggers_rule(self):
        floor = DeterministicRuleFloor(min_trusted_svn=5, allowlisted_pcrs={"valid_hash_1", "valid_hash_2"})
        rec = BootRecord(
            boot_id="rec-3",
            timestamp_iso="2026-08-17T08:00:00Z",
            crypto_status="PASS",
            measurement_status="PASS",
        )
        res = floor.evaluate(rec, observed_svn=5, pcr_composite_digest="unrecognized_pcr_hash")
        assert res.passed is False
        assert "RULE_PCR_NOT_ALLOWLISTED" in res.rules_triggered


class TestPolicyEngine:
    @pytest.fixture
    def policy_engine(self):
        return BootPolicyEngine(if_threshold=0.5, markov_threshold=0.5, drift_threshold=0.5)

    def test_policy_pass_on_clean_boot(self, policy_engine):
        rule_res = RuleCheckResult(passed=True)
        decision = policy_engine.decide(
            rule_result=rule_res,
            if_score=0.1,
            markov_score=0.05,
            drift_score=0.12,
        )
        assert decision.verdict == "PASS"
        assert decision.attestation_status == "TRUSTED"
        assert len(decision.rules_triggered) == 0

    def test_policy_invariant_3_ml_anomaly_produces_warn_never_halt(self, policy_engine):
        """CRITICAL TEST FOR SECURITY INVARIANT 3:

        ML anomaly scores (even 1.0 maximum anomaly) must produce WARN + REDUCED TRUST,
        NEVER an independent HALT.
        """
        rule_res = RuleCheckResult(passed=True)  # Rules are clean
        decision = policy_engine.decide(
            rule_result=rule_res,
            if_score=0.99,  # Extreme IF anomaly
            markov_score=0.88,  # Extreme Markov anomaly
            drift_score=0.95,  # Extreme Drift anomaly
            attributions=[
                FeatureAttribution("t_exec_s2", 150.0, 10.0, 1.0, 9.4),
            ],
        )

        # Invariant 3 check: Verdict MUST NOT BE HALT
        assert decision.verdict == "WARN"
        assert decision.attestation_status == "REDUCED_TRUST"
        assert "AI behavioral anomaly detected" in decision.reason
        assert decision.crypto_status == "PASS"
        assert len(decision.top_attributions) == 1

    def test_policy_isolated_if_anomaly_produces_warn(self, policy_engine):
        rule_res = RuleCheckResult(passed=True)
        decision = policy_engine.decide(rule_result=rule_res, if_score=0.95, markov_score=0.1, drift_score=0.1)
        assert decision.verdict == "WARN"
        assert decision.attestation_status == "REDUCED_TRUST"

    def test_policy_isolated_markov_anomaly_produces_warn(self, policy_engine):
        rule_res = RuleCheckResult(passed=True)
        decision = policy_engine.decide(rule_result=rule_res, if_score=0.1, markov_score=0.95, drift_score=0.1)
        assert decision.verdict == "WARN"
        assert decision.attestation_status == "REDUCED_TRUST"

    def test_policy_isolated_ewma_anomaly_produces_warn(self, policy_engine):
        rule_res = RuleCheckResult(passed=True)
        decision = policy_engine.decide(rule_result=rule_res, if_score=0.1, markov_score=0.1, drift_score=0.95)
        assert decision.verdict == "WARN"
        assert decision.attestation_status == "REDUCED_TRUST"

    def test_policy_halt_on_all_individual_rules(self, policy_engine):
        rule_names = [
            "RULE_SVN_ROLLBACK",
            "RULE_PCR_NOT_ALLOWLISTED",
            "RULE_STAGE_MISMATCH",
            "RULE_CRYPTO_VERIFICATION_FAILED",
            "RULE_MEASUREMENT_VERIFICATION_FAILED",
        ]
        for r_name in rule_names:
            rule_res = RuleCheckResult(passed=False, rules_triggered=[r_name], reasons=[f"Violation of {r_name}"])
            decision = policy_engine.decide(rule_result=rule_res, if_score=0.1)
            assert decision.verdict == "HALT"
            assert decision.attestation_status == "UNTRUSTED"
            assert r_name in decision.rules_triggered

