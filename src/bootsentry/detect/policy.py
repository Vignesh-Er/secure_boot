"""Three-Level Boot Policy Engine (PASS | WARN + ATTEST | HALT).

Enforces Non-Negotiable Security Invariant 3:
- Cryptographic Gate 1 fail -> HALT
- Measurement Gate 2 fail -> HALT
- Deterministic Rule fail -> HALT
- AI Gate 3 anomaly alone -> WARN + ATTEST (Cannot independently HALT / brick device)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bootsentry.detect.attribution import FeatureAttribution
from bootsentry.detect.rules import RuleCheckResult


@dataclass
class PolicyDecision:
    verdict: str  # "PASS", "WARN", or "HALT"
    reason: str
    risk_score: float  # Composite risk score in [0.0, 1.0]
    crypto_status: str  # "PASS" or "FAIL"
    measurement_status: str  # "PASS" or "FAIL"
    rules_triggered: list[str] = field(default_factory=list)
    detector_scores: dict[str, float] = field(default_factory=dict)
    top_attributions: list[FeatureAttribution] = field(default_factory=list)
    attestation_status: str = "TRUSTED"  # "TRUSTED", "REDUCED_TRUST", "UNTRUSTED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "crypto_status": self.crypto_status,
            "measurement_status": self.measurement_status,
            "rules_triggered": self.rules_triggered,
            "detector_scores": self.detector_scores,
            "top_attributions": [a.to_dict() for a in self.top_attributions],
            "attestation_status": self.attestation_status,
        }


class BootPolicyEngine:
    """Evaluates multi-gate signals to arrive at a safe, deterministic boot policy decision."""

    def __init__(
        self,
        if_threshold: float = 0.5,
        markov_threshold: float = 0.5,
        drift_threshold: float = 0.5,
    ):
        self.if_threshold = if_threshold
        self.markov_threshold = markov_threshold
        self.drift_threshold = drift_threshold

    def decide(
        self,
        rule_result: RuleCheckResult,
        if_score: float = 0.0,
        markov_score: float = 0.0,
        drift_score: float = 0.0,
        attributions: list[FeatureAttribution] | None = None,
    ) -> PolicyDecision:
        """Calculate final policy decision with strict invariant enforcement."""
        detector_scores = {
            "isolation_forest": round(if_score, 4),
            "markov_sequence": round(markov_score, 4),
            "ewma_drift": round(drift_score, 4),
        }
        top_attrs = attributions or []

        # Calculate composite behavioral risk score (max or weighted combination)
        composite_risk = max(if_score, markov_score, drift_score)

        # ---------------------------------------------------------------------
        # Case 1: Deterministic Security Rule Floor Fires -> HALT
        # ---------------------------------------------------------------------
        if not rule_result.passed:
            reasons_str = "; ".join(rule_result.reasons)
            crypto_stat = "FAIL" if "RULE_CRYPTO_VERIFICATION_FAILED" in rule_result.rules_triggered else "PASS"
            meas_stat = "FAIL" if "RULE_MEASUREMENT_VERIFICATION_FAILED" in rule_result.rules_triggered else "PASS"

            return PolicyDecision(
                verdict="HALT",
                reason=f"Deterministic rule violation: {reasons_str}",
                risk_score=1.0,
                crypto_status=crypto_stat,
                measurement_status=meas_stat,
                rules_triggered=rule_result.rules_triggered,
                detector_scores=detector_scores,
                top_attributions=top_attrs,
                attestation_status="UNTRUSTED",
            )

        # ---------------------------------------------------------------------
        # Case 2: Behavioral Anomaly Detected (Rules Clean) -> WARN + ATTEST
        # INVARIANT 3: ML anomaly alone CANNOT authorize HALT
        # ---------------------------------------------------------------------
        ai_anomalies = []
        if if_score >= self.if_threshold:
            ai_anomalies.append(f"Process behavioral anomaly (score={if_score:.2f})")
        if markov_score >= self.markov_threshold:
            ai_anomalies.append(f"Service sequence anomaly (score={markov_score:.2f})")
        if drift_score >= self.drift_threshold:
            ai_anomalies.append(f"Multi-boot behavioral drift (score={drift_score:.2f})")

        if ai_anomalies:
            anomaly_summary = "; ".join(ai_anomalies)
            return PolicyDecision(
                verdict="WARN",
                reason=f"Authentic signatures verified; AI behavioral anomaly detected: {anomaly_summary}",
                risk_score=composite_risk,
                crypto_status="PASS",
                measurement_status="PASS",
                rules_triggered=[],
                detector_scores=detector_scores,
                top_attributions=top_attrs,
                attestation_status="REDUCED_TRUST",
            )

        # ---------------------------------------------------------------------
        # Case 3: Fully Clean Boot -> PASS
        # ---------------------------------------------------------------------
        return PolicyDecision(
            verdict="PASS",
            reason="All cryptographic signatures verified; normal behavioral telemetry baseline",
            risk_score=composite_risk,
            crypto_status="PASS",
            measurement_status="PASS",
            rules_triggered=[],
            detector_scores=detector_scores,
            top_attributions=top_attrs,
            attestation_status="TRUSTED",
        )
