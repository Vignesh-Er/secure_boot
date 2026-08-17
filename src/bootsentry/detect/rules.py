"""Deterministic Security Rule Floor.

These deterministic security rules can independently authorize a HALT verdict.
AI / ML anomaly scores never override or weaken these rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank
from bootsentry.telemetry.record import BootRecord


@dataclass
class RuleCheckResult:
    passed: bool
    rules_triggered: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class DeterministicRuleFloor:
    """Evaluates non-negotiable deterministic security rules."""

    def __init__(
        self,
        min_trusted_svn: int = 5,
        allowlisted_pcrs: Optional[Set[str]] = None,
        required_stages: Optional[List[str]] = None,
    ):
        self.min_trusted_svn = min_trusted_svn
        self.allowlisted_pcrs = allowlisted_pcrs or set()
        self.required_stages = required_stages or ["S0", "S1", "S2", "S3"]

    def evaluate(
        self,
        record: BootRecord,
        observed_svn: Optional[int] = None,
        pcr_composite_digest: Optional[str] = None,
        manifest_stage_id: Optional[str] = None,
        expected_stage_id: Optional[str] = None,
    ) -> RuleCheckResult:
        """Run all deterministic security rules."""
        triggered = []
        reasons = []
        details = {}

        # Rule 1: Security Version Counter (SVN) Rollback Check
        if observed_svn is not None and observed_svn < self.min_trusted_svn:
            triggered.append("RULE_SVN_ROLLBACK")
            reasons.append(
                f"Security Version Rollback detected: observed SVN={observed_svn} < trusted minimum SVN={self.min_trusted_svn}"
            )
            details["observed_svn"] = observed_svn
            details["min_trusted_svn"] = self.min_trusted_svn

        # Rule 2: Allowlisted PCR Check (if allowlist configured)
        if self.allowlisted_pcrs and pcr_composite_digest is not None:
            if pcr_composite_digest not in self.allowlisted_pcrs:
                triggered.append("RULE_PCR_NOT_ALLOWLISTED")
                reasons.append(
                    f"PCR composite measurement {pcr_composite_digest[:16]}... is not in the trusted allowlist"
                )
                details["pcr_composite_digest"] = pcr_composite_digest

        # Rule 3: Stage Identity Mismatch
        if manifest_stage_id and expected_stage_id:
            if manifest_stage_id != expected_stage_id:
                triggered.append("RULE_STAGE_MISMATCH")
                reasons.append(
                    f"Stage ID mismatch: manifest declares '{manifest_stage_id}', executing as '{expected_stage_id}'"
                )

        # Rule 4: Crypto Status Check (from Gate 1)
        if record.crypto_status not in ("PASS", "COMPLETED"):
            triggered.append("RULE_CRYPTO_VERIFICATION_FAILED")
            reasons.append("Cryptographic signature verification failed at Gate 1")

        # Rule 5: Measurement Status Check (from Gate 2)
        if record.measurement_status not in ("PASS", "COMPLETED"):
            triggered.append("RULE_MEASUREMENT_VERIFICATION_FAILED")
            reasons.append("Measured boot state verification failed at Gate 2")


        passed = len(triggered) == 0
        return RuleCheckResult(
            passed=passed,
            rules_triggered=triggered,
            reasons=reasons,
            details=details,
        )
