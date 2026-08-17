"""Forensic Diagnostic Script to analyze ML evaluation mechanics."""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

from bootsentry.telemetry.logger import read_boot_records
from bootsentry.features.extractor import extract_feature_vector, extract_feature_matrix, FEATURE_NAMES
from bootsentry.detect.isolation_forest import IsolationForestDetector
from bootsentry.detect.markov import MarkovSequenceDetector
from bootsentry.detect.ewma import EWMADriftMonitor
from bootsentry.detect.attribution import AttributionEngine
from bootsentry.detect.policy import BootPolicyEngine
from bootsentry.detect.rules import DeterministicRuleFloor
from bootsentry.attacks.a1_downgrade import execute_attack_a1
from bootsentry.attacks.a2_toctou import execute_attack_a2
from bootsentry.attacks.a3_reorder import execute_attack_a3
from bootsentry.attacks.a4_drift import execute_attack_a4_sequence
from bootsentry.attacks.a5_cross_sku import execute_attack_a5
from bootsentry.attacks.benign_controls import execute_benign_cold_cache, execute_benign_firmware_upgrade, execute_benign_cpu_load

def main():
    print("=== BOOTSENTRY EVALUATION FORENSICS DIAGNOSTIC ===")
    
    # 1. Model Loading
    if_det = IsolationForestDetector.load('models/isolation_forest.joblib')
    mk_det = MarkovSequenceDetector.load('models/markov_sequence.joblib')
    ewma = EWMADriftMonitor.load('models/ewma_monitor.joblib')
    attr = AttributionEngine.load('models/attribution_engine.joblib')
    rule_floor = DeterministicRuleFloor(min_trusted_svn=5)
    policy = BootPolicyEngine()

    all_normal = read_boot_records('data/telemetry/normal_boots.jsonl')
    print(f"Total normal boots collected: {len(all_normal)}")
    split_idx = int(len(all_normal) * 0.8)
    train_normal = all_normal[:split_idx]
    test_normal = all_normal[split_idx:]
    print(f"Train boots: {len(train_normal)}, Test boots: {len(test_normal)}")

    # 2. Check Data Contamination
    train_ids = set(r.boot_id for r in train_normal)
    test_ids = set(r.boot_id for r in test_normal)
    overlap = train_ids.intersection(test_ids)
    print(f"Train/Test Boot ID overlap: {len(overlap)}")

    # 3. Score Distributions
    norm_if_scores = [if_det.score_record(r) for r in test_normal]
    norm_mk_scores = [mk_det.score_record(r) for r in test_normal]
    print(f"Clean Test Normal IF Scores: min={min(norm_if_scores):.4f}, mean={np.mean(norm_if_scores):.4f}, median={np.median(norm_if_scores):.4f}, max={max(norm_if_scores):.4f}")
    print(f"Clean Test Normal Markov Scores: min={min(norm_mk_scores):.4f}, mean={np.mean(norm_mk_scores):.4f}, max={max(norm_mk_scores):.4f}")

    # 4. Attack Evaluations
    print("\n--- ATTACK EVALUATION ---")
    # A1
    _, r_a1, svn_a1 = execute_attack_a1(downgrade_svn=3)
    a1_rule = rule_floor.evaluate(r_a1, observed_svn=svn_a1)
    a1_if = if_det.score_record(r_a1)
    a1_mk = mk_det.score_record(r_a1)
    print(f"A1 (Downgrade): Rules Triggered={a1_rule.rules_triggered}, IF Score={a1_if:.4f}, Markov={a1_mk:.4f}")

    # A2
    _, r_a2 = execute_attack_a2()
    a2_rule = rule_floor.evaluate(r_a2, observed_svn=5)
    a2_if = if_det.score_record(r_a2)
    a2_mk = mk_det.score_record(r_a2)
    a2_attr = attr.explain(r_a2, top_k=3)
    print(f"A2 (TOCTOU): Rules={a2_rule.rules_triggered}, IF Score={a2_if:.4f}, Markov={a2_mk:.4f}")
    for at in a2_attr:
        print(f"   Top Attribution: {at.feature_name} = {at.observed_value:.2f} ({at.formatted_sigma})")


    # A3
    _, r_a3 = execute_attack_a3()
    a3_rule = rule_floor.evaluate(r_a3, observed_svn=5)
    a3_if = if_det.score_record(r_a3)
    a3_mk = mk_det.score_record(r_a3)
    print(f"A3 (Service Reorder): Rules={a3_rule.rules_triggered}, IF Score={a3_if:.4f}, Markov={a3_mk:.4f}")

    # A4 Sequence
    ewma.reset_online_state()
    a4_boots = execute_attack_a4_sequence(num_boots=20)
    print(f"A4 Sequence (20 boots):")
    a4_d_scores = []
    a4_if_scores = []
    for idx, (_, r_a4) in enumerate(a4_boots):
        s_if = if_det.score_record(r_a4)
        is_drift, d_score, stat = ewma.update(r_a4, current_if_score=s_if)
        a4_d_scores.append(d_score)
        a4_if_scores.append(s_if)
        if (idx + 1) in [1, 5, 10, 12, 15, 20]:
            print(f"   Boot {idx+1:02d}: IF={s_if:.4f}, EWMA Drift Score={d_score:.4f}, Drift Flag={is_drift}")

    # A5 (Held-Out)
    _, r_a5 = execute_attack_a5()
    a5_rule = rule_floor.evaluate(r_a5, observed_svn=5)
    a5_if = if_det.score_record(r_a5)
    a5_mk = mk_det.score_record(r_a5)
    a5_attr = attr.explain(r_a5, top_k=3)
    print(f"A5 (Cross-SKU Held-Out): Rules={a5_rule.rules_triggered}, IF Score={a5_if:.4f}, Markov={a5_mk:.4f}")
    for at in a5_attr:
        print(f"   Top Attribution: {at.feature_name} = {at.observed_value:.2f} ({at.formatted_sigma})")


    # Benign
    print("\n--- BENIGN CONTROLS ---")
    _, b1 = execute_benign_cold_cache()
    _, b2 = execute_benign_firmware_upgrade(new_svn=6)
    _, b3 = execute_benign_cpu_load()
    for name, r, s in [("Cold Cache", b1, 5), ("Firmware Upgrade", b2, 6), ("Host CPU Load", b3, 5)]:
        r_chk = rule_floor.evaluate(r, observed_svn=s)
        s_if = if_det.score_record(r)
        s_mk = mk_det.score_record(r)
        dec = policy.decide(r_chk, s_if, s_mk, 0.0)
        print(f"Benign ({name}): Verdict={dec.verdict}, Rule={r_chk.rules_triggered}, IF Score={s_if:.4f}, Markov={s_mk:.4f}, Risk={dec.risk_score:.4f}")

if __name__ == "__main__":
    main()
