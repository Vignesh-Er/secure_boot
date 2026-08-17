"""Comprehensive evaluation forensics: analyze all evaluation protocols."""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

from bootsentry.telemetry.logger import read_boot_records
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

def compute_metrics(y_true, y_scores):
    roc = float(roc_auc_score(y_true, y_scores))
    pr = float(average_precision_score(y_true, y_scores))
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    idx_95 = np.searchsorted(tpr, 0.95)
    fpr_95 = float(fpr[min(idx_95, len(fpr) - 1)])
    return {"roc_auc": roc, "pr_auc": pr, "fpr_at_95_tpr": fpr_95}

def main():
    if_det = IsolationForestDetector.load('models/isolation_forest.joblib')
    mk_det = MarkovSequenceDetector.load('models/markov_sequence.joblib')
    ewma = EWMADriftMonitor.load('models/ewma_monitor.joblib')
    attr = AttributionEngine.load('models/attribution_engine.joblib')
    rule_floor = DeterministicRuleFloor(min_trusted_svn=5)
    policy = BootPolicyEngine()

    all_normal = read_boot_records('data/telemetry/normal_boots.jsonl')
    test_normal = all_normal[int(len(all_normal) * 0.8):]

    # Evaluate test normal boots
    normal_if = [if_det.score_record(r) for r in test_normal]
    normal_mk = [mk_det.score_record(r) for r in test_normal]
    normal_fused = []
    ewma.reset_online_state()
    for r in test_normal:
        s_if = if_det.score_record(r)
        s_mk = mk_det.score_record(r)
        _, d_score, _ = ewma.update(r, current_if_score=s_if)
        r_res = rule_floor.evaluate(r, observed_svn=5)
        dec = policy.decide(r_res, s_if, s_mk, d_score)
        normal_fused.append(dec.risk_score)

    print(f"Normal Test Boots (N={len(test_normal)}):")
    print(f"  IF scores: mean={np.mean(normal_if):.4f}, max={max(normal_if):.4f}")
    print(f"  Fused risk scores: mean={np.mean(normal_fused):.4f}, max={max(normal_fused):.4f}")

    # Generate Attacks
    _, r_a1, svn_a1 = execute_attack_a1(downgrade_svn=3)
    _, r_a2 = execute_attack_a2()
    _, r_a3 = execute_attack_a3()
    _, r_a5 = execute_attack_a5()

    ewma.reset_online_state()
    a4_boots = execute_attack_a4_sequence(num_boots=20)
    a4_d_scores = []
    for _, r_a4 in a4_boots:
        s_if = if_det.score_record(r_a4)
        _, d_score, _ = ewma.update(r_a4, current_if_score=s_if)
        a4_d_scores.append(d_score)

    attacks = [
        ("A1: Downgrade", r_a1, 1.0, svn_a1),
        ("A2: TOCTOU", r_a2, None, 5),
        ("A3: Reorder", r_a3, None, 5),
        ("A5: Cross-SKU", r_a5, None, 5),
    ]

    print("\n--- PROTOCOL 1: SCENARIO-LEVEL EVALUATION (Standard Security Benchmark) ---")
    # Each scenario is an evaluation unit (A1, A2, A3, A4_sequence, A5 vs Clean boots)
    y_true_scen = [0] * len(test_normal)
    y_scores_scen = list(normal_fused)

    # A1
    y_true_scen.append(1)
    y_scores_scen.append(1.0) # Rule HALT
    # A2
    s_if_a2 = if_det.score_record(r_a2)
    s_mk_a2 = mk_det.score_record(r_a2)
    dec_a2 = policy.decide(rule_floor.evaluate(r_a2, 5), s_if_a2, s_mk_a2, 0.0)
    y_true_scen.append(1)
    y_scores_scen.append(dec_a2.risk_score)
    # A3
    s_if_a3 = if_det.score_record(r_a3)
    s_mk_a3 = mk_det.score_record(r_a3)
    dec_a3 = policy.decide(rule_floor.evaluate(r_a3, 5), s_if_a3, s_mk_a3, 0.0)
    y_true_scen.append(1)
    y_scores_scen.append(dec_a3.risk_score)
    # A4 (Sequence max risk score)
    y_true_scen.append(1)
    y_scores_scen.append(max(a4_d_scores))
    # A5
    s_if_a5 = if_det.score_record(r_a5)
    s_mk_a5 = mk_det.score_record(r_a5)
    dec_a5 = policy.decide(rule_floor.evaluate(r_a5, 5), s_if_a5, s_mk_a5, 0.0)
    y_true_scen.append(1)
    y_scores_scen.append(dec_a5.risk_score)

    scen_metrics = compute_metrics(np.array(y_true_scen), np.array(y_scores_scen))
    print(f"Scenario-Level Metrics:")
    print(f"  ROC-AUC: {scen_metrics['roc_auc']:.4f}")
    print(f"  PR-AUC:  {scen_metrics['pr_auc']:.4f}")
    print(f"  FPR@95%TPR: {scen_metrics['fpr_at_95_tpr']:.4f}")
    print(f"  Scores: A1={1.0:.2f}, A2={dec_a2.risk_score:.2f}, A3={dec_a3.risk_score:.2f}, A4_seq={max(a4_d_scores):.2f}, A5={dec_a5.risk_score:.2f}")

    print("\n--- PROTOCOL 2: PREVIOUS FLAGGED PROTOCOL (All 20 sub-threshold A4 boots as individual samples) ---")
    y_true_old = [0] * len(test_normal)
    y_scores_old = list(normal_fused)
    y_true_old.append(1); y_scores_old.append(1.0)
    y_true_old.append(1); y_scores_old.append(s_if_a2)
    y_true_old.append(1); y_scores_old.append(s_mk_a3)
    for d_s in a4_d_scores:
        y_true_old.append(1); y_scores_old.append(d_s)
    y_true_old.append(1); y_scores_old.append(s_if_a5)

    old_metrics = compute_metrics(np.array(y_true_old), np.array(y_scores_old))
    print(f"Old Sample-Level Metrics:")
    print(f"  ROC-AUC: {old_metrics['roc_auc']:.4f}")
    print(f"  PR-AUC:  {old_metrics['pr_auc']:.4f}")
    print(f"  FPR@95%TPR: {old_metrics['fpr_at_95_tpr']:.4f}")

    print("\n--- DETECTOR-BY-DETECTOR ABLATION ON SCENARIOS ---")
    # IF only
    if_scen = list(normal_if) + [s_if_a2, s_if_a3, if_det.score_record(a4_boots[-1][1]), s_if_a5]
    if_labels = [0] * len(test_normal) + [1, 1, 1, 1]
    m_if = compute_metrics(np.array(if_labels), np.array(if_scen))
    print(f"Isolation Forest alone: ROC-AUC={m_if['roc_auc']:.4f}, PR-AUC={m_if['pr_auc']:.4f}, FPR@95%TPR={m_if['fpr_at_95_tpr']:.4f}")

    # Markov only (A3)
    mk_scen = list(normal_mk) + [mk_det.score_record(r_a3)]
    mk_labels = [0] * len(test_normal) + [1]
    m_mk = compute_metrics(np.array(mk_labels), np.array(mk_scen))
    print(f"Markov Detector alone on A3: ROC-AUC={m_mk['roc_auc']:.4f}, PR-AUC={m_mk['pr_auc']:.4f}, FPR@95%TPR={m_mk['fpr_at_95_tpr']:.4f}")

if __name__ == "__main__":
    main()
