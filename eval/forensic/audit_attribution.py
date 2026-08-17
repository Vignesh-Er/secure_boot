"""Attribution Audit Script: Verify robust-z explanations for all attacks and benign controls."""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np

from bootsentry.detect.attribution import AttributionEngine
from bootsentry.attacks.a1_downgrade import execute_attack_a1
from bootsentry.attacks.a2_toctou import execute_attack_a2
from bootsentry.attacks.a3_reorder import execute_attack_a3
from bootsentry.attacks.a4_drift import execute_attack_a4_sequence
from bootsentry.attacks.a5_cross_sku import execute_attack_a5
from bootsentry.attacks.benign_controls import execute_benign_cold_cache, execute_benign_firmware_upgrade, execute_benign_cpu_load

def main():
    engine = AttributionEngine.load("models/attribution_engine.joblib")
    
    # 1. Execute Scenarios
    _, r_a1, _ = execute_attack_a1()
    _, r_a2 = execute_attack_a2()
    _, r_a3 = execute_attack_a3()
    a4_boots = execute_attack_a4_sequence(num_boots=20)
    r_a4 = a4_boots[-1][1] # Boot 20 of A4
    _, r_a5 = execute_attack_a5()
    _, r_b1 = execute_benign_cold_cache()
    _, r_b2 = execute_benign_firmware_upgrade(new_svn=6)
    _, r_b3 = execute_benign_cpu_load()

    scenarios = [
        ("A1: Signed Downgrade", r_a1),
        ("A2: TOCTOU Config Swap", r_a2),
        ("A3: Service Reorder", r_a3),
        ("A4: Slow-Drip Drift (Boot 20)", r_a4),
        ("A5: Cross-SKU (Held-Out)", r_a5),
        ("B1: Benign Cold Cache", r_b1),
        ("B2: Benign Firmware Upgrade", r_b2),
        ("B3: Benign CPU Load", r_b3),
    ]

    audit_results = {}

    print("=== FULL ATTRIBUTION AUDIT ===")
    for name, rec in scenarios:
        top_attrs = engine.explain(rec, top_k=3)
        top_list = []
        print(f"\nScenario: {name}")
        for a in top_attrs:
            assert np.isfinite(a.robust_z), f"Non-finite z found for {a.feature_name} in {name}"
            assert not np.isnan(a.robust_z), f"NaN z found for {a.feature_name} in {name}"
            print(f"  {a.feature_name:25s}: observed={a.observed_value:10.4f}, median={a.baseline_median:10.4f}, MAD={a.baseline_mad:10.4f}, robust_z={a.robust_z:+.2f}sigma ({a.formatted_sigma})")
            top_list.append({
                "feature_name": a.feature_name,
                "observed_value": a.observed_value,
                "baseline_median": a.baseline_median,
                "baseline_mad": a.baseline_mad,
                "robust_z": a.robust_z,
                "formatted_sigma": a.formatted_sigma,
            })
        audit_results[name] = top_list

    # Print Top 10 for A5 specifically
    print("\n=== A5 TOP 10 ATTRIBUTIONS (DETAILED) ===")
    a5_top10 = engine.explain(r_a5, top_k=10)
    for a in a5_top10:
        print(f"  {a.feature_name:25s}: observed={a.observed_value:10.4f}, median={a.baseline_median:10.4f}, MAD={a.baseline_mad:10.4f}, robust_z={a.robust_z:+.2f}sigma")

    out_file = Path("eval/forensic/attribution_audit.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(audit_results, f, indent=2)

    print(f"\n[OK] Attribution audit written to {out_file}")

if __name__ == "__main__":
    main()
