#include "bootsentry_telemetry.h"
#include <string.h>
#include <math.h>

/* Forward declaration of transpiled decision tree evaluation */
extern float bootsentry_evaluate_isolation_forest(const float features[BOOTSENTRY_NUM_FEATURES]);
extern float bootsentry_evaluate_markov_sequence(void);

/* Default baseline statistics for robust dispersion attribution (28 features) */
static const float BASELINE_MEDIANS[BOOTSENTRY_NUM_FEATURES] = {
    21.08f, 21.15f, 21.03f, 25.40f,  /* 0-3 durations */
    0.23f, 0.23f, 0.23f, 0.28f,       /* 4-7 duration ratios */
    45.0f, 65.0f, 120.0f, 180.0f,     /* 8-11 RSS MB */
    12.0f, 0.0f,                      /* 12-13 ctx switches */
    32.0f, 32.0f, 1.0f,               /* 14-16 IO read/write */
    150000.0f, 180000.0f, 350000.0f, 420000.0f, /* 17-20 Inst retired */
    1200.0f, 2400.0f, 450.0f, 890.0f,  /* 21-24 Cache/branch */
    0.15f, 0.20f, 0.35f               /* 25-27 Cycle ratios */
};

static const float BASELINE_SCALES[BOOTSENTRY_NUM_FEATURES] = {
    0.28f, 0.32f, 0.31f, 0.45f,
    0.02f, 0.02f, 0.02f, 0.03f,
    2.5f, 3.1f, 5.2f, 6.4f,
    1.5f, 1.0f,
    4.0f, 4.0f, 1.0f,
    5000.0f, 6000.0f, 12000.0f, 15000.0f,
    80.0f, 150.0f, 35.0f, 60.0f,
    0.02f, 0.02f, 0.03f
};

static const char* FEATURE_NAMES[BOOTSENTRY_NUM_FEATURES] = {
    "duration_s0_ms", "duration_s1_ms", "duration_s2_ms", "duration_s3_ms",
    "dur_ratio_s0", "dur_ratio_s1", "dur_ratio_s2", "dur_ratio_s3",
    "rss_s0_mb", "rss_s1_mb", "rss_s2_mb", "rss_s3_mb",
    "ctx_switches_vol", "ctx_switches_invol",
    "io_read_bytes_kb", "io_write_bytes_kb", "io_read_write_ratio",
    "inst_retired_s0", "inst_retired_s1", "inst_retired_s2", "inst_retired_s3",
    "l1i_miss_s0", "l1i_miss_s1", "branch_mispred_s0", "branch_mispred_s1",
    "cycle_ratio_s0", "cycle_ratio_s1", "cycle_ratio_s2"
};

PolicyDecisionResult bootsentry_evaluate_policy(
    const BootFeatureVector* vector,
    uint32_t svn,
    bool crypto_pass,
    bool pcr_pass
) {
    PolicyDecisionResult result;
    memset(&result, 0, sizeof(PolicyDecisionResult));

    /* Gate 1: Cryptographic verification is deterministic & blocking */
    if (!crypto_pass) {
        result.verdict = POLICY_VERDICT_HALT;
        result.rules_triggered_bitmap |= (1 << 0);
        return result;
    }

    /* Gate 2: Measured boot verification is deterministic & blocking */
    if (!pcr_pass) {
        result.verdict = POLICY_VERDICT_HALT;
        result.rules_triggered_bitmap |= (1 << 1);
        return result;
    }

    /* Deterministic Rule Floor: SVN Rollback */
    if (svn < 5) {
        result.verdict = POLICY_VERDICT_HALT;
        result.rules_triggered_bitmap |= (1 << 2);
        return result;
    }

    /* Gate 3: Evaluate Behavioral Models (Transpiled C trees & Markov) */
    float if_score = 0.0f;
    float markov_score = 0.0f;
    float ewma_score = 0.0f;

    if (vector) {
        if_score = bootsentry_evaluate_isolation_forest(vector->features);
        markov_score = bootsentry_evaluate_markov_sequence();
    }

    result.isolation_forest_score = if_score;
    result.markov_nll_score = markov_score;
    result.ewma_drift_score = ewma_score;
    result.composite_risk_score = (if_score > markov_score) ? if_score : markov_score;

    /* Compute Primary Feature Attribution via Robust Dispersion */
    float max_abs_z = 0.0f;
    int max_z_idx = 0;
    if (vector) {
        for (int i = 0; i < BOOTSENTRY_NUM_FEATURES; i++) {
            float obs = vector->features[i];
            float med = BASELINE_MEDIANS[i];
            float scale = BASELINE_SCALES[i];
            float z = 0.0f;
            if (fabsf(obs - med) > 1e-6f && scale > 1e-6f) {
                z = (obs - med) / scale;
            }
            if (fabsf(z) > max_abs_z) {
                max_abs_z = fabsf(z);
                max_z_idx = i;
            }
        }
        strncpy(result.primary_attribution_feature, FEATURE_NAMES[max_z_idx], sizeof(result.primary_attribution_feature) - 1);
    }
    result.primary_attribution_z = max_abs_z;


    /* Invariant 3: AI anomaly scores produce WARN + REDUCED_TRUST, never HALT */
    if (result.composite_risk_score > 0.50f) {
        result.verdict = POLICY_VERDICT_WARN_REDUCED_TRUST;
    } else {
        result.verdict = POLICY_VERDICT_PASS;
    }

    return result;
}

/* Default fallback C decision tree evaluation if not overridden by generated_trees.c */
__attribute__((weak))
float bootsentry_evaluate_isolation_forest(const float features[BOOTSENTRY_NUM_FEATURES]) {
    /* Simple baseline check on memory and IO if trees not compiled */
    if (features[16] > 100.0f || features[10] > 200.0f) {
        return 0.58f;
    }
    return 0.20f;
}

__attribute__((weak))
float bootsentry_evaluate_markov_sequence(void) {
    return 0.0f;
}
