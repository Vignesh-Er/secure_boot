#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/bootsentry_telemetry.h"
#include "../include/bootsentry_crypto.h"
#include "../include/bootsentry_pcr.h"

// Forward declaration of transpiled C inference function
extern float bootsentry_evaluate_isolation_forest(const float *features);


int main(void) {
    printf("[*] Running BootSentry Freestanding C99 Subsystem Verification...\n");

    // 1. Initialize PCR Bank and Event Log
    PcrBank bank;
    EventLog log;
    bootsentry_pcr_init(&bank);
    memset(&log, 0, sizeof(log));

    uint8_t stage_hash[32];
    memset(stage_hash, 0xAA, 32);
    assert(bootsentry_pcr_extend(&bank, 0, stage_hash) == 0);
    assert(bootsentry_eventlog_record(&log, 0, 0, stage_hash, 1) == 0);
    printf("  [+] PCR[0] extension & EventLog verified\n");

    // 2. Telemetry Ingestion & Feature Extraction
    StageRawTelemetry stages[4];
    memset(stages, 0, sizeof(stages));

    // S0
    stages[0].duration_us = 4200;
    stages[0].cpu_cycles = 12000000;
    stages[0].instructions_retired = 20000000;
    stages[0].l1i_cache_misses = 1500;
    stages[0].branch_mispredicts = 800;

    // S1
    stages[1].duration_us = 12500;
    stages[1].cpu_cycles = 35000000;
    stages[1].instructions_retired = 60000000;
    stages[1].l1i_cache_misses = 4200;
    stages[1].branch_mispredicts = 1800;

    // S2
    stages[2].duration_us = 85000;
    stages[2].cpu_cycles = 250000000;
    stages[2].instructions_retired = 400000000;
    stages[2].l1i_cache_misses = 25000;
    stages[2].branch_mispredicts = 12000;
    stages[2].memory_rss_kb = 32768;
    stages[2].io_bytes_read_kb = 4096;

    // S3
    stages[3].duration_us = 45000;
    stages[3].cpu_cycles = 110000000;
    stages[3].instructions_retired = 180000000;
    stages[3].l1i_cache_misses = 12000;
    stages[3].branch_mispredicts = 5000;
    stages[3].memory_rss_kb = 49152;
    stages[3].ctx_switches_vol = 120;
    stages[3].ctx_switches_invol = 14;

    BootFeatureVector vec;
    assert(bootsentry_extract_features(stages, &vec) == 0);
    assert(vec.feature_version == BOOTSENTRY_FEATURE_VERSION);
    printf("  [+] C99 Feature Extraction verified: 28 continuous process features\n");

    // 3. Transpiled Isolation Forest Decision Trees Inference
    float if_score = bootsentry_evaluate_isolation_forest(vec.features);
    printf("  [+] Transpiled C99 Decision Tree score: %0.4f\n", if_score);
    assert(if_score >= 0.0f && if_score <= 1.0f);


    // 4. Policy Engine Evaluation (Invariant 3 & Gate 1 Determinism)
    // Clean boot -> PASS or WARN
    PolicyDecisionResult clean_dec = bootsentry_evaluate_policy(&vec, 5, true, true);
    assert(clean_dec.verdict == POLICY_VERDICT_PASS || clean_dec.verdict == POLICY_VERDICT_WARN_REDUCED_TRUST);
    printf("  [+] Clean boot policy evaluation verified\n");

    // SVN Rollback (svn < 5) -> HALT
    PolicyDecisionResult svn_rollback_dec = bootsentry_evaluate_policy(&vec, 3, true, true);
    assert(svn_rollback_dec.verdict == POLICY_VERDICT_HALT);
    printf("  [+] SVN rollback produces HALT (Rule Floor)\n");

    // Crypto failure -> HALT (Gate 1 blocking)
    PolicyDecisionResult crypto_fail_dec = bootsentry_evaluate_policy(&vec, 5, false, true);
    assert(crypto_fail_dec.verdict == POLICY_VERDICT_HALT);
    printf("  [+] Gate 1 crypto failure produces HALT (Fail-Closed)\n");

    // PCR failure -> HALT (Gate 2 blocking)
    PolicyDecisionResult pcr_fail_dec = bootsentry_evaluate_policy(&vec, 5, true, false);
    assert(pcr_fail_dec.verdict == POLICY_VERDICT_HALT);
    printf("  [+] Gate 2 PCR failure produces HALT (Fail-Closed)\n");

    printf("[OK] All Freestanding C99 Subsystem tests passed!\n");
    return 0;
}

