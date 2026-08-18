#ifndef BOOTSENTRY_TELEMETRY_H
#define BOOTSENTRY_TELEMETRY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BOOTSENTRY_FEATURE_VERSION 2
#define BOOTSENTRY_NUM_FEATURES    28
#define BOOTSENTRY_MAX_STAGES      4

typedef enum {
    BOOT_STAGE_S0_BOOTROM = 0,
    BOOT_STAGE_S1_BOOTLOADER = 1,
    BOOT_STAGE_S2_KERNEL = 2,
    BOOT_STAGE_S3_INIT = 3
} BootStageId;

typedef struct {
    uint64_t cpu_cycles;            /* Monotonic hardware core cycles */
    uint64_t instructions_retired;  /* PMU Event: 0x08 INST_RETIRED */
    uint64_t l1i_cache_misses;      /* PMU Event: 0x01 L1I_CACHE_REFILL */
    uint64_t branch_mispredicts;    /* PMU Event: 0x10 BR_MIS_PRED */
    uint64_t duration_us;           /* Stage execution wall-clock time in microseconds */
    uint32_t memory_rss_kb;         /* Resident memory size in KB (S2/S3 only) */
    uint32_t ctx_switches_vol;      /* Voluntary context switches (S3 only) */
    uint32_t ctx_switches_invol;    /* Involuntary context switches (S3 only) */
    uint32_t io_bytes_read_kb;      /* Storage I/O read bytes (S2/S3 only) */
    uint32_t io_bytes_written_kb;   /* Storage I/O write bytes (S2/S3 only) */
} __attribute__((packed)) StageRawTelemetry;

typedef struct {
    uint32_t feature_version;
    uint32_t boot_id_hash;
    float features[BOOTSENTRY_NUM_FEATURES];
} __attribute__((packed)) BootFeatureVector;

typedef enum {
    POLICY_VERDICT_PASS = 0,
    POLICY_VERDICT_WARN_REDUCED_TRUST = 1,
    POLICY_VERDICT_HALT = 2
} PolicyVerdict;

typedef struct {
    PolicyVerdict verdict;
    float composite_risk_score;
    float isolation_forest_score;
    float markov_nll_score;
    float ewma_drift_score;
    uint32_t rules_triggered_bitmap;
    char primary_attribution_feature[32];
    float primary_attribution_z;
} PolicyDecisionResult;

/* Function Declarations */
int bootsentry_pmu_init(void);
int bootsentry_capture_stage_telemetry(BootStageId stage, StageRawTelemetry* out_telemetry);
int bootsentry_extract_features(const StageRawTelemetry stages[BOOTSENTRY_MAX_STAGES], BootFeatureVector* out_vector);
PolicyDecisionResult bootsentry_evaluate_policy(const BootFeatureVector* vector, uint32_t svn, bool crypto_pass, bool pcr_pass);

#ifdef __cplusplus
}
#endif

#endif /* BOOTSENTRY_TELEMETRY_H */
