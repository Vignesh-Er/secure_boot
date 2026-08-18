#include "bootsentry_telemetry.h"
#include <string.h>

int bootsentry_extract_features(const StageRawTelemetry stages[BOOTSENTRY_MAX_STAGES], BootFeatureVector* out_vector) {
    if (!stages || !out_vector) {
        return -1;
    }

    memset(out_vector, 0, sizeof(BootFeatureVector));
    out_vector->feature_version = BOOTSENTRY_FEATURE_VERSION;

    /* Compute total execution duration */
    uint64_t total_duration = 0;
    for (int i = 0; i < BOOTSENTRY_MAX_STAGES; i++) {
        total_duration += stages[i].duration_us;
    }
    if (total_duration == 0) total_duration = 1;

    /* 1-4: Stage execution durations in milliseconds */
    out_vector->features[0] = (float)stages[0].duration_us / 1000.0f;
    out_vector->features[1] = (float)stages[1].duration_us / 1000.0f;
    out_vector->features[2] = (float)stages[2].duration_us / 1000.0f;
    out_vector->features[3] = (float)stages[3].duration_us / 1000.0f;

    /* 5-8: Stage duration ratios (clock-scaling invariant) */
    out_vector->features[4] = (float)stages[0].duration_us / (float)total_duration;
    out_vector->features[5] = (float)stages[1].duration_us / (float)total_duration;
    out_vector->features[6] = (float)stages[2].duration_us / (float)total_duration;
    out_vector->features[7] = (float)stages[3].duration_us / (float)total_duration;

    /* 9-12: Peak resident memory (RSS in MB) */
    out_vector->features[8] = (float)stages[0].memory_rss_kb / 1024.0f;
    out_vector->features[9] = (float)stages[1].memory_rss_kb / 1024.0f;
    out_vector->features[10] = (float)stages[2].memory_rss_kb / 1024.0f;
    out_vector->features[11] = (float)stages[3].memory_rss_kb / 1024.0f;

    /* 13-14: Context switches */
    out_vector->features[12] = (float)stages[3].ctx_switches_vol;
    out_vector->features[13] = (float)stages[3].ctx_switches_invol;

    /* 15-16: Storage I/O read/write */
    out_vector->features[14] = (float)stages[3].io_bytes_read_kb;
    out_vector->features[15] = (float)stages[3].io_bytes_written_kb;

    /* 17: I/O Read-Write ratio */
    float io_write = (float)stages[3].io_bytes_written_kb;
    out_vector->features[16] = (float)stages[3].io_bytes_read_kb / (io_write > 0.0f ? io_write : 1.0f);

    /* 18-21: Hardware PMU Instruction Retired counts */
    out_vector->features[17] = (float)stages[0].instructions_retired;
    out_vector->features[18] = (float)stages[1].instructions_retired;
    out_vector->features[19] = (float)stages[2].instructions_retired;
    out_vector->features[20] = (float)stages[3].instructions_retired;

    /* 22-25: PMU Cache Misses & Branch Mispredicts */
    out_vector->features[21] = (float)stages[1].l1i_cache_misses;
    out_vector->features[22] = (float)stages[2].l1i_cache_misses;
    out_vector->features[23] = (float)stages[1].branch_mispredicts;
    out_vector->features[24] = (float)stages[2].branch_mispredicts;

    /* 26-28: Core CPU Cycle Ratios */
    uint64_t total_cycles = stages[0].cpu_cycles + stages[1].cpu_cycles + stages[2].cpu_cycles + stages[3].cpu_cycles;
    if (total_cycles == 0) total_cycles = 1;
    out_vector->features[25] = (float)stages[0].cpu_cycles / (float)total_cycles;
    out_vector->features[26] = (float)stages[1].cpu_cycles / (float)total_cycles;
    out_vector->features[27] = (float)stages[2].cpu_cycles / (float)total_cycles;

    return 0;
}
