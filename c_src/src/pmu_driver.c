#include "bootsentry_telemetry.h"
#include <string.h>
#include <time.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <intrin.h>
static inline uint64_t read_cpu_cycles(void) {
    return __rdtsc();
}
#elif defined(__aarch64__)
static inline uint64_t read_cpu_cycles(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, pmccntr_el0" : "=r"(val));
    return val;
}
#else
static inline uint64_t read_cpu_cycles(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

int bootsentry_pmu_init(void) {
    /* Initialize PMU user-space cycle access or verify register accessibility */
    return 0;
}

int bootsentry_capture_stage_telemetry(BootStageId stage, StageRawTelemetry* out_telemetry) {
    if (!out_telemetry) {
        return -1;
    }

    memset(out_telemetry, 0, sizeof(StageRawTelemetry));
    out_telemetry->cpu_cycles = read_cpu_cycles();

    /* Simulated baseline hardware PMU registers based on stage execution context */
    switch (stage) {
        case BOOT_STAGE_S0_BOOTROM:
            out_telemetry->instructions_retired = 150000;
            out_telemetry->l1i_cache_misses = 240;
            out_telemetry->branch_mispredicts = 85;
            out_telemetry->duration_us = 21085;
            out_telemetry->memory_rss_kb = 45000;
            break;
        case BOOT_STAGE_S1_BOOTLOADER:
            out_telemetry->instructions_retired = 180000;
            out_telemetry->l1i_cache_misses = 520;
            out_telemetry->branch_mispredicts = 140;
            out_telemetry->duration_us = 21153;
            out_telemetry->memory_rss_kb = 65000;
            break;
        case BOOT_STAGE_S2_KERNEL:
            out_telemetry->instructions_retired = 350000;
            out_telemetry->l1i_cache_misses = 1850;
            out_telemetry->branch_mispredicts = 480;
            out_telemetry->duration_us = 21034;
            out_telemetry->memory_rss_kb = 120000;
            break;
        case BOOT_STAGE_S3_INIT:
            out_telemetry->instructions_retired = 420000;
            out_telemetry->l1i_cache_misses = 2400;
            out_telemetry->branch_mispredicts = 620;
            out_telemetry->duration_us = 25400;
            out_telemetry->memory_rss_kb = 180000;
            out_telemetry->ctx_switches_vol = 12;
            out_telemetry->ctx_switches_invol = 0;
            out_telemetry->io_bytes_read_kb = 32;
            out_telemetry->io_bytes_written_kb = 32;
            break;
    }

    return 0;
}
