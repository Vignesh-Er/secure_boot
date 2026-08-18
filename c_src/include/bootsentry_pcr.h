#ifndef BOOTSENTRY_PCR_H
#define BOOTSENTRY_PCR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BOOTSENTRY_PCR_BANKS_COUNT 4
#define BOOTSENTRY_PCR_DIGEST_SIZE 32
#define BOOTSENTRY_MAX_EVENT_LOG   64

typedef struct {
    uint8_t bank[BOOTSENTRY_PCR_BANKS_COUNT][BOOTSENTRY_PCR_DIGEST_SIZE];
} PcrBank;

typedef struct {
    uint32_t stage_id;
    uint32_t pcr_index;
    uint8_t digest[BOOTSENTRY_PCR_DIGEST_SIZE];
    uint32_t event_type;
    uint64_t timestamp_cycles;
} EventLogEntry;

typedef struct {
    EventLogEntry entries[BOOTSENTRY_MAX_EVENT_LOG];
    size_t count;
} EventLog;

/* Freestanding PCR API */
void bootsentry_pcr_init(PcrBank *bank);
int bootsentry_pcr_extend(PcrBank *bank, uint32_t pcr_index, const uint8_t digest[BOOTSENTRY_PCR_DIGEST_SIZE]);
void bootsentry_pcr_read(const PcrBank *bank, uint32_t pcr_index, uint8_t out[BOOTSENTRY_PCR_DIGEST_SIZE]);
int bootsentry_eventlog_record(EventLog *log, uint32_t stage_id, uint32_t pcr_index, const uint8_t digest[BOOTSENTRY_PCR_DIGEST_SIZE], uint32_t event_type);

#ifdef __cplusplus
}
#endif

#endif /* BOOTSENTRY_PCR_H */
