#ifndef BOOTSENTRY_CRYPTO_H
#define BOOTSENTRY_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ML_DSA_65_PUBLICKEYBYTES 1952
#define ML_DSA_65_SECRETKEYBYTES 4032
#define ML_DSA_65_BYTES          3293
#define SHA256_DIGEST_LENGTH     32

typedef struct {
    uint8_t public_key[ML_DSA_65_PUBLICKEYBYTES];
    uint8_t signature[ML_DSA_65_BYTES];
    uint8_t payload_sha256[SHA256_DIGEST_LENGTH];
    uint32_t payload_size;
    uint32_t security_version;
    char stage_id[8];
} ManifestMetadata;

/* NIST FIPS 204 Freestanding Verification Prototype */
int bootsentry_mldsa65_verify(
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *pk
);

int bootsentry_sha256(
    const uint8_t *data,
    size_t len,
    uint8_t out[SHA256_DIGEST_LENGTH]
);

#ifdef __cplusplus
}
#endif

#endif /* BOOTSENTRY_CRYPTO_H */
