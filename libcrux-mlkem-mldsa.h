/* $OpenBSD$ */
/*
 * Placed in the Public Domain.
 */

#ifndef LIBCRUX_MLKEM_MLDSA_H
#define LIBCRUX_MLKEM_MLDSA_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_api.h"

/* ML-KEM 768 */

int mlkem768_keypair(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);
int mlkem768_keypair_seeded(uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES], const uint8_t seed[64]);
int mlkem768_encapsulate(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    const uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES]);
int mlkem768_encapsulate_seeded(uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    const uint8_t pk[crypto_kem_mlkem768_PUBLICKEYBYTES],
    const uint8_t seed[32]);
int mlkem768_decapsulate(uint8_t shared_secret[crypto_kem_mlkem768_BYTES],
    const uint8_t ct[crypto_kem_mlkem768_CIPHERTEXTBYTES],
    const uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES]);

/* ML-DSA 65 */

int mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);
int mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], const uint8_t seed[32]);
int mldsa65_sign(uint8_t sig[MLDSA65_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA65_SECRETKEYBYTES]);
int mldsa65_sign_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA65_SECRETKEYBYTES], const uint8_t seed[32]);
int mldsa65_verify(const uint8_t sig[MLDSA65_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA65_PUBLICKEYBYTES]);

/* Utility */
void sha3_256(uint8_t digest[32], const uint8_t *data, size_t len);
void sha3_512(uint8_t digest[64], const uint8_t *data, size_t len);

#endif /* LIBCRUX_MLKEM_MLDSA_H */
