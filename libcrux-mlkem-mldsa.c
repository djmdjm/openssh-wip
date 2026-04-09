/* $OpenBSD$ */
/*
 * Copyright (c) 2026 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "libcrux-mlkem-mldsa.h"
#include "libcrux_internal.h"

int
mlkem768_keypair(uint8_t pk[MLKEM768_PUBLICKEYBYTES],
    uint8_t sk[MLKEM768_SECRETKEYBYTES])
{
	uint8_t rnd[64];
	int r;

	arc4random_buf(rnd, sizeof(rnd));
	r = mlkem768_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, sizeof(rnd));
	return r;
}

int
mlkem768_keypair_seeded(uint8_t pk[MLKEM768_PUBLICKEYBYTES],
    uint8_t sk[MLKEM768_SECRETKEYBYTES], const uint8_t seed[64])
{
	Eurydice_arr_060 rnd;
	libcrux_mlkem768_keypair keypair;

	memcpy(rnd.data, seed, 64);
	keypair = libcrux_ml_kem_mlkem768_portable_generate_key_pair(rnd);
	memcpy(pk, keypair.pk.data, MLKEM768_PUBLICKEYBYTES);
	memcpy(sk, keypair.sk.data, MLKEM768_SECRETKEYBYTES);

	explicit_bzero(&keypair, sizeof(keypair));
	return 0;
}

int
mlkem768_encapsulate(uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
    uint8_t shared_secret[MLKEM768_BYTES],
    const uint8_t pk[MLKEM768_PUBLICKEYBYTES])
{
	uint8_t rnd[32];
	int r;

	arc4random_buf(rnd, sizeof(rnd));
	r = mlkem768_encapsulate_seeded(ct, shared_secret, pk, rnd);
	explicit_bzero(rnd, sizeof(rnd));
	return r;
}

int
mlkem768_encapsulate_seeded(uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
    uint8_t shared_secret[MLKEM768_BYTES],
    const uint8_t pk[MLKEM768_PUBLICKEYBYTES], const uint8_t seed[32])
{
	Eurydice_arr_600 rnd;
	libcrux_mlkem768_enc_result enc;
	Eurydice_arr_74 pk_internal;

	memcpy(pk_internal.data, pk, MLKEM768_PUBLICKEYBYTES);
	if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&pk_internal))
		return -1;
	memcpy(rnd.data, seed, 32);
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&pk_internal, rnd);
	memcpy(ct, enc.fst.data, MLKEM768_CIPHERTEXTBYTES);
	memcpy(shared_secret, enc.snd.data, MLKEM768_BYTES);

	explicit_bzero(&enc, sizeof(enc));
	return 0;
}

int
mlkem768_decapsulate(uint8_t shared_secret[MLKEM768_BYTES],
    const uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
    const uint8_t sk[MLKEM768_SECRETKEYBYTES])
{
	Eurydice_arr_ea sk_internal;
	Eurydice_arr_2c ct_internal;
	Eurydice_arr_600 shared_secret_internal;

	memcpy(sk_internal.data, sk, MLKEM768_SECRETKEYBYTES);
	memcpy(ct_internal.data, ct, MLKEM768_CIPHERTEXTBYTES);
	shared_secret_internal = libcrux_ml_kem_mlkem768_portable_decapsulate(
	    &sk_internal, &ct_internal);
	memcpy(shared_secret, shared_secret_internal.data, MLKEM768_BYTES);

	explicit_bzero(&sk_internal, sizeof(sk_internal));
	explicit_bzero(&shared_secret_internal, sizeof(shared_secret_internal));
	return 0;
}

int
mldsa65_keypair(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[32];
	int r;

	arc4random_buf(rnd, sizeof(rnd));
	r = mldsa65_keypair_seeded(pk, sk, rnd);
	explicit_bzero(rnd, sizeof(rnd));
	return r;
}

int
mldsa65_keypair_seeded(uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES], const uint8_t seed[32])
{
	Eurydice_arr_600 rnd;
	libcrux_ml_dsa_types_MLDSAKeyPair_06 keypair;

	memcpy(rnd.data, seed, 32);
	keypair = libcrux_ml_dsa_ml_dsa_65_portable_generate_key_pair(rnd);
	memcpy(pk, keypair.verification_key.data, MLDSA65_PUBLICKEYBYTES);
	memcpy(sk, keypair.signing_key.data, MLDSA65_SECRETKEYBYTES);

	explicit_bzero(&keypair, sizeof(keypair));
	return 0;
}

int
mldsa65_sign(uint8_t sig[MLDSA65_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA65_SECRETKEYBYTES])
{
	uint8_t rnd[32];
	int r;

	arc4random_buf(rnd, sizeof(rnd));
	r = mldsa65_sign_seeded(sig, msg, msglen, ctx, ctxlen, sk, rnd);
	explicit_bzero(rnd, sizeof(rnd));
	return r;
}

int
mldsa65_sign_seeded(uint8_t sig[MLDSA65_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA65_SECRETKEYBYTES], const uint8_t seed[32])
{
	Eurydice_arr_600 rnd;
	Eurydice_arr_d10 sk_internal;
	Eurydice_borrow_slice_u8 message = { msg, msglen };
	Eurydice_borrow_slice_u8 context = { ctx, ctxlen };
	Result_97 res;
	int r = -1;

	memcpy(sk_internal.data, sk, MLDSA65_SECRETKEYBYTES);
	memcpy(rnd.data, seed, 32);
	res = libcrux_ml_dsa_ml_dsa_65_portable_sign(&sk_internal,
	    message, context, rnd);
	if (res.tag == Ok) {
		memcpy(sig, res.val.case_Ok.data, MLDSA65_SIGBYTES);
		r = 0;
	}

	explicit_bzero(&sk_internal, sizeof(sk_internal));
	explicit_bzero(&res, sizeof(res));
	return r;
}

int
mldsa65_verify(const uint8_t sig[MLDSA65_SIGBYTES],
    const uint8_t *msg, size_t msglen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA65_PUBLICKEYBYTES])
{
	Eurydice_arr_4a pk_internal;
	Eurydice_arr_96 sig_internal;
	Eurydice_borrow_slice_u8 message = { msg, msglen };
	Eurydice_borrow_slice_u8 context = { ctx, ctxlen };
	Result_41 res;

	memcpy(pk_internal.data, pk, MLDSA65_PUBLICKEYBYTES);
	memcpy(sig_internal.data, sig, MLDSA65_SIGBYTES);
	res = libcrux_ml_dsa_ml_dsa_65_portable_verify(&pk_internal,
	    message, context, &sig_internal);

	return (res.tag == Ok) ? 0 : -1;
}

void
sha3_256(uint8_t digest[32], const uint8_t *data, size_t len)
{
	Eurydice_borrow_slice_u8 input = { data, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 32 };
	libcrux_sha3_portable_sha256(output, input);
}

void
sha3_512(uint8_t digest[64], const uint8_t *data, size_t len)
{
	Eurydice_borrow_slice_u8 input = { data, len };
	Eurydice_mut_borrow_slice_u8 output = { digest, 64 };
	libcrux_sha3_portable_sha512(output, input);
}
