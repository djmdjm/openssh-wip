/* $OpenBSD:$ */
/*
 * Copyright (c) 2025 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "libcrux_mlkem768_sha3.h"
#include "crypto_api.h"

int
crypto_kem_mlkem768_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned char rnd[LIBCRUX_ML_KEM_KEY_PAIR_PRNG_LEN];
	struct libcrux_mlkem768_keypair keypair;

	arc4random_buf(rnd, sizeof(rnd));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_key_pair(rnd);
	memcpy(pk, keypair.pk.value, crypto_kem_mlkem768_PUBLICKEYBYTES);
	memcpy(sk, keypair.sk.value, crypto_kem_mlkem768_SECRETKEYBYTES);
	explicit_bzero(rnd, sizeof(rnd));
	explicit_bzero(&keypair, sizeof(keypair));
	return 0;
}

int
crypto_kem_mlkem768_enc(unsigned char *c, unsigned char *k,
    const unsigned char *pk)
{
	unsigned char rnd[LIBCRUX_ML_KEM_ENC_PRNG_LEN];
	struct libcrux_mlkem768_enc_result enc;
	struct libcrux_mlkem768_pk mlkem_pub;

	memcpy(mlkem_pub.value, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&mlkem_pub))
		return -1;
	arc4random_buf(rnd, sizeof(rnd));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&mlkem_pub, rnd);
	memcpy(c, enc.fst.value, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	memcpy(k, enc.snd, crypto_kem_mlkem768_BYTES);
	explicit_bzero(&enc, sizeof(enc));
	explicit_bzero(rnd, sizeof(rnd));
	return 0;
}

int
crypto_kem_mlkem768_dec(unsigned char *k, const unsigned char *c,
    const unsigned char *sk)
{
	struct libcrux_mlkem768_ciphertext mlkem_ciphertext;
	struct libcrux_mlkem768_sk mlkem_priv;

	memcpy(mlkem_priv.value, sk, crypto_kem_mlkem768_SECRETKEYBYTES);
	memcpy(mlkem_ciphertext.value, c, crypto_kem_mlkem768_CIPHERTEXTBYTES);
	libcrux_ml_kem_mlkem768_portable_decapsulate(&mlkem_priv,
	   &mlkem_ciphertext, k);
	explicit_bzero(&mlkem_priv, sizeof(mlkem_priv));
	return 0;
}
