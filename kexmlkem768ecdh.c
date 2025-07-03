/* $OpenBSD: kexmlkem768ecdh.c,v */
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

int
kex_kem_mlkem768ecdh_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	struct sshbuf *ec_blob = NULL;
	EC_KEY *client_key = NULL;
	const EC_GROUP *group;
	const EC_POINT *public_key;
	u_char *cp = NULL;
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((client_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_generate_key(client_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(client_key);
	public_key = EC_KEY_get0_public_key(client_key);

	need = crypto_kem_mlkem768_PUBLICKEYBYTES;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_key);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    crypto_kem_mlkem768_PUBLICKEYBYTES);
#endif
	if ((ec_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_ec(ec_blob, public_key, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, NULL)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	/* success */
	r = 0;
	kex->ec_client_key = client_key;
	kex->ec_group = group;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_KEY_free(client_key);
	return r;
}

int
kex_kem_mlkem768ecdh_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	const EC_GROUP *group;
	const EC_POINT *pub_key;
	EC_KEY *server_key = NULL;
	struct sshbuf *ec_pub = NULL;
	struct sshbuf *ec_blob = NULL;
	struct sshbuf *ec_shared = NULL;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char *kem_key, *ciphertext;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_mlkem768_PUBLICKEYBYTES;
	if (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    crypto_kem_mlkem768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, crypto_kem_mlkem768_BYTES,
	    &kem_key)) != 0)
		goto out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	need = crypto_kem_mlkem768_CIPHERTEXTBYTES;
	if ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		goto out;
	/* generate and encrypt KEM key with client key */
	if (crypto_kem_mlkem768_enc(ciphertext, kem_key, client_pub) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	client_pub += crypto_kem_mlkem768_PUBLICKEYBYTES;
	if ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    crypto_kem_mlkem768_PUBLICKEYBYTES)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* generate ECDH key pair */
	if ((server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_generate_key(server_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(server_key);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	/* store server pubkey after ciphertext */
	pub_key = EC_KEY_get0_public_key(server_key);
	if ((ec_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_ec(ec_blob, pub_key, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, NULL)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		goto out;

	/* append ECDH shared key */
	if ((r = kex_ecdh_dec_key_group(kex, ec_pub, server_key, group,
	    &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		goto out;

	if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (enc):", ciphertext,
	    crypto_kem_mlkem768_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_key, crypto_kem_mlkem768_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(server_key, sizeof(server_key));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	return r;
}

int
kex_kem_mlkem768ecdh_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	struct sshbuf *ec_pub = NULL;
	struct sshbuf *ec_shared = NULL;
	u_char *kem_key = NULL;
	const u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int decoded;
	int r = SSH_ERR_INTERNAL_ERROR;

	*shared_secretp = NULL;

	need = crypto_kem_mlkem768_CIPHERTEXTBYTES;
	if (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_mlkem768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    crypto_kem_mlkem768_CIPHERTEXTBYTES);
#endif
	if ((r = sshbuf_reserve(buf, crypto_kem_mlkem768_BYTES,
	    &kem_key)) != 0)
		goto out;
	decoded = crypto_kem_mlkem768_dec(kem_key, ciphertext,
	    kex->mlkem768_client_key);
	if ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kex_ecdh_dec(kex, ec_pub, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_key, crypto_kem_mlkem768_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	if (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	return r;
}
