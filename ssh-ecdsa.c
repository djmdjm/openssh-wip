/* $OpenBSD: ssh-ecdsa.c,v 1.26 2023/03/08 04:43:12 guenther Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

static u_int
ssh_ecdsa_size(const struct sshkey *key)
{
	switch (key->ecdsa_nid) {
	case NID_X9_62_prime256v1:
		return 256;
	case NID_secp384r1:
		return 384;
	case NID_secp521r1:
		return 521;
	default:
		return 0;
	}
}

static void
ssh_ecdsa_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static int
ssh_ecdsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (EVP_PKEY_cmp(a->pkey, b->pkey) == 1)
		return 1;

	return 0;
}

static int
ssh_ecdsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec(b, key->pkey)) != 0)
		return r;

	return 0;
}

static int
ssh_ecdsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_ecdsa_serialize_public(key, b, opts)) != 0)
			return r;
	}
	if ((r = sshbuf_put_bignum2(b,
	    EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(key->pkey)))) != 0)
		return r;
	return 0;
}

static int
ssh_ecdsa_generate(struct sshkey *k, int bits)
{
	EVP_PKEY *res = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	if ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		return SSH_ERR_KEY_LENGTH;

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(res);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	k->pkey = res;
	return 0;
}

static int
ssh_ecdsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const EC_KEY *ec_from;
	EC_KEY *ec_to = NULL;

	ec_from = EVP_PKEY_get0_EC_KEY(from->pkey);
	if (ec_from == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	if ((ec_to = EC_KEY_new_by_curve_name(from->ecdsa_nid)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (EC_KEY_set_public_key(ec_to,
	    EC_KEY_get0_public_key(ec_from)) != 1) {
		EC_KEY_free(ec_to);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	EVP_PKEY_free(to->pkey);
	to->pkey = NULL;
	if ((to->pkey = EVP_PKEY_new()) == NULL) {
		EC_KEY_free(ec_to);
		return SSH_ERR_ALLOC_FAIL;
	}
	if (EVP_PKEY_set1_EC_KEY(to->pkey, ec_to) != 1) {
		EC_KEY_free(ec_to);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	EC_KEY_free(ec_to);
	return 0;
}

static int
ssh_ecdsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	char *curve = NULL;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec = NULL;

	if ((key->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_get_cstring(b, &curve, NULL)) != 0)
		goto out;
	if (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}

	if ((ec = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshbuf_get_eckey(b, ec)) != 0)
		goto out;
	if (sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec)) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}

	if ((pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key->pkey)),
	    EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(key->pkey)));
#endif
 out:
	EC_KEY_free(ec);
	free(curve);
	if (r != 0) {
		EVP_PKEY_free(key->pkey);
		key->pkey = NULL;
	}
	return r;
}

static int
ssh_ecdsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	BIGNUM *exponent = NULL;
	EC_KEY *ec = NULL;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_ecdsa_deserialize_public(ktype, b, key)) != 0)
			return r;
	}
	if ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		goto out;
	if ((ec = EVP_PKEY_get1_EC_KEY(key->pkey)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshkey_ec_validate_private(ec)) != 0)
		goto out;
	if (EVP_PKEY_set1_EC_KEY(key->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	return r;
}

static int
ssh_ecdsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = NULL;
	unsigned char *sigb = NULL;
	const unsigned char *psig;
	const BIGNUM *sig_r, *sig_s;
	int hash_alg;
	int len;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		return SSH_ERR_INTERNAL_ERROR;

	if ((ret = sshkey_pkey_sign_internal(key->pkey, hash_alg, &sigb, &len,
	    data, dlen)) != 0)
		goto out;

	psig = sigb;
	if (d2i_ECDSA_SIG(&esig, &psig, len) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);
	if ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	free(sigb);
	sshbuf_free(b);
	sshbuf_free(bb);
	ECDSA_SIG_free(esig);
	return ret;
}

static int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	int hash_alg, len;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	unsigned char *sigb = NULL, *psig = NULL;

	if (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	if (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((esig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	/* Figure out the length */
	if ((len = i2d_ECDSA_SIG(esig, NULL)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((sigb = malloc(len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	psig = sigb;
	if ((len = i2d_ECDSA_SIG(esig, &psig)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if ((ret = sshkey_pkey_verify_internal(key->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		goto out;
	/* success */
 out:
	free(sigb);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	free(ktype);
	return ret;
}

/* NB. not static; used by ECDSA-SK */
const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_public,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};
