/*
 * Copyright (c) 2025 Damien Miller <djm@mindrot.org>
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
#include <stdlib.h>
#include <string.h>

#include "digest.h"
#include "hmac.h"
#include "ssherr.h"
#include "hkdf.h"
#include "log.h" //XXX

#ifdef WITH_OPENSSL

#include <openssl/evp.h>
#include <openssl/hkdf.h>

static const EVP_MD *
hashalg_to_evpmd(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA256:
		return EVP_sha256();
	case SSH_DIGEST_SHA384:
		return EVP_sha384();
	case SSH_DIGEST_SHA512:
		return EVP_sha512();
	}
	return NULL;
}

int
ssh_hkdf_extract(int hash_alg,
    const u_char *salt, size_t salt_len,
    const u_char *ikm, size_t ikm_len,
    u_char *prk, size_t prk_len)
{
	const EVP_MD *md = NULL;
	size_t hash_len;

	if ((hash_len = ssh_digest_bytes(hash_alg)) == 0 ||
	    prk_len != hash_len)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((md = hashalg_to_evpmd(hash_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!HKDF_extract(prk, &hash_len, md, ikm, ikm_len, salt, salt_len))
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

int
ssh_hkdf_expand(int hash_alg,
    const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len,
    u_char *out, size_t out_len)
{
	const EVP_MD *md = NULL;
	size_t hash_len;

	if ((hash_len = ssh_digest_bytes(hash_alg)) == 0 ||
	    prk_len != hash_len)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((md = hashalg_to_evpmd(hash_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!HKDF_expand(out, out_len, md, prk, prk_len, info, info_len))
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

#else /* WITH_OPENSSL */

int
ssh_hkdf_extract(int hash_alg,
    const u_char *salt, size_t salt_len,
    const u_char *ikm, size_t ikm_len,
    u_char *prk, size_t prk_len)
{
	size_t hash_len;
	const u_char zero[SSH_DIGEST_MAX_LENGTH] = { 0 };
	struct ssh_hmac_ctx *ctx = NULL;
	int r;

	if ((hash_len = ssh_digest_bytes(hash_alg)) == 0 ||
	    prk_len != hash_len ||
	    (ctx = ssh_hmac_start(hash_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (salt_len == 0) {
		/* RFC5869 s2.2 */
		salt = zero;
		salt_len = hash_len;
	}
	if ((r = ssh_hmac_init(ctx, salt, salt_len)) != 0 ||
	    (r = ssh_hmac_update(ctx, ikm, ikm_len)) != 0 ||
	    (r = ssh_hmac_final(ctx, prk, prk_len)) != 0) {
		ssh_hmac_free(ctx);
		return r;
	}
	/* success */
	ssh_hmac_free(ctx);
	return 0;
}

int
ssh_hkdf_expand(int hash_alg,
    const u_char *prk, size_t prk_len,
    const u_char *info, size_t info_len,
    u_char *out, size_t out_len)
{
	size_t hash_len, o, l;
	u_char n;
	struct ssh_hmac_ctx *ctx = NULL;
	u_char h[SSH_DIGEST_MAX_LENGTH];
	int r;

	if ((hash_len = ssh_digest_bytes(hash_alg)) == 0 ||
	    prk_len != hash_len || out_len > (255 * hash_len) ||
	    (ctx = ssh_hmac_start(hash_alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = ssh_hmac_init(ctx, prk, prk_len)) != 0) {
		ssh_hmac_free(ctx);
		return r;
	}
	for (o = 0, n = 1; o < out_len; o += hash_len, n++) {
		if ((r = ssh_hmac_init(ctx, NULL, 0)) != 0 ||
		    (n > 1 && (r = ssh_hmac_update(ctx, h, hash_len)) != 0) ||
		    (info_len > 0 &&
		    (r = ssh_hmac_update(ctx, info, info_len)) != 0) ||
		    (r = ssh_hmac_update(ctx, &n, sizeof(n))) != 0 ||
		    (r = ssh_hmac_final(ctx, h, hash_len)) != 0) {
			ssh_hmac_free(ctx);
			return r;
		}
		l = out_len - o;
		memcpy(out + o, h, l > hash_len ? hash_len : l);
	}

	memset(h, 0, sizeof(h));
	ssh_hmac_free(ctx);
	return 0;
}

#endif /* WITH_OPENSSL */

#ifdef TEST_HKDF

#include "sshbuf.h"
#include "log.h"
#include "misc.h"

struct testcase {
	int hash_alg;
	/* all these are hex */
	char *ikm;
	char *salt;
	char *prk;
	char *info;
	char *okm;
};

struct testcase testcases[] = {
	/* A.1.  Test Case 1 */
	{
		.hash_alg = SSH_DIGEST_SHA256,
		.ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		.salt = "000102030405060708090a0b0c",
		.prk = "077709362c2e32df0ddc3f0dc47bba63"
		    "90b6c73bb50f9c3122ec844ad7c2b3e5",
		.info = "f0f1f2f3f4f5f6f7f8f9",
		.okm = "3cb25f25faacd57a90434f64d0362f2a"
		    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
		    "34007208d5b887185865",
	},
	/* A.2.  Test Case 2 */
	{
		.hash_alg = SSH_DIGEST_SHA256,
		.ikm = "000102030405060708090a0b0c0d0e0f"
		    "101112131415161718191a1b1c1d1e1f"
		    "202122232425262728292a2b2c2d2e2f"
		    "303132333435363738393a3b3c3d3e3f"
		    "404142434445464748494a4b4c4d4e4f",
		.salt = "606162636465666768696a6b6c6d6e6f"
		    "707172737475767778797a7b7c7d7e7f"
		    "808182838485868788898a8b8c8d8e8f"
		    "909192939495969798999a9b9c9d9e9f"
		    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		.prk = "06a6b88c5853361a06104c9ceb35b45c"
		    "ef760014904671014a193f40c15fc244",
		.info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
		    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		.okm = "b11e398dc80327a1c8e7f78c596a4934"
		    "4f012eda2d4efad8a050cc4c19afa97c"
		    "59045a99cac7827271cb41c65e590e09"
		    "da3275600c2f09b8367793a9aca3db71"
		    "cc30c58179ec3e87c14c01d5c1f3434f"
		    "1d87",
	},
	/* A.3.  Test Case 3 */
	{
		.hash_alg = SSH_DIGEST_SHA256,
		.ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		.salt = NULL,
		.prk = "19ef24a32c717b167f33a91d6f648bdf"
		    "96596776afdb6377ac434c1c293ccb04",
		.info = NULL,
		.okm = "8da4e775a563c18f715f802a063c5a31"
		    "b8a11f5c5ee1879ec3454e5f3c738d2d"
		    "9d201395faa4b61a96c8",
	},
	{
		-1, NULL, NULL, NULL, NULL, NULL,
	},
};

static struct sshbuf *
fromhex(const char *cp)
{
	struct sshbuf *ret;
	char *tmp;

	if (cp == NULL)
		return NULL;
	if ((ret = sshbuf_b16tod(cp)) == NULL ||
	    (tmp = sshbuf_dtob16(ret)) == NULL)
		fatal("failed to parse testcase %s", cp);
	if (strcmp(cp, tmp) != 0)
		fatal("sshbuf_b16tod is busted");
	free(tmp);
	return ret;
}

static void
eq(size_t i, const char *tag, const u_char *p, size_t l, const struct sshbuf *b)
{
	char *got, *want;

	if (l != sshbuf_len(b)) {
		fatal("case %zu: %s bad len (got %zu / want %zu)", i, tag,
		    l, sshbuf_len(b));
	}
	if (memcmp(p, sshbuf_ptr(b), l) != 0) {
		got = tohex(p, l);
		want = sshbuf_dtob16(b);
		error("case %zu: %s bad data (len %zu)", i, tag, l);
		error("     got: %s", got);
		error("    want: %s", want);
		cleanup_exit(1);
	}
}

int
main(void)
{
	size_t i, hash_len;
	struct sshbuf *ikm, *salt, *prk, *info, *okm;
	struct testcase *tc;
	int r;
	u_char p[SSH_DIGEST_MAX_LENGTH];

        log_init("hkdf_test", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	for (i = 0; testcases[i].hash_alg != -1; i++) {
		ikm = salt = prk = info = okm = NULL;
		memset(p, 0, sizeof(p));
		tc = testcases + i;

		if ((hash_len = ssh_digest_bytes(tc->hash_alg)) == 0)
			fatal("case %zu: bad hash", i);
		ikm = fromhex(tc->ikm);
		salt = fromhex(tc->salt);
		prk = fromhex(tc->prk);
		info = fromhex(tc->info);
		okm = fromhex(tc->okm);

		if ((r = ssh_hkdf_extract(tc->hash_alg,
		    salt == NULL ? NULL : sshbuf_ptr(salt),
		    salt == NULL ? 0 : sshbuf_len(salt),
		    sshbuf_ptr(ikm), sshbuf_len(ikm),
		    p, hash_len)) != 0)
			fatal("case %zu: extract failed", i);

		eq(i, "prk", p, hash_len, prk);

		sshbuf_free(ikm);
		sshbuf_free(salt);
		sshbuf_free(prk);
		sshbuf_free(info);
		sshbuf_free(okm);
	}
	return 0;
}

#endif
