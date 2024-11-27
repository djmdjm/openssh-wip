/* $OpenBSD$ */
/*
 * Copyright (c) 2022 Damien Miller <djm@mindrot.org>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "bloom.h"
#include "bitmap.h"
#include "digest.h"
#include "err.h"
#include "log.h"
#include "sshbuf.h"

#ifdef __has_builtin
# if __has_builtin(__builtin_clz)
#  define use_builtin_clz
# endif
#endif

struct sshbloom {
	u_char seed[32];	/* random hash seed */
	u_int m;		/* bitmap size in bits */
	u_int k;		/* number of hash functions */
	struct bitmap *bits;
};

/* Returns the number of leading 0 digits in the binary representation of 'x' */
static u_int
clz(u_int x)
{
#ifdef use_builtin_clz
	if (x == 0)
		return 32;
	return (u_int)(__builtin_clz(x));
#else
	u_int n, ret = 0;
	const u_int lut[16] = {
		4, 3, 2, 2, 1, 1, 1, 1,
		0, 0, 0, 0, 0, 0, 0, 0,
	};

	while (x != 0) {
		n = (x >> 28) & 0xf;
		if (n != 0)
			return (u_int)(ret + lut[n]);
		x <<= 4;
		ret += 4;
	}
	return 32;
#endif
}

/* round 'x' up to the next power of 2; returns 0 if out of range */
static u_int
roundup_pow2(u_int x)
{
	u_int nbits;

	nbits = clz(x);
	if (nbits == 0 || nbits == 32)
		return 0;
	nbits = 31 - nbits;
	if (x > 1 << nbits)
		nbits++;
	return 1 << nbits;
}

static int
calculate_bloom_mk(u_int nmemb, u_int fp_rate, u_int *mp, u_int *kp)
{
	u_int k, m, tmp;

	if (mp != NULL)
		*mp = 0;
	if (kp != NULL)
		*kp = 0;
	if (fp_rate <= 2 || nmemb <= 2)
		return SSH_ERR_INVALID_ARGUMENT;
	/* wikipedia.org/wiki/Bloom_filter#Optimal_number_of_hash_functions */
	/* optimal k = log2(fp_rate) */
	k = 32 - clz(fp_rate);
	/*
	 * optimal m = n * 1.44 * k, but we round up to the nearest 2^n
	 * to avoid modulo bias when hashing later.
	 */
	if (k == 0 || nmemb > UINT_MAX/(k * 2))
		return SSH_ERR_INVALID_ARGUMENT;
	tmp = nmemb * k;
	tmp += (tmp * 4)/10 + (tmp * 4)/100; /* * 1.44 */
	m = roundup_pow2(tmp);
	if (m == 0 || m > BITMAP_MAXBITS || ((m / 8) + 128 > SSHBUF_SIZE_MAX))
		return SSH_ERR_INVALID_ARGUMENT; /* bad k or bitmap too big */
	if (mp != NULL)
		*mp = m;
	if (kp != NULL)
		*kp = k;
	return 0;
}

int
sshbloom_can_alloc(u_int nmemb, u_int fp_rate)
{
	return calculate_bloom_mk(nmemb, fp_rate, NULL, NULL);
}

/*
 * Prepare a bloom filter to hold nmemb expected elements with false positive
 * probability approximately 1/fp_rate
 */
struct sshbloom *
sshbloom_new(u_int nmemb, u_int fp_rate)
{
	struct sshbloom *ret;
	u_int k, m;

	if (calculate_bloom_mk(nmemb, fp_rate, &m, &k) != 0)
		return NULL;
	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->bits = bitmap_new()) == NULL) {
		free(ret);
		return NULL;
	}
	ret->m = m;
	ret->k = k;
	arc4random_buf(ret->seed, sizeof(ret->seed));
	debug2_f("nmemb = %u, fp = %u, k = %u, m = %u",
	    nmemb, fp_rate, ret->k, ret->m);
	return ret;
}

void
sshbloom_free(struct sshbloom *b)
{
	if (b == NULL)
		return;
	bitmap_free(b->bits);
	freezero(b, sizeof(*b));
}

void
sshbloom_dump(const struct sshbloom *b)
{
	u_int i;

	fprintf(stderr, "bloom filter size %u nhashes %u\n", b->m, b->k);
	for (i = 0; i < b->m ; i++) {
		if ((i % 64) == 0)
			fprintf(stderr, "%08x ", i);
		fputc(bitmap_test_bit(b->bits, i) ? 'X' : '.', stderr);
		if (i && (i == b->m - 1 || (i % 64) == 63))
			fputc('\n', stderr);
	}
}

/*
 * Bloom filter hash. Returns b->k * hash values via h[]. Hash values
 * are already reduced modulo b->m.
 * Hashes are SHA256(key || ctr || data) taken as 8 * u32 words.
 * "ctr" increments for each 8 words.
 */
static int
gethashes(const struct sshbloom *b, const void *ptr, size_t len,
    u_int *h, u_int nh)
{
	struct ssh_digest_ctx *ctx = NULL;
	u_char ib[4], hash[32];
	u_int i, j;

	if (nh < b->k)
		return -1;
	for (i = 0; i < b->k; i += 8) {
		POKE_U32(ib, i/8);
		if ((ctx = ssh_digest_start(SSH_DIGEST_SHA256)) == NULL)
			return -1;
		if (ssh_digest_update(ctx, b->seed, sizeof(b->seed)) != 0 ||
		    ssh_digest_update(ctx, ib, sizeof(ib)) != 0 ||
		    ssh_digest_update(ctx, ptr, len) != 0 ||
		    ssh_digest_final(ctx, hash, sizeof(hash)) != 0) {
			ssh_digest_free(ctx);
			return -1;
		}
		ssh_digest_free(ctx);
		for (j = 0; j < 8; j++) {
			if (i + j >= b->k)
				return 0;
			h[i+j] = PEEK_U32(hash + (j * 4)) % b->m;
		}
	}
	return 0;
}

int
sshbloom_add_ptr(struct sshbloom *b, const void *ptr, size_t len)
{
	u_int i, h[32];

	if (gethashes(b, ptr, len, h, sizeof(h)/sizeof(*h)) != 0)
		return -1;
	for (i = 0; i < b->k; i++) {
		if (bitmap_set_bit(b->bits, h[i]) != 0)
			return -1;
	}
	return 0;
}

int
sshbloom_add_u64(struct sshbloom *b, uint64_t x)
{
	u_char v[8];

	POKE_U64(v, x);
	return sshbloom_add_ptr(b, v, sizeof(v));
}

int
sshbloom_add_cstring(struct sshbloom *b, const char *s)
{
	return sshbloom_add_ptr(b, s, s == NULL ? 0 : strlen(s));
}

int
sshbloom_test_ptr(const struct sshbloom *b, const void *ptr, size_t len,
    int *found)
{
	u_int i, h[32];

	*found = 0;
	if (gethashes(b, ptr, len, h, sizeof(h)) != 0)
		return -1;
	for (i = 0; i < b->k; i++) {
		/* NB. not trying to be constant time here */
		if (!bitmap_test_bit(b->bits, h[i]))
			return 0;
	}
	*found = 1;
	return 0;
}

int
sshbloom_test_u64(const struct sshbloom *b, uint64_t x, int *found)
{
	u_char v[8];

	POKE_U64(v, x);
	return sshbloom_test_ptr(b, v, sizeof(v), found);
}

int
sshbloom_test_cstring(const struct sshbloom *b, const char *s, int *found)
{
	return sshbloom_test_ptr(b, s, s == NULL ? 0 : strlen(s), found);
}

int
sshbloom_serialize(const struct sshbloom *b, struct sshbuf *m)
{
	int r;
	u_char *bitmap = NULL;
	size_t bitmap_len;

	bitmap_len = bitmap_nbytes(b->bits);
	if (bitmap_len != 0 && (bitmap = calloc(1, bitmap_len)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (bitmap_to_string(b->bits, bitmap, bitmap_len) != 0) {
		free(bitmap);
		return SSH_ERR_INTERNAL_ERROR;
	}
	if ((r = sshbuf_put_u32(m, b->m)) != 0 ||
	    (r = sshbuf_put_u32(m, b->k)) != 0 ||
	    (r = sshbuf_put_cstring(m, "sha256-ctr")) != 0 || /* hash alg */
	    (r = sshbuf_put_string(m, b->seed, sizeof(b->seed))) != 0 ||
	    (r = sshbuf_put_string(m, bitmap, bitmap_len)) != 0) {
		error_fr(r, "format");
		freezero(bitmap, bitmap_len);
		return r;
	}
	/* success */
	freezero(bitmap, bitmap_len);
	return 0;
}

int
sshbloom_deserialize(struct sshbuf *m, struct sshbloom **bp)
{
	struct sshbloom *b;
	char *hashalg = NULL;
	u_char *seed = NULL;
	const u_char *bitmap = NULL;
	size_t seedlen = 0, bitmaplen = 0;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((b = calloc(1, sizeof(*b))) == NULL ||
	    (b->bits = bitmap_new()) == NULL) {
		error_f("alloc bloom filter failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_u32(m, &b->m)) != 0 ||
	    (r = sshbuf_get_u32(m, &b->k)) != 0 ||
	    (r = sshbuf_get_cstring(m, &hashalg, NULL)) != 0 ||
	    (r = sshbuf_get_string(m, &seed, &seedlen)) != 0 ||
	    (r = sshbuf_get_string_direct(m, &bitmap, &bitmaplen)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if (strcmp(hashalg, "sha256-ctr") != 0) {
		error_f("unsupported hash algorithm \"%s\"", hashalg);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	if (b->k == 0 || b->k > 32 || b->m == 0 ||
	    (b->m & (b->m - 1)) != 0 || /* m must be 2^n */
	    seedlen != sizeof(b->seed)) {
		error_f("invalid parameters");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (bitmap_from_string(b->bits, bitmap, bitmaplen) != 0) {
		error_f("alloc bitmap failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (bitmap_nbits(b->bits) > b->m) {
		error_f("inconsistent bitmap size");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	memcpy(b->seed, seed, sizeof(b->seed));
	/* success */
	debug2_f("k = %u, m = %u", b->k, b->m);
	*bp = b;
	b = NULL;
 out:
	sshbloom_free(b);
	freezero(seed, seedlen);
	free(hashalg);
	return r;
}
