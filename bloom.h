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

/* basic Bloom filter */

#include <sys/types.h>

struct sshbloom;
struct sshbuf;

int	sshbloom_can_alloc(u_int nmemb, u_int fp_rate);
struct sshbloom *sshbloom_new(u_int nmemb, u_int fp_rate);
void	sshbloom_free(struct sshbloom *b);
void	sshbloom_dump(const struct sshbloom *b);
int	sshbloom_add_ptr(struct sshbloom *b, const void *ptr, size_t len);
int	sshbloom_add_u64(struct sshbloom *b, uint64_t x);
int	sshbloom_add_cstring(struct sshbloom *b, const char *s);
int	sshbloom_test_ptr(const struct sshbloom *b, const void *ptr, size_t len,
    int *found);
int	sshbloom_test_u64(const struct sshbloom *b, uint64_t x, int *found);
int	sshbloom_test_cstring(const struct sshbloom *b, const char *s,
    int *found);
int	sshbloom_serialize(const struct sshbloom *b, struct sshbuf *m);
int	sshbloom_deserialize(struct sshbuf *m, struct sshbloom **bp);

/* Only exposed for unit tests */
int sshbloom_hash_hmac_sha512_uniform(const void *data, size_t datalen,
    const void *key, size_t keylen, uint32_t i,
    uint32_t upper_bound, uint32_t *valp);

