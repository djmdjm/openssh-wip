/*
 * Copyright (c) 2020 Darren Tucker <dtucker@openbsd.org>
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
struct xaddr;

void	srclimit_init(int, int, int, int, int, int, int, int, int);
int	srclimit_check_allow(int, int);
void	srclimit_done(int);

#define SRCLIMIT_PENALTY_NONE		0
#define SRCLIMIT_PENALTY_CRASH		1
#define SRCLIMIT_PENALTY_AUTHFAIL	2
#define SRCLIMIT_PENALTY_GRACE_EXCEEDED	3

void	srclimit_penalise(struct xaddr *, int);
int	srclimit_penalty_check_allow(int, const char **);
