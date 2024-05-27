/*
 * Copyright (c) 2020 Darren Tucker <dtucker@openbsd.org>
 * Copyright (c) 2024 Damien Miller <djm@mindrot.org>
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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/tree.h>

#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "addr.h"
#include "canohost.h"
#include "log.h"
#include "misc.h"
#include "srclimit.h"
#include "xmalloc.h"

static int max_children, max_persource, ipv4_masklen, ipv6_masklen;
static int penalty_crash, penalty_auth_timeout, penalty_max;

/* Per connection state, used to enforce unauthenticated connection limit. */
static struct child_info {
	int id;
	struct xaddr addr;
} *child;

/* Penalised addresses, entries here prohibit connections until expired */
struct penalty {
	struct xaddr addr;
	time_t expiry;
	const char *reason;
	RB_ENTRY(penalty) tree_entry;
};
static int penalty_addr_cmp(struct penalty *a, struct penalty *b);
RB_HEAD(penalties, penalty) penalties;
RB_GENERATE_STATIC(penalties, penalty, tree_entry, penalty_addr_cmp)

static int
srclimit_mask_addr(const struct xaddr *addr, int bits, struct xaddr *masked)
{
	struct xaddr xmask;

	/* Mask address off address to desired size. */
	if (addr_netmask(addr->af, bits, &xmask) != 0 ||
	    addr_and(masked, addr, &xmask) != 0) {
		debug3_f("%s: invalid mask %d bits", __func__, bits);
		return -1;
	}
	return 0;
}

static int
srclimit_peer_addr(int sock, struct xaddr *addr)
{
	struct sockaddr_storage storage;
	socklen_t addrlen = sizeof(storage);
	struct sockaddr *sa = (struct sockaddr *)&storage;

	if (getpeername(sock, sa, &addrlen) != 0)
		return 1;	/* not remote socket? */
	if (addr_sa_to_xaddr(sa, addrlen, addr) != 0)
		return 1;	/* unknown address family? */
	return 0;
}

void
srclimit_init(int max, int persource, int ipv4len, int ipv6len,
    int crash_penalty, int auth_timeout_penalty, int max_penalty)
{
	int i;

	max_children = max;
	ipv4_masklen = ipv4len;
	ipv6_masklen = ipv6len;
	max_persource = persource;
	penalty_crash = crash_penalty;
	penalty_auth_timeout = auth_timeout_penalty;
	penalty_max = max_penalty;
	if (max_persource == INT_MAX)	/* no limit */
		return;
	debug("%s: max connections %d, per source %d, masks %d,%d", __func__,
	    max, persource, ipv4len, ipv6len);
	if (max <= 0)
		fatal("%s: invalid number of sockets: %d", __func__, max);
	child = xcalloc(max_children, sizeof(*child));
	for (i = 0; i < max_children; i++)
		child[i].id = -1;
	RB_INIT(&penalties);
}

/* returns 1 if connection allowed, 0 if not allowed. */
int
srclimit_check_allow(int sock, int id)
{
	struct xaddr xa, xb;
	int i, bits, first_unused, count = 0;
	char xas[NI_MAXHOST];

	if (max_persource == INT_MAX)	/* no limit */
		return 1;

	debug("%s: sock %d id %d limit %d", __func__, sock, id, max_persource);
	if (srclimit_peer_addr(sock, &xa) != 0)
		return 1;
	bits = xa.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	if (srclimit_mask_addr(&xa, bits, &xb) != 0)
		return 1;

	first_unused = max_children;
	/* Count matching entries and find first unused one. */
	for (i = 0; i < max_children; i++) {
		if (child[i].id == -1) {
			if (i < first_unused)
				first_unused = i;
		} else if (addr_cmp(&child[i].addr, &xb) == 0) {
			count++;
		}
	}
	if (addr_ntop(&xa, xas, sizeof(xas)) != 0) {
		debug3("%s: addr ntop failed", __func__);
		return 1;
	}
	debug3("%s: new unauthenticated connection from %s/%d, at %d of %d",
	    __func__, xas, bits, count, max_persource);

	if (first_unused == max_children) { /* no free slot found */
		debug3("%s: no free slot", __func__);
		return 0;
	}
	if (first_unused < 0 || first_unused >= max_children)
		fatal("%s: internal error: first_unused out of range",
		    __func__);

	if (count >= max_persource)
		return 0;

	/* Connection allowed, store masked address. */
	child[first_unused].id = id;
	memcpy(&child[first_unused].addr, &xb, sizeof(xb));
	return 1;
}

void
srclimit_done(int id)
{
	int i;

	if (max_persource == INT_MAX)	/* no limit */
		return;

	debug("%s: id %d", __func__, id);
	/* Clear corresponding state entry. */
	for (i = 0; i < max_children; i++) {
		if (child[i].id == id) {
			child[i].id = -1;
			return;
		}
	}
}

static int
penalty_addr_cmp(struct penalty *a, struct penalty *b)
{
	return addr_cmp(&a->addr, &b->addr);
}

static void
expire_penalties(time_t now)
{
	struct penalty *penalty, *tmp;

	/* XXX avoid full scan of tree, e.g. min-heap */
	RB_FOREACH_SAFE(penalty, penalties, &penalties, tmp) {
		if (penalty->expiry >= now)
			continue;
		RB_REMOVE(penalties, &penalties, penalty);
		free(penalty);
	}
}

static void
addr_masklen_ntop(struct xaddr *addr, int masklen, char *s, size_t slen)
{
	size_t o;

	if (addr_ntop(addr, s, slen) != 0) {
		strlcpy(s, "UNKNOWN", slen);
		return;
	}
	if ((o = strlen(s)) < slen)
		snprintf(s + o, slen - o, "/%d", masklen);
}

int
srclimit_penalty_check_allow(int sock, const char **reason)
{
	struct xaddr addr;
	struct penalty find, *penalty;
	time_t now;
	int bits;


	if (srclimit_peer_addr(sock, &addr) != 0)
		return 1;
	bits = addr.af == AF_INET ? ipv4_masklen : ipv6_masklen;
	memset(&find, 0, sizeof(find));
	if (srclimit_mask_addr(&addr, bits, &find.addr) != 0)
		return 1;
	now = monotime();
	if ((penalty = RB_FIND(penalties, &penalties, &find)) == NULL)
		return 1; /* no penalty */
	if (penalty->expiry < now) {
		expire_penalties(now);
		return 1; /* expired penalty */
	}
	*reason = penalty->reason;
	return 0;
}

void
srclimit_penalise(struct xaddr *addr, int was_crash, int was_auth_timeout)
{
	struct xaddr masked;
	struct penalty *penalty, *existing;
	time_t now;
	int bits;
	int penalty_secs = was_crash ? penalty_crash : penalty_auth_timeout;
	char addrnetmask[NI_MAXHOST + 4];

	bits = addr->af == AF_INET ? ipv4_masklen : ipv6_masklen;
	if (srclimit_mask_addr(addr, bits, &masked) != 0)
		return;
	addr_masklen_ntop(addr, bits, addrnetmask, sizeof(addrnetmask));
	debug3_f("penalty of %d seconds for %s", penalty_secs, addrnetmask);

	now = monotime();
	expire_penalties(now);
	penalty = xcalloc(1, sizeof(*penalty));
	penalty->addr = masked;
	penalty->expiry = now + penalty_secs;
	penalty->reason = was_crash ? "caused crash" :
	    "exceeded login grace time";
	if ((existing = RB_INSERT(penalties, &penalties, penalty)) != NULL) {
		/* An entry already existed. Accumulate penalty up to maximum */
		debug3_f("penalty for %s for %s already pending",
		    addrnetmask, existing->reason);
		existing->expiry += penalty_secs;
		if (existing->expiry - now > penalty_max)
			existing->expiry = now + penalty_max;
		existing->reason = penalty->reason;
		free(penalty);
	}
}
