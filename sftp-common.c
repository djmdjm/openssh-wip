/* $OpenBSD: sftp-common.c,v 1.34 2023/03/31 04:00:37 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
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
#include <sys/stat.h>

#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <util.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"

#include "sftp.h"
#include "sftp-common.h"

/* Clear contents of attributes structure */
void
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->xflags = 0;
	a->size = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	memset(&a->atim, 0, sizeof(a->atim));
	memset(&a->mtim, 0, sizeof(a->mtim));
	memset(&a->ctim, 0, sizeof(a->ctim));
}

/* Convert from struct stat to filexfer attribs */
void
stat_to_attrib(const struct stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_SIZE;
	a->size = st->st_size;
	a->flags |= SSH2_FILEXFER_ATTR_UIDGID;
	a->uid = st->st_uid;
	a->gid = st->st_gid;
	a->flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	a->perm = st->st_mode;
	a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->xflags |= SSH2_FILEXFER_XATTR_AMCTIMES;
	a->atim = st->st_atim;
	a->mtim = st->st_mtim;
	a->ctim = st->st_ctim;
}

/* Convert from filexfer attribs to struct stat */
void
attrib_to_stat(const Attrib *a, struct stat *st)
{
	memset(st, 0, sizeof(*st));

	if (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	if (a->xflags & SSH2_FILEXFER_XATTR_AMCTIMES) {
		st->st_atim = a->atim;
		st->st_mtim = a->mtim;
		st->st_ctim = a->ctim;
	} else if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atim.tv_sec;
		st->st_mtime = a->mtim.tv_sec;
	}
}

struct timeval *
attrib_to_tv(const Attrib *a)
{
	static struct timeval tv[2];

	tv[0].tv_sec = a->atim.tv_sec;
	tv[0].tv_usec = a->atim.tv_nsec / 1000;
	tv[1].tv_sec = a->mtim.tv_sec;
	tv[1].tv_usec = a->mtim.tv_nsec / 1000;
	return tv;
}

struct timespec *
attrib_to_ts(const Attrib *a)
{
	static struct timespec ts[2];

	ts[0] = a->atim;
	ts[1] = a->mtim;
	return ts;
}

static void
u64_to_ts(uint64_t t, struct timespec *ts)
{
	ts->tv_nsec = (int)(t % 1000000000);
	t /= 1000000000;
	ts->tv_sec = (int64_t)t >= SSH_TIME_T_MAX ? SSH_TIME_T_MAX : (time_t)t;
}

static int
decode_amctimes(struct sshbuf *b, Attrib *a)
{
	uint64_t at, mt, ct;
	int r;

	debug3_f("decode len=%zu", sshbuf_len(b));
	if ((r = sshbuf_get_u64(b, &at)) != 0 ||
	    (r = sshbuf_get_u64(b, &mt)) != 0 ||
	    (r = sshbuf_get_u64(b, &ct)) != 0)
		return r;
	a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->xflags |= SSH2_FILEXFER_XATTR_AMCTIMES;
	u64_to_ts(at, &a->atim);
	u64_to_ts(mt, &a->mtim);
	u64_to_ts(ct, &a->ctim);
	return 0;
}

static time_t
u32_to_time(u_int t)
{
	return (int64_t)t > SSH_TIME_T_MAX ? SSH_TIME_T_MAX : (time_t)t;
}

/* Decode attributes in buffer */
int
decode_attrib(struct sshbuf *b, Attrib *a)
{
	int r;
	u_int at, mt;

	attrib_clear(a);
	if ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		return r;
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		if ((r = sshbuf_get_u64(b, &a->size)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		if ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		if ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		if ((r = sshbuf_get_u32(b, &at)) != 0 ||
		    (r = sshbuf_get_u32(b, &mt)) != 0)
			return r;
		a->atim.tv_sec = u32_to_time(at);
		a->mtim.tv_sec = u32_to_time(mt);
	}
	/* vendor-specific extensions */
	if (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		char *type;
		struct sshbuf *d;
		u_int i, count;

		if ((d = sshbuf_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((r = sshbuf_get_u32(b, &count)) != 0)
			return r;
		if (count > 0x100000)
			return SSH_ERR_INVALID_FORMAT;
		for (i = 0; i < count; i++) {
			sshbuf_reset(d);
			type = NULL;
			if ((r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
			    (r = sshbuf_get_stringb(b, d)) != 0) {
				free(type);
				return r;
			}
			r = -1;
			if (strcmp(type, "amctimes-0@openssh.com") == 0)
				r = decode_amctimes(d, a);
			else {
				debug3("Unsupported file attribute \"%.100s\" "
				    "len %zu", type, sshbuf_len(d));
				r = 0; /* ignore */
			}
			free(type);
			if (r != 0) {
				sshbuf_free(d);
				return r;
			}
		}
		sshbuf_free(d);
	}
	return 0;
}

static uint64_t
ts_to_u64(const struct timespec *ts)
{
	if (ts->tv_sec < 0 || ts->tv_nsec < 0)
		return 0;
	if ((uint64_t)ts->tv_sec >= ((uint64_t)-1) / 1000000000)
		return (uint64_t)-1;
	return (uint64_t)ts->tv_nsec + (((uint64_t)ts->tv_sec) * 1000000000);
}


static u_int
time_to_u32(time_t t)
{
	if (t <= 0)
		return 0;
	if ((int64_t)t >= 0xFFFFFFFFLL)
		return 0xFFFFFFFF;
	return (u_int)t;
}

/* Encode attributes to buffer */
int
encode_attrib(struct sshbuf *b, const Attrib *a, u_int compat)
{
	int r;
	struct sshbuf *ext;
	u_int ext_flag = 0;

	if ((compat & SSH2_FILEXFER_COMPAT_ATTRIB_EXT) == 0) {
		if (a->xflags & SSH2_FILEXFER_XATTR_AMCTIMES)
			ext_flag = SSH2_FILEXFER_ATTR_EXTENDED;
	}

	if ((r = sshbuf_put_u32(b, a->flags | ext_flag)) != 0)
		return r;
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		if ((r = sshbuf_put_u64(b, a->size)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		if ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		if ((r = sshbuf_put_u32(b, a->perm)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		if ((r = sshbuf_put_u32(b, time_to_u32(a->atim.tv_sec))) != 0 ||
		    (r = sshbuf_put_u32(b, time_to_u32(a->mtim.tv_sec))) != 0)
			return r;
	}
	/* extensions; only one supported so far */
	if ((compat & SSH2_FILEXFER_COMPAT_ATTRIB_EXT) == 0 &&
	    (a->xflags & SSH2_FILEXFER_XATTR_AMCTIMES)) {
		if ((r = sshbuf_put_u32(b, 1)) != 0) /* extension count */
			return r;
		if ((ext = sshbuf_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((r = sshbuf_put_u64(ext, ts_to_u64(&a->atim))) != 0 ||
		    (r = sshbuf_put_u64(ext, ts_to_u64(&a->mtim))) != 0 ||
		    (r = sshbuf_put_u64(ext, ts_to_u64(&a->ctim))) != 0 ||
		    (r = sshbuf_put_cstring(b,
		    "amctimes-0@openssh.com")) != 0 ||
		    (r = sshbuf_put_stringb(b, ext)) != 0) {
			sshbuf_free(ext);
			return r;
		}
		sshbuf_free(ext);
	}

	return 0;
}

/* Convert from SSH2_FX_ status to text error message */
const char *
fx2txt(int status)
{
	switch (status) {
	case SSH2_FX_OK:
		return("No error");
	case SSH2_FX_EOF:
		return("End of file");
	case SSH2_FX_NO_SUCH_FILE:
		return("No such file or directory");
	case SSH2_FX_PERMISSION_DENIED:
		return("Permission denied");
	case SSH2_FX_FAILURE:
		return("Failure");
	case SSH2_FX_BAD_MESSAGE:
		return("Bad message");
	case SSH2_FX_NO_CONNECTION:
		return("No connection");
	case SSH2_FX_CONNECTION_LOST:
		return("Connection lost");
	case SSH2_FX_OP_UNSUPPORTED:
		return("Operation unsupported");
	default:
		return("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
char *
ls_file(const char *name, const struct stat *st, int remote, int si_units,
    const char *user, const char *group)
{
	int ulen, glen, sz = 0;
	struct tm *ltime = localtime(&st->st_mtime);
	char buf[1024], lc[8], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	char sbuf[FMT_SCALED_STRSIZE];
	time_t now;

	strmode(st->st_mode, mode);
	if (remote) {
		if (user == NULL) {
			snprintf(ubuf, sizeof ubuf, "%u", (u_int)st->st_uid);
			user = ubuf;
		}
		if (group == NULL) {
			snprintf(gbuf, sizeof gbuf, "%u", (u_int)st->st_gid);
			group = gbuf;
		}
		strlcpy(lc, "?", sizeof(lc));
	} else {
		user = user_from_uid(st->st_uid, 0);
		group = group_from_gid(st->st_gid, 0);
		snprintf(lc, sizeof(lc), "%u", (u_int)st->st_nlink);
	}
	if (ltime != NULL) {
		now = time(NULL);
		if (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, sizeof tbuf, "%b %e %H:%M", ltime);
		else
			sz = strftime(tbuf, sizeof tbuf, "%b %e  %Y", ltime);
	}
	if (sz == 0)
		tbuf[0] = '\0';
	ulen = MAXIMUM(strlen(user), 8);
	glen = MAXIMUM(strlen(group), 8);
	if (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, sizeof buf, "%s %3s %-*s %-*s %8s %s %s",
		    mode, lc, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} else {
		snprintf(buf, sizeof buf, "%s %3s %-*s %-*s %8llu %s %s",
		    mode, lc, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	return xstrdup(buf);
}
