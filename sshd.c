/* $OpenBSD: sshd.c,v 1.602 2024/01/08 00:34:34 djm Exp $ */
/*
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
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
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <paths.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "sshpty.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "servconf.h"
#include "compat.h"
#include "digest.h"
#include "sshkey.h"
#include "authfile.h"
#include "pathnames.h"
#include "canohost.h"
#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "msg.h"
#include "version.h"
#include "ssherr.h"
#include "sk-api.h"
#include "srclimit.h"

/* Re-exec fds */
#define REEXEC_DEVCRYPTO_RESERVED_FD	(STDERR_FILENO + 1)
#define REEXEC_STARTUP_PIPE_FD		(STDERR_FILENO + 2)
#define REEXEC_CONFIG_PASS_FD		(STDERR_FILENO + 3)
#define REEXEC_MIN_FREE_FD		(STDERR_FILENO + 4)

extern char *__progname;

/* Server configuration options. */
ServerOptions options;

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
int debug_flag = 0;

/* Saved arguments to main(). */
static char **saved_argv;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
static int listen_socks[MAX_LISTEN_SOCKS];
static int num_listen_socks = 0;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
struct {
	struct sshkey	**host_keys;		/* all private host keys */
	struct sshkey	**host_pubkeys;		/* all public host keys */
	struct sshkey	**host_certificates;	/* all public host certificates */
	int		have_ssh2_key;
} sensitive_data;

/* This is set to true when a signal is received. */
static volatile sig_atomic_t received_sighup = 0;
static volatile sig_atomic_t received_sigterm = 0;

/* record remote hostname or ip */
u_int utmp_len = HOST_NAME_MAX+1;

/*
 * startup_pipes/flags are used for tracking children of the listening sshd
 * process early in their lifespans. This tracking is needed for three things:
 *
 * 1) Implementing the MaxStartups limit of concurrent unauthenticated
 *    connections.
 * 2) Avoiding a race condition for SIGHUP processing, where child processes
 *    may have listen_socks open that could collide with main listener process
 *    after it restarts.
 * 3) Ensuring that rexec'd sshd processes have received their initial state
 *    from the parent listen process before handling SIGHUP.
 *
 * Child processes signal that they have completed closure of the listen_socks
 * and (if applicable) received their rexec state by sending a char over their
 * sock. Child processes signal that authentication has completed by closing
 * the sock (or by exiting).
 */
static int *startup_pipes = NULL;
static int *startup_flags = NULL;	/* Indicates child closed listener */
static int startup_pipe = -1;		/* in child */

/* sshd_config buffer */
struct sshbuf *cfg;

/* Included files from the configuration file */
struct include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* message to be displayed after login */
struct sshbuf *loginmsg;

static char *listener_proctitle;

/*
 * Close all listening sockets
 */
static void
close_listen_socks(void)
{
	int i;

	for (i = 0; i < num_listen_socks; i++)
		close(listen_socks[i]);
	num_listen_socks = 0;
}

static void
close_startup_pipes(void)
{
	int i;

	if (startup_pipes)
		for (i = 0; i < options.max_startups; i++)
			if (startup_pipes[i] != -1)
				close(startup_pipes[i]);
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */

static void
sighup_handler(int sig)
{
	received_sighup = 1;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
static void
sighup_restart(void)
{
	logit("Received SIGHUP; restarting.");
	if (options.pid_file != NULL)
		unlink(options.pid_file);
	close_listen_socks();
	close_startup_pipes();
	ssh_signal(SIGHUP, SIG_IGN); /* will be restored after exec */
	execv(saved_argv[0], saved_argv);
	logit("RESTART FAILED: av[0]='%.100s', error: %.100s.", saved_argv[0],
	    strerror(errno));
	exit(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
static void
sigterm_handler(int sig)
{
	received_sigterm = sig;
}

/*
 * SIGCHLD handler.  This is called whenever a child dies.  This will then
 * reap any zombies left by exited children.
 */
static void
main_sigchld_handler(int sig)
{
	int save_errno = errno;
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid == -1 && errno == EINTR))
		;
	errno = save_errno;
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
static int
should_drop_connection(int startups)
{
	int p, r;

	if (startups < options.max_startups_begin)
		return 0;
	if (startups >= options.max_startups)
		return 1;
	if (options.max_startups_rate == 100)
		return 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= options.max_startups - options.max_startups_begin;
	p += options.max_startups_rate;
	r = arc4random_uniform(100);

	debug_f("p %d, r %d", p, r);
	return (r < p) ? 1 : 0;
}

/*
 * Check whether connection should be accepted by MaxStartups.
 * Returns 0 if the connection is accepted. If the connection is refused,
 * returns 1 and attempts to send notification to client.
 * Logs when the MaxStartups condition is entered or exited, and periodically
 * while in that state.
 */
static int
drop_connection(int sock, int startups, int notify_pipe)
{
	char *laddr, *raddr;
	const char msg[] = "Exceeded MaxStartups\r\n";
	static time_t last_drop, first_drop;
	static u_int ndropped;
	LogLevel drop_level = SYSLOG_LEVEL_VERBOSE;
	time_t now;

	now = monotime();
	if (!should_drop_connection(startups) &&
	    srclimit_check_allow(sock, notify_pipe) == 1) {
		if (last_drop != 0 &&
		    startups < options.max_startups_begin - 1) {
			/* XXX maybe need better hysteresis here */
			logit("exited MaxStartups throttling after %s, "
			    "%u connections dropped",
			    fmt_timeframe(now - first_drop), ndropped);
			last_drop = 0;
		}
		return 0;
	}

#define SSHD_MAXSTARTUPS_LOG_INTERVAL	(5 * 60)
	if (last_drop == 0) {
		error("beginning MaxStartups throttling");
		drop_level = SYSLOG_LEVEL_INFO;
		first_drop = now;
		ndropped = 0;
	} else if (last_drop + SSHD_MAXSTARTUPS_LOG_INTERVAL < now) {
		/* Periodic logs */
		error("in MaxStartups throttling for %s, "
		    "%u connections dropped",
		    fmt_timeframe(now - first_drop), ndropped + 1);
		drop_level = SYSLOG_LEVEL_INFO;
	}
	last_drop = now;
	ndropped++;

	laddr = get_local_ipaddr(sock);
	raddr = get_peer_ipaddr(sock);
	do_log2(drop_level, "drop connection #%d from [%s]:%d on [%s]:%d "
	    "past MaxStartups", startups, raddr, get_peer_port(sock),
	    laddr, get_local_port(sock));
	free(laddr);
	free(raddr);
	/* best-effort notification to client */
	(void)write(sock, msg, sizeof(msg) - 1);
	return 1;
}

static void
usage(void)
{
	fprintf(stderr, "%s, %s\n", SSH_VERSION, SSH_OPENSSL_VERSION);
	fprintf(stderr,
"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n"
"            [-E log_file] [-f config_file] [-g login_grace_time]\n"
"            [-h host_key_file] [-o option] [-p port] [-u len]\n"
	);
	exit(1);
}

static struct sshbuf *
pack_hostkeys(void)
{
	struct sshbuf *keybuf = NULL, *hostkeys = NULL;
	int r;
	u_int i;

	if ((keybuf = sshbuf_new()) == NULL ||
	    (hostkeys = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack hostkeys into a string. Empty key slots get empty strings */
	for (i = 0; i < options.num_host_key_files; i++) {
		/* private key */
		sshbuf_reset(keybuf);
		if (sensitive_data.host_keys[i] != NULL &&
		    (r = sshkey_private_serialize(sensitive_data.host_keys[i],
		    keybuf)) != 0)
			fatal_fr(r, "serialize hostkey private");
		if ((r = sshbuf_put_stringb(hostkeys, keybuf)) != 0)
			fatal_fr(r, "compose hostkey private");
		/* public key */
		if (sensitive_data.host_pubkeys[i] != NULL) {
			if ((r = sshkey_puts(sensitive_data.host_pubkeys[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose hostkey public");
		} else {
			if ((r = sshbuf_put_string(hostkeys, NULL, 0)) != 0)
				fatal_fr(r, "compose hostkey empty public");
		}
		/* cert */
		if (sensitive_data.host_certificates[i] != NULL) {
			if ((r = sshkey_puts(
			    sensitive_data.host_certificates[i],
			    hostkeys)) != 0)
				fatal_fr(r, "compose host cert");
		} else {
			if ((r = sshbuf_put_string(hostkeys, NULL, 0)) != 0)
				fatal_fr(r, "compose host cert empty");
		}
	}

	sshbuf_free(keybuf);
	return hostkeys;
}

static void
send_rexec_state(int fd, struct sshbuf *conf)
{
	struct sshbuf *m = NULL, *inc = NULL, *hostkeys = NULL;
	struct include_item *item = NULL;
	int r, sz;

	debug3_f("entering fd = %d config len %zu", fd,
	    sshbuf_len(conf));

	if ((m = sshbuf_new()) == NULL ||
	    (inc = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* pack includes into a string */
	TAILQ_FOREACH(item, &includes, entry) {
		if ((r = sshbuf_put_cstring(inc, item->selector)) != 0 ||
		    (r = sshbuf_put_cstring(inc, item->filename)) != 0 ||
		    (r = sshbuf_put_stringb(inc, item->contents)) != 0)
			fatal_fr(r, "compose includes");
	}

	hostkeys = pack_hostkeys();

	/*
	 * Protocol from reexec master to child:
	 *	string	configuration
	 *	uint64	timing_secret
	 *	string	host_keys[] {
	 *		string private_key
	 *		string public_key
	 *		string certificate
	 *	}
	 *	string	included_files[] {
	 *		string	selector
	 *		string	filename
	 *		string	contents
	 *	}
	 */
	if ((r = sshbuf_put_stringb(m, conf)) != 0 ||
	    (r = sshbuf_put_u64(m, options.timing_secret)) != 0 ||
	    (r = sshbuf_put_stringb(m, hostkeys)) != 0 ||
	    (r = sshbuf_put_stringb(m, inc)) != 0)
		fatal_fr(r, "compose config");

	/* We need to fit the entire message inside the socket send buffer */
	sz = ROUNDUP(sshbuf_len(m) + 5, 16*1024);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz) == -1)
		fatal_f("setsockopt SO_SNDBUF: %s", strerror(errno));

	if (ssh_msg_send(fd, 0, m) == -1)
		error_f("ssh_msg_send failed");

	sshbuf_free(m);
	sshbuf_free(inc);
	sshbuf_free(hostkeys);

	debug3_f("done");
}

/*
 * Listen for TCP connections
 */
static void
listen_on_addrs(struct listenaddr *la)
{
	int ret, listen_sock;
	struct addrinfo *ai;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	for (ai = la->addrs; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (num_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. "
			    "Enlarge MAX_LISTEN_SOCKS");
		if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo failed: %.100s",
			    ssh_gai_strerror(ret));
			continue;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype,
		    ai->ai_protocol);
		if (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			continue;
		}
		if (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			continue;
		}
		if (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			continue;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);
		if (la->rdomain != NULL &&
		    set_rdomain(listen_sock, la->rdomain) == -1) {
			close(listen_sock);
			continue;
		}

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.",
			    strport, ntop, strerror(errno));
			close(listen_sock);
			continue;
		}
		listen_socks[num_listen_socks] = listen_sock;
		num_listen_socks++;

		/* Start listening on the port. */
		if (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1)
			fatal("listen on [%s]:%s: %.100s",
			    ntop, strport, strerror(errno));
		logit("Server listening on %s port %s%s%s.",
		    ntop, strport,
		    la->rdomain == NULL ? "" : " rdomain ",
		    la->rdomain == NULL ? "" : la->rdomain);
	}
}

static void
server_listen(void)
{
	u_int i;

	/* Initialise per-source limit tracking. */
	srclimit_init(options.max_startups, options.per_source_max_startups,
	    options.per_source_masklen_ipv4, options.per_source_masklen_ipv6);

	for (i = 0; i < options.num_listen_addrs; i++) {
		listen_on_addrs(&options.listen_addrs[i]);
		freeaddrinfo(options.listen_addrs[i].addrs);
		free(options.listen_addrs[i].rdomain);
		memset(&options.listen_addrs[i], 0,
		    sizeof(options.listen_addrs[i]));
	}
	free(options.listen_addrs);
	options.listen_addrs = NULL;
	options.num_listen_addrs = 0;

	if (!num_listen_socks)
		fatal("Cannot bind any address.");
}

/*
 * The main TCP accept loop. Note that, for the non-debug case, returns
 * from this function are in a forked subprocess.
 */
static void
server_accept_loop(int *sock_in, int *sock_out, int *newsock, int *config_s,
    int log_stderr)
{
	struct pollfd *pfd = NULL;
	int i, j, ret, npfd;
	int ostartups = -1, startups = 0, listening = 0, lameduck = 0;
	int startup_p[2] = { -1 , -1 }, *startup_pollfd;
	char c = 0;
	struct sockaddr_storage from;
	socklen_t fromlen;
	pid_t pid;
	sigset_t nsigset, osigset;

	/* setup fd set for accept */
	/* pipes connected to unauthenticated child sshd processes */
	startup_pipes = xcalloc(options.max_startups, sizeof(int));
	startup_flags = xcalloc(options.max_startups, sizeof(int));
	startup_pollfd = xcalloc(options.max_startups, sizeof(int));
	for (i = 0; i < options.max_startups; i++)
		startup_pipes[i] = -1;

	/*
	 * Prepare signal mask that we use to block signals that might set
	 * received_sigterm or received_sighup, so that we are guaranteed
	 * to immediately wake up the ppoll if a signal is received after
	 * the flag is checked.
	 */
	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGCHLD);
	sigaddset(&nsigset, SIGTERM);
	sigaddset(&nsigset, SIGQUIT);

	/* sized for worst-case */
	pfd = xcalloc(num_listen_socks + options.max_startups,
	    sizeof(struct pollfd));

	/*
	 * Stay listening for connections until the system crashes or
	 * the daemon is killed with a signal.
	 */
	for (;;) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		if (received_sigterm) {
			logit("Received signal %d; terminating.",
			    (int) received_sigterm);
			close_listen_socks();
			if (options.pid_file != NULL)
				unlink(options.pid_file);
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		if (ostartups != startups) {
			setproctitle("%s [listener] %d of %d-%d startups",
			    listener_proctitle, startups,
			    options.max_startups_begin, options.max_startups);
			ostartups = startups;
		}
		if (received_sighup) {
			if (!lameduck) {
				debug("Received SIGHUP; waiting for children");
				close_listen_socks();
				lameduck = 1;
			}
			if (listening <= 0) {
				sigprocmask(SIG_SETMASK, &osigset, NULL);
				sighup_restart();
			}
		}

		for (i = 0; i < num_listen_socks; i++) {
			pfd[i].fd = listen_socks[i];
			pfd[i].events = POLLIN;
		}
		npfd = num_listen_socks;
		for (i = 0; i < options.max_startups; i++) {
			startup_pollfd[i] = -1;
			if (startup_pipes[i] != -1) {
				pfd[npfd].fd = startup_pipes[i];
				pfd[npfd].events = POLLIN;
				startup_pollfd[i] = npfd++;
			}
		}

		/* Wait until a connection arrives or a child exits. */
		ret = ppoll(pfd, npfd, NULL, &osigset);
		if (ret == -1 && errno != EINTR) {
			error("ppoll: %.100s", strerror(errno));
			if (errno == EINVAL)
				cleanup_exit(1); /* can't recover */
		}
		sigprocmask(SIG_SETMASK, &osigset, NULL);
		if (ret == -1)
			continue;

		for (i = 0; i < options.max_startups; i++) {
			if (startup_pipes[i] == -1 ||
			    startup_pollfd[i] == -1 ||
			    !(pfd[startup_pollfd[i]].revents & (POLLIN|POLLHUP)))
				continue;
			switch (read(startup_pipes[i], &c, sizeof(c))) {
			case -1:
				if (errno == EINTR || errno == EAGAIN)
					continue;
				if (errno != EPIPE) {
					error_f("startup pipe %d (fd=%d): "
					    "read %s", i, startup_pipes[i],
					    strerror(errno));
				}
				/* FALLTHROUGH */
			case 0:
				/* child exited or completed auth */
				close(startup_pipes[i]);
				srclimit_done(startup_pipes[i]);
				startup_pipes[i] = -1;
				startups--;
				if (startup_flags[i])
					listening--;
				break;
			case 1:
				/* child has finished preliminaries */
				if (startup_flags[i]) {
					listening--;
					startup_flags[i] = 0;
				}
				break;
			}
		}
		for (i = 0; i < num_listen_socks; i++) {
			if (!(pfd[i].revents & POLLIN))
				continue;
			fromlen = sizeof(from);
			*newsock = accept(listen_socks[i],
			    (struct sockaddr *)&from, &fromlen);
			if (*newsock == -1) {
				if (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED)
					error("accept: %.100s",
					    strerror(errno));
				if (errno == EMFILE || errno == ENFILE)
					usleep(100 * 1000);
				continue;
			}
			if (unset_nonblock(*newsock) == -1) {
				close(*newsock);
				continue;
			}
			if (pipe(startup_p) == -1) {
				error_f("pipe(startup_p): %s", strerror(errno));
				close(*newsock);
				continue;
			}
			if (drop_connection(*newsock, startups, startup_p[0])) {
				close(*newsock);
				close(startup_p[0]);
				close(startup_p[1]);
				continue;
			}

			if (socketpair(AF_UNIX,
			    SOCK_STREAM, 0, config_s) == -1) {
				error("reexec socketpair: %s",
				    strerror(errno));
				close(*newsock);
				close(startup_p[0]);
				close(startup_p[1]);
				continue;
			}

			for (j = 0; j < options.max_startups; j++)
				if (startup_pipes[j] == -1) {
					startup_pipes[j] = startup_p[0];
					startups++;
					startup_flags[j] = 1;
					break;
				}

			/*
			 * Got connection.  Fork a child to handle it, unless
			 * we are in debugging mode.
			 */
			if (debug_flag) {
				/*
				 * In debugging mode.  Close the listening
				 * socket, and start processing the
				 * connection without forking.
				 */
				debug("Server will not fork when running in debugging mode.");
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				close(startup_p[0]);
				close(startup_p[1]);
				startup_pipe = -1;
				pid = getpid();
				send_rexec_state(config_s[0], cfg);
				close(config_s[0]);
				free(pfd);
				return;
			}

			/*
			 * Normal production daemon.  Fork, and have
			 * the child process the connection. The
			 * parent continues listening.
			 */
			listening++;
			if ((pid = fork()) == 0) {
				/*
				 * Child.  Close the listening and
				 * max_startup sockets.  Start using
				 * the accepted socket. Reinitialize
				 * logging (since our pid has changed).
				 * We return from this function to handle
				 * the connection.
				 */
				startup_pipe = startup_p[1];
				close_startup_pipes();
				close_listen_socks();
				*sock_in = *newsock;
				*sock_out = *newsock;
				log_init(__progname,
				    options.log_level,
				    options.log_facility,
				    log_stderr);
				close(config_s[0]);
				free(pfd);
				return;
			}

			/* Parent.  Stay in the loop. */
			if (pid == -1)
				error("fork: %.100s", strerror(errno));
			else
				debug("Forked child %ld.", (long)pid);

			close(startup_p[1]);

			close(config_s[1]);
			send_rexec_state(config_s[0], cfg);
			close(config_s[0]);
			close(*newsock);
		}
	}
}

static void
accumulate_host_timing_secret(struct sshbuf *server_cfg,
    struct sshkey *key)
{
	static struct ssh_digest_ctx *ctx;
	u_char *hash;
	size_t len;
	struct sshbuf *buf;
	int r;

	if (ctx == NULL && (ctx = ssh_digest_start(SSH_DIGEST_SHA512)) == NULL)
		fatal_f("ssh_digest_start");
	if (key == NULL) { /* finalize */
		/* add server config in case we are using agent for host keys */
		if (ssh_digest_update(ctx, sshbuf_ptr(server_cfg),
		    sshbuf_len(server_cfg)) != 0)
			fatal_f("ssh_digest_update");
		len = ssh_digest_bytes(SSH_DIGEST_SHA512);
		hash = xmalloc(len);
		if (ssh_digest_final(ctx, hash, len) != 0)
			fatal_f("ssh_digest_final");
		options.timing_secret = PEEK_U64(hash);
		freezero(hash, len);
		ssh_digest_free(ctx);
		ctx = NULL;
		return;
	}
	if ((buf = sshbuf_new()) == NULL)
		fatal_f("could not allocate buffer");
	if ((r = sshkey_private_serialize(key, buf)) != 0)
		fatal_fr(r, "encode %s key", sshkey_ssh_name(key));
	if (ssh_digest_update(ctx, sshbuf_ptr(buf), sshbuf_len(buf)) != 0)
		fatal_f("ssh_digest_update");
	sshbuf_reset(buf);
	sshbuf_free(buf);
}

static char *
prepare_proctitle(int ac, char **av)
{
	char *ret = NULL;
	int i;

	for (i = 0; i < ac; i++)
		xextendf(&ret, " ", "%s", av[i]);
	return ret;
}

static void
print_config(struct connection_info *connection_info)
{
	/*
	 * If no connection info was provided by -C then use
	 * use a blank one that will cause no predicate to match.
	 */
	if (connection_info == NULL)
		connection_info = get_connection_info(NULL, 0, 0);
	connection_info->test = 1;
	parse_server_match_config(&options, &includes, connection_info);
	dump_config(&options);
	exit(0);
}

/*
 * Main program for the daemon.
 */
int
main(int ac, char **av)
{
	extern char *optarg;
	extern int optind;
	int log_stderr = 0, inetd_flag = 0, test_flag = 0, no_daemon_flag = 0;
	char *config_file_name = _PATH_SERVER_CONFIG_FILE;
	int r, opt, do_dump_cfg = 0, keytype, already_daemon, have_agent = 0;
	int sock_in = -1, sock_out = -1, newsock = -1, rexec_argc = 0;
	char *fp, *line, *logfile = NULL, **rexec_argv = NULL;
	struct stat sb;
	int config_s[2] = { -1 , -1 };
	u_int i, j;
	mode_t new_umask;
	struct sshkey *key;
	struct sshkey *pubkey;
	struct connection_info *connection_info = NULL;
	sigset_t sigmask;

	sigemptyset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);

	/* Save argv. */
	saved_argv = av;
	rexec_argc = ac;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	while ((opt = getopt(ac, av,
	    "C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV")) != -1) {
		switch (opt) {
		case '4':
			options.address_family = AF_INET;
			break;
		case '6':
			options.address_family = AF_INET6;
			break;
		case 'f':
			config_file_name = optarg;
			break;
		case 'c':
			servconf_add_hostcert("[command-line]", 0,
			    &options, optarg);
			break;
		case 'd':
			if (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} else if (options.log_level < SYSLOG_LEVEL_DEBUG3)
				options.log_level++;
			break;
		case 'D':
			no_daemon_flag = 1;
			break;
		case 'G':
			do_dump_cfg = 1;
			break;
		case 'E':
			logfile = optarg;
			/* FALLTHROUGH */
		case 'e':
			log_stderr = 1;
			break;
		case 'i':
			inetd_flag = 1;
			break;
		case 'r':
			/* ignored */
			break;
		case 'R':
			fatal("-R not supported here");
			break;
		case 'Q':
			/* ignored */
			break;
		case 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			break;
		case 'b':
			/* protocol 1, ignored */
			break;
		case 'p':
			options.ports_from_cmdline = 1;
			if (options.num_ports >= MAX_PORTS) {
				fprintf(stderr, "too many ports.\n");
				exit(1);
			}
			options.ports[options.num_ports++] = a2port(optarg);
			if (options.ports[options.num_ports-1] <= 0) {
				fprintf(stderr, "Bad port number.\n");
				exit(1);
			}
			break;
		case 'g':
			if ((options.login_grace_time = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid login grace time.\n");
				exit(1);
			}
			break;
		case 'k':
			/* protocol 1, ignored */
			break;
		case 'h':
			servconf_add_hostkey("[command-line]", 0,
			    &options, optarg, 1);
			break;
		case 't':
			test_flag = 1;
			break;
		case 'T':
			test_flag = 2;
			break;
		case 'C':
			connection_info = get_connection_info(NULL, 0, 0);
			if (parse_server_match_testspec(connection_info,
			    optarg) == -1)
				exit(1);
			break;
		case 'u':
			utmp_len = (u_int)strtonum(optarg, 0, HOST_NAME_MAX+1+1, NULL);
			if (utmp_len > HOST_NAME_MAX+1) {
				fprintf(stderr, "Invalid utmp length.\n");
				exit(1);
			}
			break;
		case 'o':
			line = xstrdup(optarg);
			if (process_server_config_line(&options, line,
			    "command-line", 0, NULL, NULL, &includes) != 0)
				exit(1);
			free(line);
			break;
		case 'V':
			fprintf(stderr, "%s, %s\n",
			    SSH_VERSION, SSH_OPENSSL_VERSION);
			exit(0);
		default:
			usage();
			break;
		}
	}
	if (!test_flag && !do_dump_cfg && !path_absolute(av[0]))
		fatal("sshd requires execution with an absolute path");
	closefrom(REEXEC_DEVCRYPTO_RESERVED_FD);

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
#endif

	/* If requested, redirect the logs to the specified logfile. */
	if (logfile != NULL) {
		char *cp, pid_s[32];

		snprintf(pid_s, sizeof(pid_s), "%ld", (unsigned long)getpid());
		cp = percent_expand(logfile,
		    "p", pid_s,
		    "P", "sshd",
		    (char *)NULL);
		log_redirect_stderr_to(cp);
		free(cp);
	}

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    log_stderr || !inetd_flag || debug_flag);

	sensitive_data.have_ssh2_key = 0;

	/*
	 * If we're not doing an extended test do not silently ignore connection
	 * test params.
	 */
	if (test_flag < 2 && connection_info != NULL)
		fatal("Config test connection parameter (-C) provided without "
		    "test mode (-T)");

	/* Fetch our configuration */
	if ((cfg = sshbuf_new()) == NULL)
		fatal("sshbuf_new config failed");
	if (strcasecmp(config_file_name, "none") != 0)
		load_server_config(config_file_name, cfg);

	parse_server_config(&options, config_file_name, cfg,
	    &includes, NULL, 0);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	/* Check that options are sensible */
	if (options.authorized_keys_command_user == NULL &&
	    (options.authorized_keys_command != NULL &&
	    strcasecmp(options.authorized_keys_command, "none") != 0))
		fatal("AuthorizedKeysCommand set without "
		    "AuthorizedKeysCommandUser");
	if (options.authorized_principals_command_user == NULL &&
	    (options.authorized_principals_command != NULL &&
	    strcasecmp(options.authorized_principals_command, "none") != 0))
		fatal("AuthorizedPrincipalsCommand set without "
		    "AuthorizedPrincipalsCommandUser");

	/*
	 * Check whether there is any path through configured auth methods.
	 * Unfortunately it is not possible to verify this generally before
	 * daemonisation in the presence of Match blocks, but this catches
	 * and warns for trivial misconfigurations that could break login.
	 */
	if (options.num_auth_methods != 0) {
		for (i = 0; i < options.num_auth_methods; i++) {
			if (auth2_methods_valid(options.auth_methods[i],
			    1) == 0)
				break;
		}
		if (i >= options.num_auth_methods)
			fatal("AuthenticationMethods cannot be satisfied by "
			    "enabled authentication methods");
	}

	/* Check that there are no remaining arguments. */
	if (optind < ac) {
		fprintf(stderr, "Extra argument %s.\n", av[optind]);
		exit(1);
	}

	debug("sshd version %s, %s", SSH_VERSION, SSH_OPENSSL_VERSION);

	if (do_dump_cfg)
		print_config(connection_info);

	/* load host keys */
	sensitive_data.host_keys = xcalloc(options.num_host_key_files,
	    sizeof(struct sshkey *));
	sensitive_data.host_pubkeys = xcalloc(options.num_host_key_files,
	    sizeof(struct sshkey *));

	if (options.host_key_agent) {
		if (strcmp(options.host_key_agent, SSH_AUTHSOCKET_ENV_NAME))
			setenv(SSH_AUTHSOCKET_ENV_NAME,
			    options.host_key_agent, 1);
		if ((r = ssh_get_authentication_socket(NULL)) == 0)
			have_agent = 1;
		else
			error_r(r, "Could not connect to agent \"%s\"",
			    options.host_key_agent);
	}

	for (i = 0; i < options.num_host_key_files; i++) {
		int ll = options.host_key_file_userprovided[i] ?
		    SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_DEBUG1;

		if (options.host_key_files[i] == NULL)
			continue;
		if ((r = sshkey_load_private(options.host_key_files[i], "",
		    &key, NULL)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_key_files[i]);
		if (sshkey_is_sk(key) &&
		    key->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			debug("host key %s requires user presence, ignoring",
			    options.host_key_files[i]);
			key->sk_flags &= ~SSH_SK_USER_PRESENCE_REQD;
		}
		if (r == 0 && key != NULL &&
		    (r = sshkey_shield_private(key)) != 0) {
			do_log2_r(r, ll, "Unable to shield host key \"%s\"",
			    options.host_key_files[i]);
			sshkey_free(key);
			key = NULL;
		}
		if ((r = sshkey_load_public(options.host_key_files[i],
		    &pubkey, NULL)) != 0 && r != SSH_ERR_SYSTEM_ERROR)
			do_log2_r(r, ll, "Unable to load host key \"%s\"",
			    options.host_key_files[i]);
		if (pubkey != NULL && key != NULL) {
			if (!sshkey_equal(pubkey, key)) {
				error("Public key for %s does not match "
				    "private key", options.host_key_files[i]);
				sshkey_free(pubkey);
				pubkey = NULL;
			}
		}
		if (pubkey == NULL && key != NULL) {
			if ((r = sshkey_from_private(key, &pubkey)) != 0)
				fatal_r(r, "Could not demote key: \"%s\"",
				    options.host_key_files[i]);
		}
		if (pubkey != NULL && (r = sshkey_check_rsa_length(pubkey,
		    options.required_rsa_size)) != 0) {
			error_fr(r, "Host key %s", options.host_key_files[i]);
			sshkey_free(pubkey);
			sshkey_free(key);
			continue;
		}
		sensitive_data.host_keys[i] = key;
		sensitive_data.host_pubkeys[i] = pubkey;

		if (key == NULL && pubkey != NULL && have_agent) {
			debug("will rely on agent for hostkey %s",
			    options.host_key_files[i]);
			keytype = pubkey->type;
		} else if (key != NULL) {
			keytype = key->type;
			accumulate_host_timing_secret(cfg, key);
		} else {
			do_log2(ll, "Unable to load host key: %s",
			    options.host_key_files[i]);
			sensitive_data.host_keys[i] = NULL;
			sensitive_data.host_pubkeys[i] = NULL;
			continue;
		}

		switch (keytype) {
		case KEY_RSA:
		case KEY_DSA:
		case KEY_ECDSA:
		case KEY_ED25519:
		case KEY_ECDSA_SK:
		case KEY_ED25519_SK:
		case KEY_XMSS:
			if (have_agent || key != NULL)
				sensitive_data.have_ssh2_key = 1;
			break;
		}
		if ((fp = sshkey_fingerprint(pubkey, options.fingerprint_hash,
		    SSH_FP_DEFAULT)) == NULL)
			fatal("sshkey_fingerprint failed");
		debug("%s host key #%d: %s %s",
		    key ? "private" : "agent", i, sshkey_ssh_name(pubkey), fp);
		free(fp);
	}
	accumulate_host_timing_secret(cfg, NULL);
	if (!sensitive_data.have_ssh2_key) {
		logit("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	sensitive_data.host_certificates = xcalloc(options.num_host_key_files,
	    sizeof(struct sshkey *));
	for (i = 0; i < options.num_host_key_files; i++)
		sensitive_data.host_certificates[i] = NULL;

	for (i = 0; i < options.num_host_cert_files; i++) {
		if (options.host_cert_files[i] == NULL)
			continue;
		if ((r = sshkey_load_public(options.host_cert_files[i],
		    &key, NULL)) != 0) {
			error_r(r, "Could not load host certificate \"%s\"",
			    options.host_cert_files[i]);
			continue;
		}
		if (!sshkey_is_cert(key)) {
			error("Certificate file is not a certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		/* Find matching private key */
		for (j = 0; j < options.num_host_key_files; j++) {
			if (sshkey_equal_public(key,
			    sensitive_data.host_pubkeys[j])) {
				sensitive_data.host_certificates[j] = key;
				break;
			}
		}
		if (j >= options.num_host_key_files) {
			error("No matching private key for certificate: %s",
			    options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		sensitive_data.host_certificates[j] = key;
		debug("host certificate: #%u type %d %s", j, key->type,
		    sshkey_type(key));
	}

	/* Ensure privsep directory is correctly configured. */
	if (getpwnam(SSH_PRIVSEP_USER) == NULL)
		fatal("Privilege separation user %s does not exist",
		    SSH_PRIVSEP_USER);
	endpwent();
	if ((stat(_PATH_PRIVSEP_CHROOT_DIR, &sb) == -1) ||
	    (S_ISDIR(sb.st_mode) == 0))
		fatal("Missing privilege separation directory: %s",
		    _PATH_PRIVSEP_CHROOT_DIR);
	if (sb.st_uid != 0 || (sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
		fatal("%s must be owned by root and not group or "
		    "world-writable.", _PATH_PRIVSEP_CHROOT_DIR);

	if (test_flag > 1)
		print_config(connection_info);

	/* Configuration looks good, so exit if in test mode. */
	if (test_flag)
		exit(0);

	/* Prepare arguments for sshd-monitor */
	if (rexec_argc < 0)
		fatal("rexec_argc %d < 0", rexec_argc);
	rexec_argv = xcalloc(rexec_argc + 3, sizeof(char *));
	/* Point to the sshd-monitor binary instead of sshd */
	rexec_argv[0] = options.sshd_monitor_path;
	for (i = 1; i < (u_int)rexec_argc; i++) {
		debug("rexec_argv[%d]='%s'", i, saved_argv[i]);
		rexec_argv[i] = saved_argv[i];
	}
	rexec_argv[rexec_argc++] = "-R";
	rexec_argv[rexec_argc] = NULL;
	if (stat(rexec_argv[0], &sb) != 0 || !(sb.st_mode & (S_IXOTH|S_IXUSR)))
		fatal("%s does not exist or is not executable", rexec_argv[0]);
	debug3("using %s for re-exec", rexec_argv[0]);

	/* Ensure that the privsep binary exists now too. */
	if (stat(options.sshd_privsep_preauth_path, &sb) != 0 ||
	    !(sb.st_mode & (S_IXOTH|S_IXUSR))) {
		fatal("%s does not exist or is not executable",
		    options.sshd_privsep_preauth_path);
	}

	listener_proctitle = prepare_proctitle(ac, av);

	/* Ensure that umask disallows at least group and world write */
	new_umask = umask(0077) | 0022;
	(void) umask(new_umask);

	/* Initialize the log (it is reinitialized below in case we forked). */
	if (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level,
	    options.log_facility, log_stderr);
	for (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);

	/*
	 * If not in debugging mode, not started from inetd and not already
	 * daemonized (eg re-exec via SIGHUP), disconnect from the controlling
	 * terminal, and fork.  The original process exits.
	 */
	already_daemon = daemonized();
	if (!(debug_flag || inetd_flag || no_daemon_flag || already_daemon)) {

		if (daemon(0, 0) == -1)
			fatal("daemon() failed: %.200s", strerror(errno));

		disconnect_controlling_tty();
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/*
	 * Chdir to the root directory so that the current disk can be
	 * unmounted if desired.
	 */
	if (chdir("/") == -1)
		error("chdir(\"/\"): %s", strerror(errno));

	/* ignore SIGPIPE */
	ssh_signal(SIGPIPE, SIG_IGN);

	/* Get a connection, either from inetd or a listening TCP socket */
	if (inetd_flag) {
		/* Send configuration to ancestor sshd-monitor process */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, config_s) == -1)
			fatal("socketpair: %s", strerror(errno));
		send_rexec_state(config_s[0], cfg);
		close(config_s[0]);
	} else {
		server_listen();

		ssh_signal(SIGHUP, sighup_handler);
		ssh_signal(SIGCHLD, main_sigchld_handler);
		ssh_signal(SIGTERM, sigterm_handler);
		ssh_signal(SIGQUIT, sigterm_handler);

		/*
		 * Write out the pid file after the sigterm handler
		 * is setup and the listen sockets are bound
		 */
		if (options.pid_file != NULL && !debug_flag) {
			FILE *f = fopen(options.pid_file, "w");

			if (f == NULL) {
				error("Couldn't create pid file \"%s\": %s",
				    options.pid_file, strerror(errno));
			} else {
				fprintf(f, "%ld\n", (long) getpid());
				fclose(f);
			}
		}

		/* Accept a connection and return in a forked child */
		server_accept_loop(&sock_in, &sock_out,
		    &newsock, config_s, log_stderr);
	}

	/* This is the child processing a new connection. */
	setproctitle("%s", "[accepted]");

	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
	if (!debug_flag && !inetd_flag && setsid() == -1)
		error("setsid: %.100s", strerror(errno));

	debug("rexec start in %d out %d newsock %d pipe %d sock %d/%d",
	    sock_in, sock_out, newsock, startup_pipe, config_s[0], config_s[1]);
	if (!inetd_flag) {
		if (dup2(newsock, STDIN_FILENO) == -1)
			debug3("dup2 stdin: %s", strerror(errno));
		if (dup2(STDIN_FILENO, STDOUT_FILENO) == -1)
			debug3("dup2 stdout: %s", strerror(errno));
	}
	log_redirect_stderr_to(NULL); /* dup might clobber log fd */
	if (config_s[1] != REEXEC_CONFIG_PASS_FD) {
		if (dup2(config_s[1], REEXEC_CONFIG_PASS_FD) == -1)
			debug3("dup2 config_s: %s", strerror(errno));
		close(config_s[1]);
	}
	if (startup_pipe == -1)
		close(REEXEC_STARTUP_PIPE_FD);
	else if (startup_pipe != REEXEC_STARTUP_PIPE_FD) {
		if (dup2(startup_pipe, REEXEC_STARTUP_PIPE_FD) == -1)
			debug3("dup2 startup_p: %s", strerror(errno));
		close(startup_pipe);
	}

	ssh_signal(SIGHUP, SIG_IGN); /* avoid reset to SIG_DFL */
	execv(rexec_argv[0], rexec_argv);

	fatal("rexec of %s failed: %s", rexec_argv[0], strerror(errno));
}

/* server specific fatal cleanup */
void
cleanup_exit(int i)
{
	_exit(i);
}
