/* $OpenBSD: servconf.h,v 1.176 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Definitions for server configuration data and for the functions reading it.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef SERVCONF_H
#define SERVCONF_H

#include <sys/queue.h>

#define MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#define	PERMIT_NOT_SET		-1
#define	PERMIT_NO		0
#define	PERMIT_FORCED_ONLY	1
#define	PERMIT_NO_PASSWD	2
#define	PERMIT_YES		3

/* PermitOpen */
#define PERMITOPEN_ANY		0
#define PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#define IGNORE_RHOSTS_NO	0
#define IGNORE_RHOSTS_YES	1
#define IGNORE_RHOSTS_SHOSTS	2

#define DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#define DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#define INTERNAL_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#define PUBKEYAUTH_TOUCH_REQUIRED	(1)
#define PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

struct ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
struct queued_listenaddr {
	char *addr;
	int port; /* <=0 if unspecified */
	char *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
struct listenaddr {
	char *rdomain;
	struct addrinfo *addrs;
};

#define PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL	1
#define PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE	2
struct per_source_penalty {
	int	enabled;
	int	max_sources4;
	int	max_sources6;
	int	overflow_mode;
	int	overflow_mode6;
	double	penalty_crash;
	double	penalty_grace;
	double	penalty_authfail;
	double	penalty_invaliduser;
	double	penalty_noauth;
	double	penalty_refuseconnection;
	double	penalty_max;
	double	penalty_min;
};

/*
 * This macro is used to generate most of ServerOptions and some of the
 * parsing and de/serialisation code in servconf.c. Every variable in
 * ServerOptions *must* be represented here.
 *
 * Variables and configuration options that need special handling (e.g.
 * those that represent a struct or use a single option to populate multiple
 * values) use the SSHCONF_CUSTOM macro and get manual variable entries in
 * ServerOptions below.
 *
 * Variables that exist in ServerOptions but aren't populated by a keyword
 * use the SSHCONF_NONCONF macro and also get manual entries in ServerOptions.
 *
 * Everything else uses one of the SSHCONF_INT, SSHCONF_STRING, or
 * SSHCONF_STRARRAY macros. These automatically populate their corresponding
 * variable definitions in ServerOptions.
 *
 * Unsupported options use SSHCONF_INT_UNSUP. This leaves the placeholder
 * variable in ServerOptions but marks the keyword as unsupported in the
 * parser.
 *
 * Why go to all this trouble? It ensures a level of consistency between
 * the configuration structure and the parsing code and helps us write
 * serialisation/deserialisation functions that we can be pretty sure will
 * capture every value in the configuration file.
 */
#define SSHD_CONFIG_ENTRIES_BASE \
SSHCONF_CUSTOM(Port, port, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(ListenAddress, listenaddress, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(HostKeyFile, hostkeyfile, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL) \
SSHCONF_CUSTOM(StreamLocalBindMask, streamlocalbindmask, SSHCFG_ALL) \
SSHCONF_CUSTOM(StreamLocalBindUnlink, streamlocalbindunlink, SSHCFG_ALL) \
SSHCONF_CUSTOM(LogFacility, logfacility, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkeyauthopts, SSHCFG_ALL) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(PerSourceNetBlockSize, persourcenetblocksize, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(PerSourcePenalties, persourcepenalties, SSHCFG_GLOBAL) \
SSHCONF_CUSTOM(RekeyLimit, rekeylimit, SSHCFG_ALL) \
SSHCONF_NONCONF(timingsuffix) \
SSHCONF_CUSTOM(ChannelTimeout, channeltimeout, SSHCFG_ALL) \
\
SSHCONF_INT(address_family, AddressFamily, SSHCFG_GLOBAL, multistate_addressfamily) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL) \
SSHCONF_STRARRAY(host_cert_files, num_host_cert_files, HostCertificate, SSHCFG_GLOBAL) \
SSHCONF_STRING(host_key_agent, HostKeyAgent, SSHCFG_GLOBAL) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL) \
SSHCONF_INT(login_grace_time, LoginGraceTime, SSHCFG_GLOBAL, NULL) \
SSHCONF_INT(permit_root_login, PermitRootLogin, SSHCFG_ALL, multistate_permitrootlogin) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts) \
SSHCONF_INTFLAG(ignore_user_known_hosts, IgnoreUserKnownHosts, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(print_lastlog, PrintLastLog, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL) \
SSHCONF_INT(x11_display_offset, X11DisplayOffset, SSHCFG_ALL, NULL) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL) \
SSHCONF_STRARRAY(log_verbose, num_log_verbose, LogVerbose, SSHCFG_ALL) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL) \
SSHCONF_INTFLAG(hostbased_uses_name_from_packet_only, HostbasedUsesNameFromPacketOnly, SSHCFG_ALL) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_STRING(hostkeyalgorithms, HostKeyAlgorithms, SSHCFG_GLOBAL) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_INTFLAG(permit_empty_passwd, PermitEmptyPasswd, SSHCFG_ALL) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd) \
SSHCONF_INT(allow_streamlocal_forwarding, AllowStreamLocalForwarding, SSHCFG_ALL, multistate_tcpfwd) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL) \
SSHCONF_STRARRAY(allow_users, num_allow_users, AllowUsers, SSHCFG_ALL) \
SSHCONF_STRARRAY(deny_users, num_deny_users, DenyUsers, SSHCFG_ALL) \
SSHCONF_STRARRAY(allow_groups, num_allow_groups, AllowGroups, SSHCFG_ALL) \
SSHCONF_STRARRAY(deny_groups, num_deny_groups, DenyGroups, SSHCFG_ALL) \
SSHCONF_STRARRAY(accept_env, num_accept_env, AcceptEnv, SSHCFG_ALL) \
SSHCONF_STRARRAY(setenv, num_setenv, SetEnv, SSHCFG_ALL) \
SSHCONF_INT(per_source_max_startups, PerSourceMaxStartups, SSHCFG_GLOBAL, NULL) \
SSHCONF_STRING(per_source_penalty_exempt, PerSourcePenaltyExemptList, SSHCFG_GLOBAL) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, NULL) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, NULL) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, NULL) \
SSHCONF_INT(client_alive_count_max, ClientAliveCountMax, SSHCFG_ALL, NULL) \
SSHCONF_STRARRAY(authorized_keys_files, num_authkeys_files, AuthorizedKeysFile, SSHCFG_ALL) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL) SSHCONF_STRARRAY(permitted_opens, num_permitted_opens, PermitOpen, SSHCFG_ALL) \
SSHCONF_STRARRAY(permitted_listens, num_permitted_listens, PermitListen, SSHCFG_ALL) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL) \
SSHCONF_STRARRAY(revoked_keys_files, num_revoked_keys_files, RevokedKeys, SSHCFG_ALL) \
SSHCONF_STRING(trusted_user_ca_keys, TrustedUserCAKeys, SSHCFG_ALL) \
SSHCONF_STRING(authorized_keys_command, AuthorizedKeysCommand, SSHCFG_ALL) \
SSHCONF_STRING(authorized_keys_command_user, AuthorizedKeysCommandUser, SSHCFG_ALL) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL) \
SSHCONF_STRING(version_addendum, VersionAddendum, SSHCFG_GLOBAL) \
SSHCONF_STRARRAY(auth_methods, num_auth_methods, AuthenticationMethods, SSHCFG_ALL) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, NULL) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL) \
SSHCONF_STRING(sk_provider, SecurityKeyProvider, SSHCFG_GLOBAL) \
SSHCONF_INT(required_rsa_size, RequiredRSASize, SSHCFG_ALL, NULL) \
SSHCONF_INT(unused_connection_timeout, UnusedConnectionTimeout, SSHCFG_ALL, NULL) \
SSHCONF_STRING(sshd_session_path, SshdSessionPath, SSHCFG_GLOBAL) \
SSHCONF_STRING(sshd_auth_path, SshdAuthPath, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(refuse_connection, ExposeAuthInfo, SSHCFG_ALL)

#ifdef KRB5
#define SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#else /* KRB5 */
#define SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INT_UNSUP(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_INT_UNSUP(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_INT_UNSUP(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_INT_UNSUP(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#endif /* KRB5 */

#ifdef GSSAPI
#define SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GssAuthentication, SSHCFG_ALL) \
SSHCONF_INTFLAG(gss_cleanup_creds, GssCleanupCreds, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(gss_deleg_creds, GssDelegateCreds, SSHCFG_GLOBAL) \
SSHCONF_INTFLAG(gss_strict_acceptor, GssStrictAcceptor, SSHCFG_GLOBAL)
#else /* GSSAPI */
#define SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INT_UNSUP(gss_authentication, GssAuthentication, SSHCFG_ALL) \
SSHCONF_INT_UNSUP(gss_cleanup_creds, GssCleanupCreds, SSHCFG_GLOBAL) \
SSHCONF_INT_UNSUP(gss_deleg_creds, GssDelegateCreds, SSHCFG_GLOBAL) \
SSHCONF_INT_UNSUP(gss_strict_acceptor, GssStrictAcceptor, SSHCFG_GLOBAL)
#endif /* GSSAPI */

#define SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_BASE \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS

/* Macros to declare ServerOptions member variables */
#define SSHCONF_INT(var, conf, flags, ms)		int var;
#define SSHCONF_INT_UNSUP(var, conf, flags)		int var;
#define SSHCONF_INTFLAG(var, conf, flags)		int var;
#define SSHCONF_UINT(var, conf, flags, ms)		u_int var;
#define SSHCONF_STRING(var, conf, flags)		char *var;
#define SSHCONF_STRARRAY(var, nvar, conf, flags)	\
	char **var; \
	u_int nvar;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags) /* empty */
#define SSHCONF_NONCONF(funcsuffix) /* empty */
typedef struct {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	num_ports;
	u_int	ports_from_cmdline;
	int	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	struct queued_listenaddr *queued_listen_addrs;
	u_int	num_queued_listens;
	struct listenaddr *listen_addrs;
	u_int	num_listen_addrs;
	/* HostKeyFile */
	char   **host_key_files;	/* Files containing host keys. */
	int	*host_key_file_userprovided; /* Key was specified by user. */
	u_int	num_host_key_files;     /* Number of files for host keys. */
	/* IPQoS */
	int	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	int	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	/* XXX could be simplified */
	struct ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PubkeyAuthOptions */
	int	pubkey_auth_options;	/* -1 or mask of PUBKEYAUTH_* flags */
	/* PermitUserEnvironment */
	int     permit_user_env;	/* If true, read ~/.ssh/environment */
	char   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int num_subsystems;
	char   **subsystem_name;
	char   **subsystem_command;
	char   **subsystem_args;
	/* MaxStartups */
	int	max_startups_begin;
	int	max_startups_rate;
	int	max_startups;
	/* PerSourceNetBlockSize */
	int	per_source_masklen_ipv4;
	int	per_source_masklen_ipv6;
	/* PerSourcePenalties */
	struct per_source_penalty per_source_penalty;
	/* RekeyLimit */
	int64_t rekey_limit;
	int	rekey_interval;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
	/* ChannelTimeout */
	char	**channel_timeouts;	/* inactivity timeout by channel type */
	u_int	num_channel_timeouts;
}       ServerOptions;
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_UINT
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF

/* Information about the incoming connection as used by Match */
struct connection_info {
	const char *user;
	int user_invalid;
	const char *host;	/* possibly resolved hostname */
	const char *address;	/* remote address */
	const char *laddress;	/* local address */
	int lport;		/* local port */
	const char *rdomain;	/* routing domain if available */
	int test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
struct include_item {
	char *selector;
	char *filename;
	struct sshbuf *contents;
	TAILQ_ENTRY(include_item) entry;
};
TAILQ_HEAD(include_list, include_item);


/*
 * These are string config options that must be copied between the
 * Match sub-config and the main config, and must be sent from the
 * privsep child to the privsep master. We use a macro to ensure all
 * the options are copied and the copies are done in the correct order.
 *
 * NB. an option must appear in servconf.c:copy_set_server_options() or
 * COPY_MATCH_STRING_OPTS here but never both.
 */
#define COPY_MATCH_STRING_OPTS() do { \
		M_CP_STROPT(banner); \
		M_CP_STROPT(trusted_user_ca_keys); \
		M_CP_STROPT(authorized_keys_command); \
		M_CP_STROPT(authorized_keys_command_user); \
		M_CP_STROPT(authorized_principals_file); \
		M_CP_STROPT(authorized_principals_command); \
		M_CP_STROPT(authorized_principals_command_user); \
		M_CP_STROPT(hostbased_accepted_algos); \
		M_CP_STROPT(pubkey_accepted_algos); \
		M_CP_STROPT(ca_sign_algorithms); \
		M_CP_STROPT(routing_domain); \
		M_CP_STROPT(permit_user_env_allowlist); \
		M_CP_STRARRAYOPT(authorized_keys_files, num_authkeys_files, 1);\
		M_CP_STRARRAYOPT(revoked_keys_files, \
		    num_revoked_keys_files, 1); \
		M_CP_STRARRAYOPT(allow_users, num_allow_users, 1); \
		M_CP_STRARRAYOPT(deny_users, num_deny_users, 1); \
		M_CP_STRARRAYOPT(allow_groups, num_allow_groups, 1); \
		M_CP_STRARRAYOPT(deny_groups, num_deny_groups, 1); \
		M_CP_STRARRAYOPT(accept_env, num_accept_env, 1); \
		M_CP_STRARRAYOPT(setenv, num_setenv, 1); \
		M_CP_STRARRAYOPT(auth_methods, num_auth_methods, 1); \
		M_CP_STRARRAYOPT(permitted_opens, num_permitted_opens, 1); \
		M_CP_STRARRAYOPT(permitted_listens, num_permitted_listens, 1); \
		M_CP_STRARRAYOPT(channel_timeouts, num_channel_timeouts, 1); \
		M_CP_STRARRAYOPT(log_verbose, num_log_verbose, 1); \
		/* Note: don't clobber num_subsystems until all copied */ \
		M_CP_STRARRAYOPT(subsystem_name, num_subsystems, 0); \
		M_CP_STRARRAYOPT(subsystem_command, num_subsystems, 0); \
		M_CP_STRARRAYOPT(subsystem_args, num_subsystems, 1); \
	} while (0)

void	 initialize_server_options(ServerOptions *);
void	 fill_default_server_options(ServerOptions *);
int	 process_server_config_line(ServerOptions *, char *, const char *, int,
	    int *, struct connection_info *, struct include_list *includes);
void	 load_server_config(const char *, struct sshbuf *);
void	 parse_server_config(ServerOptions *, const char *, struct sshbuf *,
	    struct include_list *includes, struct connection_info *, int);
void	 parse_server_match_config(ServerOptions *,
	    struct include_list *includes, struct connection_info *);
int	 parse_server_match_testspec(struct connection_info *, char *);
void	 servconf_merge_subsystems(ServerOptions *, ServerOptions *);
void	 copy_set_server_options(ServerOptions *, ServerOptions *, int);
void	 dump_config(ServerOptions *);
char	*derelativise_path(const char *);
void	 servconf_add_hostkey(const char *, const int,
	    ServerOptions *, const char *path, int);
void	 servconf_add_hostcert(const char *, const int,
	    ServerOptions *, const char *path);

#endif				/* SERVCONF_H */
