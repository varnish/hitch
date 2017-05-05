/**
 * configuration.c
 *
 * Original author: Brane F. Gracnar
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <syslog.h>
#include <libgen.h>

#include "configuration.h"
#include "foreign/miniobj.h"
#include "foreign/vas.h"
#include "foreign/vsb.h"

#include "cfg_parser.h"

#define ADDR_LEN 150
#define PORT_LEN 6
#define CFG_BOOL_ON "on"


// BEGIN: configuration parameters
#define CFG_CIPHERS "ciphers"
#define CFG_SSL_ENGINE "ssl-engine"
#define CFG_PREFER_SERVER_CIPHERS "prefer-server-ciphers"
#define CFG_BACKEND "backend"
#define CFG_FRONTEND "frontend"
#define CFG_WORKERS "workers"
#define CFG_BACKLOG "backlog"
#define CFG_KEEPALIVE "keepalive"
#define CFG_CHROOT "chroot"
#define CFG_USER "user"
#define CFG_GROUP "group"
#define CFG_QUIET "quiet"
#define CFG_SYSLOG "syslog"
#define CFG_SYSLOG_FACILITY "syslog-facility"
#define CFG_PARAM_SYSLOG_FACILITY 11015
#define CFG_DAEMON "daemon"
#define CFG_WRITE_IP "write-ip"
#define CFG_WRITE_PROXY "write-proxy"
#define CFG_WRITE_PROXY_V1 "write-proxy-v1"
#define CFG_WRITE_PROXY_V2 "write-proxy-v2"
#define CFG_PEM_FILE "pem-file"
#define CFG_PROXY_PROXY "proxy-proxy"
#define CFG_ALPN_PROTOS "alpn-protos"
#define CFG_PARAM_ALPN_PROTOS 48173
#define CFG_BACKEND_CONNECT_TIMEOUT "backend-connect-timeout"
#define CFG_SSL_HANDSHAKE_TIMEOUT "ssl-handshake-timeout"
#define CFG_RECV_BUFSIZE "recv-bufsize"
#define CFG_SEND_BUFSIZE "send-bufsize"
#define CFG_LOG_FILENAME "log-filename"
#define CFG_RING_SLOTS "ring-slots"
#define CFG_RING_DATA_LEN "ring-data-len"
#define CFG_PIDFILE "pidfile"
#define CFG_SNI_NOMATCH_ABORT "sni-nomatch-abort"
#define CFG_OCSP_DIR "ocsp-dir"
#define CFG_TLS_PROTOS "tls-protos"

#ifdef USE_SHARED_CACHE
	#define CFG_SHARED_CACHE "shared-cache"
	#define CFG_SHARED_CACHE_LISTEN "shared-cache-listen"
	#define CFG_SHARED_CACHE_PEER "shared-cache-peer"
	#define CFG_SHARED_CACHE_MCASTIF "shared-cache-if"
#endif

#define FMT_STR "%s = %s\n"
#define FMT_QSTR "%s = \"%s\"\n"
#define FMT_ISTR "%s = %d\n"

#define CONFIG_BUF_SIZE 1024
#define CFG_PARAM_CFGFILE 10000

#define CFG_CONFIG "config"

extern FILE *yyin;
extern int yyparse(hitch_config *);

void cfg_cert_file_free(struct cfg_cert_file **cfptr);

// END: configuration parameters

static char error_buf[CONFIG_BUF_SIZE];
static char tmp_buf[150];

/* declare static printf like functions: */
static void config_error_set(char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static void
config_error_set(char *fmt, ...)
{
	int len;
	char buf[CONFIG_BUF_SIZE] = "";

	va_list args;
	va_start(args, fmt);
	len = vsnprintf(buf, (sizeof(buf) - 1), fmt, args);
	va_end(args);

	len += 1;
	if (len > CONFIG_BUF_SIZE)
		len = CONFIG_BUF_SIZE;
	memcpy(error_buf, buf, len);
}

const char *
config_error_get(void)
{
	return error_buf;
}

struct front_arg *
front_arg_new(void)
{
	struct front_arg *fa;

	ALLOC_OBJ(fa, FRONT_ARG_MAGIC);
	AN(fa);
	fa->match_global_certs = -1;
	fa->sni_nomatch_abort = -1;
	fa->selected_protos = 0;
	fa->prefer_server_ciphers = -1;

	return (fa);
}

void
front_arg_destroy(struct front_arg *fa)
{
	struct cfg_cert_file *cf, *cftmp;

	CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);
	free(fa->ip);
	free(fa->port);
	free(fa->pspec);
	free(fa->ciphers);
	HASH_ITER(hh, fa->certs, cf, cftmp) {
		CHECK_OBJ_NOTNULL(cf, CFG_CERT_FILE_MAGIC);
		HASH_DEL(fa->certs, cf);
		cfg_cert_file_free(&cf);
	}
	FREE_OBJ(fa);
}

hitch_config *
config_new(void)
{
	int i;
	hitch_config *r;
	struct front_arg *fa;

	r = calloc(1, sizeof(hitch_config));
	AN(r);

	(void) i;
	// set default values

	r->PMODE              = SSL_SERVER;
	r->SELECTED_TLS_PROTOS= 0;
	r->WRITE_IP_OCTET     = 0;
	r->WRITE_PROXY_LINE_V1= 0;
	r->WRITE_PROXY_LINE_V2= 0;
	r->PROXY_PROXY_LINE   = 0;
	r->ALPN_PROTOS        = NULL;
	r->ALPN_PROTOS_LV     = NULL;
	r->ALPN_PROTOS_LV_LEN = 0;
	r->CHROOT             = NULL;
	r->UID                = -1;
	r->GID                = -1;
	r->BACK_IP            = strdup("127.0.0.1");
	r->BACK_PORT          = strdup("8000");
	r->NCORES             = 1;
	r->CIPHER_SUITE       = strdup("EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH");
	r->ENGINE             = NULL;
	r->BACKLOG            = 100;
	r->SNI_NOMATCH_ABORT  = 0;
	r->CERT_DEFAULT	      = NULL;
	r->CERT_FILES         = NULL;
	r->LISTEN_ARGS        = NULL;
	fa = front_arg_new();
	fa->port = strdup("8443");
	fa->pspec = strdup("default");
	HASH_ADD_KEYPTR(hh, r->LISTEN_ARGS, fa->pspec, strlen(fa->pspec), fa);
	r->LISTEN_DEFAULT = fa;
	r->OCSP_DIR           = strdup("/var/lib/hitch/");
	r->OCSP_VFY = 0;
	r->OCSP_RESP_TMO = 10.0;
	r->OCSP_CONN_TMO = 4.0;

#ifdef USE_SHARED_CACHE
	r->SHARED_CACHE       = 0;
	r->SHCUPD_IP          = NULL;
	r->SHCUPD_PORT        = NULL;

	for (i = 0 ; i < MAX_SHCUPD_PEERS; i++)
		memset(&r->SHCUPD_PEERS[i], 0, sizeof(shcupd_peer_opt));

	r->SHCUPD_MCASTIF     = NULL;
	r->SHCUPD_MCASTTTL    = NULL;
#endif

	r->QUIET              = 0;
	r->SYSLOG             = 0;
	r->SYSLOG_FACILITY    = LOG_DAEMON;
	r->TCP_KEEPALIVE_TIME = 3600;
	r->DAEMONIZE          = 0;
	r->PREFER_SERVER_CIPHERS = 0;
	r->TEST	              = 0;

	r->BACKEND_CONNECT_TIMEOUT = 30;
	r->SSL_HANDSHAKE_TIMEOUT = 30;

	r->RECV_BUFSIZE = -1;
	r->SEND_BUFSIZE = -1;

	r->LOG_FILENAME = NULL;
	r->PIDFILE = NULL;

	r->RING_SLOTS = 0;
	r->RING_DATA_LEN = 0;

	return (r);
}

void
config_destroy(hitch_config *cfg)
{
	// printf("config_destroy() in pid %d: %p\n", getpid(), cfg);
	struct front_arg *fa, *ftmp;
	struct cfg_cert_file *cf, *cftmp;
	if (cfg == NULL)
		return;

	// free all members!
	free(cfg->CHROOT);
	HASH_ITER(hh, cfg->LISTEN_ARGS, fa, ftmp) {
		CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);
		HASH_DEL(cfg->LISTEN_ARGS, fa);
		front_arg_destroy(fa);
	}
	free(cfg->BACK_IP);
	free(cfg->BACK_PORT);
	HASH_ITER(hh, cfg->CERT_FILES, cf, cftmp) {
		CHECK_OBJ_NOTNULL(cf, CFG_CERT_FILE_MAGIC);
		HASH_DEL(cfg->CERT_FILES, cf);
		cfg_cert_file_free(&cf);
	}

	if (cfg->CERT_DEFAULT != NULL)
		cfg_cert_file_free(&cfg->CERT_DEFAULT);

	free(cfg->CIPHER_SUITE);
	free(cfg->ENGINE);
	free(cfg->PIDFILE);
	free(cfg->OCSP_DIR);
	free(cfg->ALPN_PROTOS);
	free(cfg->ALPN_PROTOS_LV);

#ifdef USE_SHARED_CACHE
	free(cfg->SHCUPD_IP);
	free(cfg->SHCUPD_PORT);

	for (int i = 0; i < MAX_SHCUPD_PEERS; i++) {
		free(cfg->SHCUPD_PEERS[i].ip);
		free(cfg->SHCUPD_PEERS[i].port);
	}

	free(cfg->SHCUPD_MCASTIF);
	free(cfg->SHCUPD_MCASTTTL);
#endif
	free(cfg);
}

static char *
config_assign_str(char **dst, char *v)
{
	assert(v != NULL);

	if (strlen(v) <= 0)
		return(NULL);
	if (*dst != NULL)
		free(*dst);

	*dst = strdup(v);
	return (*dst);
}

static int
config_param_val_bool(char *val, int *res)
{
	assert(val != NULL);

	if (strcasecmp(val, CFG_BOOL_ON) == 0 || strcasecmp(val, "yes") == 0 ||
	    strcasecmp(val, "y") == 0 || strcasecmp(val, "true") == 0 ||
	    strcasecmp(val, "t") == 0 || strcasecmp(val, "1") == 0) {
		*res = 1;
	}

	return (1);
}

static int
config_param_host_port_wildcard(const char *str, char **addr,
    char **port, char **cert, int wildcard_okay)
{
	const char *cert_ptr = NULL;

	if (str == NULL) {
		config_error_set("Invalid/unset host/port string.");
		return (0);
	}

	if (strlen(str) > ADDR_LEN) {
		config_error_set("Host address too long.");
		return (0);
	}

	// address/port buffers
	char port_buf[PORT_LEN];
	char addr_buf[ADDR_LEN];

	memset(port_buf, '\0', sizeof(port_buf));
	memset(addr_buf, '\0', sizeof(addr_buf));

	// FORMAT IS: [address]:port
	if (*str != '[') {
		config_error_set("Invalid address string '%s'", str);
		return (0);
	}

	const char *ptr = str + 1;
	const char *x = strrchr(ptr, ']');
	if (x == NULL) {
		config_error_set("Invalid address '%s'.", str);
		return (0);
	}

	unsigned addrlen = x - ptr;
	// address
	if (addrlen >= sizeof(addr_buf)) {
		config_error_set("Invalid address '%s'.", str);
		return (0);
	}
	strncpy(addr_buf, ptr, addrlen);

	// port
	if (x[1] != ':' || x[2] == '\0') {
		config_error_set("Invalid port specifier in string '%s'.", str);
		return (0);
	}
	ptr = x + 2;
	x = strchr(ptr, '+');
	if (x == NULL)
		memcpy(port_buf, ptr, sizeof(port_buf) - 1);
	else
		memcpy(port_buf, ptr, (x - ptr));

	// cert
	if (cert && x)
		cert_ptr = x + 1;

	// printf("PARSED ADDR '%s', PORT '%s'\n", addr_buf, port_buf);

	int p = atoi(port_buf);
	if (p < 0 || p > 65536) {
		config_error_set("Invalid port number '%s'", port_buf);
		return (0);
	}

	if (strcmp(addr_buf, "*") == 0) {
		if (wildcard_okay) {
			free(*addr);
			*addr = NULL;
		}
		else {
			config_error_set(
			    "Invalid address: wildcards are not allowed.");
			return (0);
		}
	} else {
		*addr = strdup(addr_buf);
	}
	*port = strdup(port_buf);
	if (cert_ptr != NULL)
		*cert = strdup(cert_ptr);

	/* printf("ADDR FINAL: '%s', '%s', '%s'\n", *addr, *port, */
	/*     cert ? *cert : ""); */

	return (1);
}

static int
config_param_host_port(char *str, char **addr, char **port)
{
	return (config_param_host_port_wildcard(str, addr, port, NULL, 0));
}


static int
config_param_val_int(char *str, int *dst, int positive_only)
{
	int num;

	assert(str != NULL);
	num = atoi(str);

	if (positive_only && num < 0) {
		config_error_set("Not a positive number.");
		return (0);
	}

	*dst = num;
	return 1;
}

static int
config_param_val_long(char *str, long *dst, int positive_only)
{
	long num;
	assert(str != NULL);

	num = atol(str);

	if (positive_only && num <= 0) {
		config_error_set("Not a positive number.");
		return (0);
	}

	*dst = num;
	return (1);
}

static double
mtim2double(const struct stat *sb)
{
	double d = sb->st_mtime;

#if defined(HAVE_STRUCT_STAT_ST_MTIM)
	d += sb->st_mtim.tv_nsec * 1e-9;
#elif defined(HAVE_STRUCT_STAT_ST_MTIMESPEC)
	d += sb->st_mtimespec.tv_nsec * 1e-9;
#endif
	return (d);
}

struct cfg_cert_file *
cfg_cert_file_new(void)
{
	struct cfg_cert_file *cert;
	ALLOC_OBJ(cert, CFG_CERT_FILE_MAGIC);
	AN(cert);
	cert->ocsp_vfy = -1;
	return (cert);
}

void
cfg_cert_file_free(struct cfg_cert_file **cfptr)
{
	struct cfg_cert_file *cf;

	CHECK_OBJ_NOTNULL(*cfptr, CFG_CERT_FILE_MAGIC);
	cf = *cfptr;
	free(cf->filename);
	free(cf->ocspfn);
	FREE_OBJ(cf);
	*cfptr = NULL;
}

int
cfg_cert_vfy(struct cfg_cert_file *cf)
{
	struct stat st;

	CHECK_OBJ_NOTNULL(cf, CFG_CERT_FILE_MAGIC);
	AN(cf->filename);

	if (cf->filename == NULL || strlen(cf->filename) <= 0)
		return (0);

	if (stat(cf->filename, &st) != 0) {
		config_error_set("Unable to stat x509 "
		    "certificate PEM file '%s': %s", cf->filename,
		    strerror(errno));
		return (0);
	}
	if (!S_ISREG(st.st_mode)) {
		config_error_set("Invalid x509 certificate "
		    "PEM file '%s': Not a file.", cf->filename);
		return (0);
	}
	cf->mtim = mtim2double(&st);

	if (cf->ocspfn != NULL) {
		if (stat(cf->ocspfn, &st) == -1) {
			config_error_set("Unable to stat OCSP "
			    "stapling file '%s': %s", cf->ocspfn,
			    strerror(errno));
			return (0);
		}
		if (!S_ISREG(st.st_mode)) {
			config_error_set("Invalid OCSP stapling file "
			    "'%s': Not a file.", cf->ocspfn);
			return (0);
		}
		cf->ocsp_mtim = mtim2double(&st);
	}

	return (1);
}

void
cfg_cert_add(struct cfg_cert_file *cf, struct cfg_cert_file **dst)
{
	CHECK_OBJ_NOTNULL(cf, CFG_CERT_FILE_MAGIC);
	AN(dst);
	CHECK_OBJ_ORNULL(*dst, CFG_CERT_FILE_MAGIC);
	HASH_ADD_KEYPTR(hh, *dst, cf->filename, strlen(cf->filename), cf);
}

#ifdef USE_SHARED_CACHE
/* Parse mcast and ttl options */
static int
config_param_shcupd_mcastif(char *str, char **iface, char **ttl)
{
	char buf[150];
	char *sp;

	if (strlen(str) >= sizeof buf) {
		config_error_set("Invalid option for IFACE[,TTL]");
		return (0);
	}

	sp = strchr(str, ',');
	if (!sp) {
		if (!strcmp(str, "*"))
			*iface = NULL;
		else
			*iface = strdup(str);
		*ttl = NULL;
		return (1);
	}
	else if (!strncmp(str, "*", sp - str))
		*iface = NULL;
	else {
		*sp = 0;
		*iface = strdup(str);
	}
	*ttl = strdup(sp + 1);

	return (1);
}

static int
config_param_shcupd_peer(char *str, hitch_config *cfg)
{
	if (cfg == NULL) {
		config_error_set("Configuration pointer is NULL.");
		return (0);
	}

	// parse result
	int r = 1;

	// find place for new peer
	int offset = 0;
	int i = 0;
	for (i = 0; i < MAX_SHCUPD_PEERS; i++) {
		if (cfg->SHCUPD_PEERS[i].ip == NULL &&
		    cfg->SHCUPD_PEERS[i].port == NULL) {
			offset = i;
			break;
		}
	}
	if (i >= MAX_SHCUPD_PEERS) {
		config_error_set(
		    "Reached maximum number of shared cache update peers (%d).",
		    MAX_SHCUPD_PEERS
		);
		return (0);
	}

	// create place for new peer
	char *addr = malloc(ADDR_LEN);
	if (addr == NULL) {
		config_error_set(
		    "Unable to allocate memory for new shared cache update peer address: %s",
		    strerror(errno)
		);
		r = 0;
		goto outta_parse_peer;
	}
	memset(addr, '\0', ADDR_LEN);
	char *port = malloc(PORT_LEN);
	if (port == NULL) {
		config_error_set(
		    "Unable to allocate memory for new shared cache update peer port: %s",
		    strerror(errno)
		);
		r = 0;
		goto outta_parse_peer;
	}
	memset(port, '\0', PORT_LEN);

	// try to parse address
	if (! config_param_host_port(str, &addr, &port)) {
		r = 0;
		goto outta_parse_peer;
	}

	outta_parse_peer:

	if (! r) {
		free(addr);
		free(port);
	} else {
		cfg->SHCUPD_PEERS[offset].ip = addr;
		cfg->SHCUPD_PEERS[offset].port = port;
	}

	return (r);
}

#endif /* USE_SHARED_CACHE */

int
front_arg_add(hitch_config *cfg, struct front_arg *fa)
{
	struct vsb pspec;

	CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);
	if (cfg->LISTEN_DEFAULT != NULL) {
		/* drop default listen arg. */
		struct front_arg *def = NULL;
		HASH_FIND_STR(cfg->LISTEN_ARGS, "default", def);
		AN(def);
		HASH_DEL(cfg->LISTEN_ARGS, def);
		free(def->ip);
		free(def->port);
		free(def->pspec);
		FREE_OBJ(def);
		cfg->LISTEN_DEFAULT = NULL;
	}

	VSB_new(&pspec, NULL, 0, VSB_AUTOEXTEND);
	VSB_printf(&pspec, "[%s]:%s", fa->ip, fa->port);
	VSB_finish(&pspec);
	fa->pspec = VSB_data(&pspec);

	if (fa->port == NULL) {
		config_error_set("No port number specified "
		    "for frontend '%s'", fa->pspec);
		return (0);
	}

	HASH_ADD_KEYPTR(hh, cfg->LISTEN_ARGS, fa->pspec,
	    strlen(fa->pspec), fa);

	if (fa->match_global_certs == -1) {
		if (HASH_CNT(hh, fa->certs) == 0)
			fa->match_global_certs = 1;
		else
			fa->match_global_certs = 0;
	} else {
		if (HASH_CNT(hh, fa->certs) == 0
		    && fa->match_global_certs == 0) {
			config_error_set("No certificate configured "
			    "for frontend '%s'", fa->pspec);
			return (0);
		}
	}

	return (1);
}

int
config_param_validate(char *k, char *v, hitch_config *cfg,
    char *file, int line)
{
	int r = 1;
	struct stat st;

	assert(k != NULL);
	assert(v != NULL);
	assert(strlen(k) >= 2);

	if (strcmp(k, "tls") == 0) {
		cfg->SELECTED_TLS_PROTOS = TLS_OPTION_PROTOS;
	} else if (strcmp(k, "ssl") == 0) {
		cfg->SELECTED_TLS_PROTOS = SSL_OPTION_PROTOS;
	} else if (strcmp(k, CFG_CIPHERS) == 0) {
		if (strlen(v) > 0) {
			config_assign_str(&cfg->CIPHER_SUITE, v);
		}
	} else if (strcmp(k, CFG_SSL_ENGINE) == 0) {
		if (strlen(v) > 0) {
			config_assign_str(&cfg->ENGINE, v);
		}
	} else if (strcmp(k, CFG_PREFER_SERVER_CIPHERS) == 0) {
		r = config_param_val_bool(v, &cfg->PREFER_SERVER_CIPHERS);
	} else if (strcmp(k, CFG_FRONTEND) == 0) {
		struct front_arg *fa;
		struct cfg_cert_file *cert;
		char *certfile = NULL;

		fa = front_arg_new();
		r = config_param_host_port_wildcard(v,
		    &fa->ip, &fa->port, &certfile, 1);
		if (r != 0) {
			if (certfile != NULL) {
				cert = cfg_cert_file_new();
				config_assign_str(&cert->filename, certfile);
				r = cfg_cert_vfy(cert);
				if (r != 0)
					cfg_cert_add(cert, &fa->certs);
				else
					cfg_cert_file_free(&cert);
				free(certfile);
			}
			if (r != 0)
				r = front_arg_add(cfg, fa);
			else
				FREE_OBJ(fa);
		}
	} else if (strcmp(k, CFG_BACKEND) == 0) {
		free(cfg->BACK_PORT);
		free(cfg->BACK_IP);
		r = config_param_host_port(v, &cfg->BACK_IP, &cfg->BACK_PORT);
	} else if (strcmp(k, CFG_WORKERS) == 0) {
		r = config_param_val_long(v, &cfg->NCORES, 1);
	} else if (strcmp(k, CFG_BACKLOG) == 0) {
		r = config_param_val_int(v, &cfg->BACKLOG, 0);
	} else if (strcmp(k, CFG_KEEPALIVE) == 0) {
		r = config_param_val_int(v, &cfg->TCP_KEEPALIVE_TIME, 1);
	}
#ifdef USE_SHARED_CACHE
	else if (strcmp(k, CFG_SHARED_CACHE) == 0) {
		r = config_param_val_int(v, &cfg->SHARED_CACHE, 1);
	} else if (strcmp(k, CFG_SHARED_CACHE_LISTEN) == 0) {
		if (strlen(v) > 0)
			r = config_param_host_port_wildcard(v, &cfg->SHCUPD_IP,
			    &cfg->SHCUPD_PORT, NULL, 1);
	} else if (strcmp(k, CFG_SHARED_CACHE_PEER) == 0) {
		r = config_param_shcupd_peer(v, cfg);
	} else if (strcmp(k, CFG_SHARED_CACHE_MCASTIF) == 0) {
		r = config_param_shcupd_mcastif(v, &cfg->SHCUPD_MCASTIF,
		    &cfg->SHCUPD_MCASTTTL);
	}
#endif
	else if (strcmp(k, CFG_CHROOT) == 0) {
		if (strlen(v) > 0) {
			// check directory
			if (stat(v, &st) != 0) {
				config_error_set("Unable to stat directory"
				    " '%s': %s'.",v,strerror(errno));
				r = 0;
			} else {
				if (! S_ISDIR(st.st_mode)) {
					config_error_set("Bad chroot directory "
					    "'%s': Not a directory", v);
					r = 0;
				} else {
					config_assign_str(&cfg->CHROOT, v);
				}
			}
		}
	} else if (strcmp(k, CFG_USER) == 0) {
		if (strlen(v) > 0) {
			struct passwd *passwd;
			passwd = getpwnam(v);
			if (!passwd) {
				config_error_set("Invalid user '%s'.", v);
				r = 0;
			} else {
				cfg->UID = passwd->pw_uid;
				cfg->GID = passwd->pw_gid;
			}
		}
	} else if (strcmp(k, CFG_GROUP) == 0) {
		if (strlen(v) > 0) {
			struct group *grp;
			grp = getgrnam(v);
			if (!grp) {
				config_error_set("Invalid group '%s'.", v);
				r = 0;
			} else {
				cfg->GID = grp->gr_gid;
			}
		}
	} else if (strcmp(k, CFG_QUIET) == 0) {
		r = config_param_val_bool(v, &cfg->QUIET);
	} else if (strcmp(k, CFG_SYSLOG) == 0) {
		r = config_param_val_bool(v, &cfg->SYSLOG);
	} else if (strcmp(k, CFG_SYSLOG_FACILITY) == 0) {
		int facility = -1;
		r = 1;
#define SYSLOG_FAC(m, s)				\
		if (!strcmp(v, s))			\
			facility = m;
#include "sysl_tbl.h"
#undef SYSLOG_FAC
		if (facility != -1)
			cfg->SYSLOG_FACILITY = facility;
		else {
			config_error_set("Invalid facility '%s'.", v);
			r = 0;
		}
	} else if (strcmp(k, CFG_DAEMON) == 0) {
		r = config_param_val_bool(v, &cfg->DAEMONIZE);
	} else if (strcmp(k, CFG_WRITE_IP) == 0) {
		r = config_param_val_bool(v, &cfg->WRITE_IP_OCTET);
	} else if (strcmp(k, CFG_WRITE_PROXY) == 0) {
		r = config_param_val_bool(v, &cfg->WRITE_PROXY_LINE_V2);
	} else if (strcmp(k, CFG_WRITE_PROXY_V1) == 0) {
		r = config_param_val_bool(v, &cfg->WRITE_PROXY_LINE_V1);
	} else if (strcmp(k, CFG_WRITE_PROXY_V2) == 0) {
		r = config_param_val_bool(v, &cfg->WRITE_PROXY_LINE_V2);
	} else if (strcmp(k, CFG_PROXY_PROXY) == 0) {
		r = config_param_val_bool(v, &cfg->PROXY_PROXY_LINE);
	} else if (strcmp(k, CFG_ALPN_PROTOS) == 0) {
		if (strlen(v) > 0) {
			config_assign_str(&cfg->ALPN_PROTOS, v);
		}
	} else if (strcmp(k, CFG_PEM_FILE) == 0) {
		struct cfg_cert_file *cert;
		cert = cfg_cert_file_new();
		config_assign_str(&cert->filename, v);
		r = cfg_cert_vfy(cert);
		if (r != 0) {
			if (cfg->CERT_DEFAULT != NULL) {
				struct cfg_cert_file *tmp = cfg->CERT_DEFAULT;
				cfg_cert_add(tmp, &cfg->CERT_FILES);
			}
			cfg->CERT_DEFAULT = cert;
		} else
			cfg_cert_file_free(&cert);
	} else if (strcmp(k, CFG_BACKEND_CONNECT_TIMEOUT) == 0) {
		r = config_param_val_int(v, &cfg->BACKEND_CONNECT_TIMEOUT, 1);
	} else if (strcmp(k, CFG_SSL_HANDSHAKE_TIMEOUT) == 0) {
		r = config_param_val_int(v, &cfg->SSL_HANDSHAKE_TIMEOUT, 1);
	} else if (strcmp(k, CFG_RECV_BUFSIZE) == 0) {
		r = config_param_val_int(v, &cfg->RECV_BUFSIZE, 1);
	} else if (strcmp(k, CFG_SEND_BUFSIZE) == 0) {
		r = config_param_val_int(v, &cfg->SEND_BUFSIZE, 1);
	} else if (strcmp(k, CFG_LOG_FILENAME) == 0) {
		if (strlen(v) > 0) {
			config_assign_str(&cfg->LOG_FILENAME, v);
		}
	} else if (strcmp(k, CFG_PIDFILE) == 0) {
		if (strlen(v) > 0) {
			config_assign_str(&cfg->PIDFILE, v);
		}
	} else if (strcmp(k, CFG_RING_SLOTS) == 0) {
		r = config_param_val_int(v, &cfg->RING_SLOTS, 1);
	} else if (strcmp(k, CFG_RING_DATA_LEN) == 0) {
		r = config_param_val_int(v, &cfg->RING_DATA_LEN, 1);
	} else if (strcmp(k, CFG_SNI_NOMATCH_ABORT) == 0) {
		r = config_param_val_bool(v, &cfg->SNI_NOMATCH_ABORT);
	} else if (strcmp(k, CFG_OCSP_DIR) == 0) {
		config_assign_str(&cfg->OCSP_DIR, v);
	} else {
		fprintf(
			stderr,
			"Ignoring unknown configuration key '%s' in configuration file '%s', line %d\n",
			k, file, line
		);
	}

	if (!r) {
		if (file != NULL)
			config_error_set("Error in configuration file '%s', "
			    "line %d: %s\n", file, line, config_error_get());
		else
			config_error_set("Invalid parameter '%s': %s", k,
			    config_error_get());
		return (1);
	}

	return (0);
}

static int
config_file_parse(char *file, hitch_config *cfg)
{
	FILE *fp = NULL;
	int r = 0;

	AN(cfg);

	// should we read stdin?
	if (file == NULL || strlen(file) < 1 || strcmp(file, "-") == 0)
		fp = stdin;
	else
		fp = fopen(file, "r");

	if (fp == NULL) {
		config_error_set("Unable to open configuration file '%s': %s\n",
		    file, strerror(errno));
		return (1);
	}

	yyin = fp;
	do {
		if (yyparse(cfg) != 0) {
			r = 1;
			break;
		}
	} while (!feof(yyin));

	fclose(fp);
	return (r);
}

static char *
config_disp_str(char *str)
{
	return ((str == NULL) ? "" : str);
}

static char *
config_disp_bool(int v)
{
	return ((v > 0) ? CFG_BOOL_ON : "off");
}

static char *
config_disp_uid(uid_t uid)
{
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if (uid == 0 && geteuid() != 0)
		return (tmp_buf);
	struct passwd *pw = getpwuid(uid);
	if (pw) {
		strncpy(tmp_buf, pw->pw_name, sizeof(tmp_buf));
		tmp_buf[sizeof(tmp_buf) - 1] = '\0';
	}
	return (tmp_buf);
}

static char *
config_disp_gid (gid_t gid)
{
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if (gid == 0 && geteuid() != 0)
		return (tmp_buf);
	struct group *gr = getgrgid(gid);
	if (gr) {
		strncpy(tmp_buf, gr->gr_name, sizeof(tmp_buf));
		tmp_buf[sizeof(tmp_buf) - 1] = '\0';
	}
	return (tmp_buf);
}

static const char *
config_disp_hostport(char *host, char *port)
{
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if (host == NULL && port == NULL)
		return ("");

	strcat(tmp_buf, "[");
	if (host == NULL)
		strcat(tmp_buf, "*");
	else
		strncat(tmp_buf, host, 40);
	strcat(tmp_buf, "]:");
	strncat(tmp_buf, port, 5);
	return (tmp_buf);
}

static const char *
config_disp_log_facility (int facility)
{
	switch (facility)
	{
#define SYSLOG_FAC(m, s)			\
		case m:				\
			return (s);
#include "sysl_tbl.h"
#undef SYSLOG_FAC
		default:
			return ("UNKNOWN");
	}
}

void
config_print_usage_fd(char *prog, FILE *out)
{
	hitch_config *cfg;

	cfg = config_new();
	AN(cfg);

	if (out == NULL)
		out = stderr;
	fprintf(out, "Usage: %s [OPTIONS] PEM\n\n", basename(prog));
	fprintf(out, "This is hitch, The Scalable TLS Unwrapping Daemon.\n\n");
	fprintf(out, "CONFIGURATION:\n");
	fprintf(out, "\n");
	fprintf(out, "        --config=FILE      Load configuration from specified file.\n");
	fprintf(out, "\n");
	fprintf(out, "ENCRYPTION METHODS:\n");
	fprintf(out, "\n");
	fprintf(out, "      --tls                   TLSv1 (default. No SSLv3)\n");
	fprintf(out, "      --ssl                   SSLv3 (enables SSLv3)\n");
	fprintf(out, "  -c  --ciphers=SUITE         Sets allowed ciphers (Default: \"%s\")\n", config_disp_str(cfg->CIPHER_SUITE));
	fprintf(out, "  -e  --ssl-engine=NAME       Sets OpenSSL engine (Default: \"%s\")\n", config_disp_str(cfg->ENGINE));
	fprintf(out, "  -O  --prefer-server-ciphers Prefer server list order\n");
	fprintf(out, "\n");
	fprintf(out, "SOCKET:\n");
	fprintf(out, "\n");
	fprintf(out, "  --client                      Enable client proxy mode\n");
	fprintf(out, "  -b  --backend=[HOST]:PORT     Backend [connect] (default is \"%s\")\n", config_disp_hostport(cfg->BACK_IP, cfg->BACK_PORT));
	fprintf(out, "  -f  --frontend=[HOST]:PORT[+CERT]    Frontend [bind] (default is \"%s\")\n", config_disp_hostport(cfg->LISTEN_DEFAULT->ip, cfg->LISTEN_DEFAULT->port));
	fprintf(out, "                                (Note: brackets are mandatory in endpoint specifiers.)");

#ifdef USE_SHARED_CACHE
	fprintf(out, "\n");
	fprintf(out, "  -U  --shared-cache-listen=[HOST]:PORT\n");
	fprintf(out, "                              Accept cache updates on UDP (Default: \"%s\")\n", config_disp_hostport(cfg->SHCUPD_IP, cfg->SHCUPD_PORT));
	fprintf(out, "                              NOTE: This option requires enabled SSL session cache.\n");
	fprintf(out, "  -P  --shared-cache-peer=[HOST]:PORT\n");
	fprintf(out, "                              Send cache updates to specified peer\n");
	fprintf(out, "                              NOTE: This option can be specified multiple times.\n");
	fprintf(out, "  -M  --shared-cache-if=IFACE[,TTL]\n");
	fprintf(out, "                              Force iface and ttl to receive and send multicast updates\n");
#endif

	fprintf(out, "\n");
	fprintf(out, "PERFORMANCE:\n");
	fprintf(out, "\n");
	fprintf(out, "  -n  --workers=NUM          Number of worker processes (Default: %ld)\n", cfg->NCORES);
	fprintf(out, "  -B  --backlog=NUM          Set listen backlog size (Default: %d)\n", cfg->BACKLOG);
	fprintf(out, "  -k  --keepalive=SECS       TCP keepalive on client socket (Default: %d)\n", cfg->TCP_KEEPALIVE_TIME);

#ifdef USE_SHARED_CACHE
	fprintf(out, "  -C  --session-cache=NUM    Enable and set SSL session cache to specified number\n");
	fprintf(out, "                             of sessions (Default: %d)\n", cfg->SHARED_CACHE);
#endif

	fprintf(out, "\n");
	fprintf(out, "SECURITY:\n");
	fprintf(out, "\n");
	fprintf(out, "  -r  --chroot=DIR           Sets chroot directory (Default: \"%s\")\n", config_disp_str(cfg->CHROOT));
	fprintf(out, "  -u  --user=USER            Set uid/gid after binding the socket (Default: \"%s\")\n", config_disp_uid(cfg->UID));
	fprintf(out, "  -g  --group=GROUP          Set gid after binding the socket (Default: \"%s\")\n", config_disp_gid(cfg->GID));
	fprintf(out, "\n");
	fprintf(out, "LOGGING:\n");
	fprintf(out, "  -q  --quiet                Be quiet; emit only error messages\n");
	fprintf(out, "  -s  --syslog               Send log message to syslog in addition to stderr/stdout\n");
	fprintf(out, "  --syslog-facility=FACILITY Syslog facility to use (Default: \"%s\")\n", config_disp_log_facility(cfg->SYSLOG_FACILITY));
	fprintf(out, "\n");
	fprintf(out, "OTHER OPTIONS:\n");
	fprintf(out, "      --daemon               Fork into background and become a daemon (Default: %s)\n", config_disp_bool(cfg->DAEMONIZE));
	fprintf(out, "      --write-ip             Write 1 octet with the IP family followed by the IP\n");
	fprintf(out, "                             address in 4 (IPv4) or 16 (IPv6) octets little-endian\n");
	fprintf(out, "                             to backend before the actual data\n");
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->WRITE_IP_OCTET));
	fprintf(out, "      --write-proxy-v1       Write HaProxy's PROXY v1 (IPv4 or IPv6) protocol line\n" );
	fprintf(out, "                             before actual data\n");
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->WRITE_PROXY_LINE_V1));
	fprintf(out, "      --write-proxy-v2       Write HaProxy's PROXY v2 binary (IPv4 or IPv6)  protocol line\n" );
	fprintf(out, "                             before actual data\n");
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->WRITE_PROXY_LINE_V2));
	fprintf(out, "      --write-proxy          Equivalent to --write-proxy-v2. For PROXY version 1 use\n");
	fprintf(out, "                              --write-proxy-v1 explicitly\n");
	fprintf(out, "      --proxy-proxy          Proxy HaProxy's PROXY (IPv4 or IPv6) protocol line\n" );
	fprintf(out, "                             before actual data (PROXY v1 only)\n");
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->PROXY_PROXY_LINE));
	fprintf(out, "      --sni-nomatch-abort    Abort handshake when client "
			"submits an unrecognized SNI server name\n" );
	fprintf(out, "                             (Default: %s)\n",
			config_disp_bool(cfg->SNI_NOMATCH_ABORT));
	fprintf(out, "      --ocsp-dir=DIR         Set OCSP staple cache directory\n");
	fprintf(out, "                             This enables automated retrieval and stapling of OCSP responses\n");
	fprintf(out, "                             (Default: \"%s\")\n", config_disp_str(cfg->OCSP_DIR));
	fprintf(out, "\n");
	fprintf(out, "  -t  --test                 Test configuration and exit\n");
	fprintf(out, "  -p  --pidfile=FILE         PID file\n");
	fprintf(out, "  -V  --version              Print program version and exit\n");
	fprintf(out, "  -h  --help                 This help message\n");

	config_destroy(cfg);
}

static void
config_print_usage(char *prog)
{
	config_print_usage_fd(prog, stdout);
}

static int
create_alpn_callback_data(hitch_config *cfg, char **error)
{
	size_t i = 1, j, l;

	AN(cfg->ALPN_PROTOS);
	l = strlen(cfg->ALPN_PROTOS);
	cfg->ALPN_PROTOS_LV = malloc(l + 1);
	AN(cfg->ALPN_PROTOS_LV);

	// first remove spaces while copying to cfg->ALPN_PROTOS_LV
	for(j = 0; j < l; j++)
		if (!isspace(cfg->ALPN_PROTOS[j])) {
			cfg->ALPN_PROTOS_LV[i] = cfg->ALPN_PROTOS[j];
			i++;
		}

	l = i - 1; // same as before iff cfg->ALPN_PROTOS has no spaces
	i = 0; // location of next "length" byte
	for(j = 1; j <= l; j++) {
		if (cfg->ALPN_PROTOS_LV[j] == ',') {
			if (i + 1 == j) {
				*error = "alpn-protos has empty proto in list";
				return (0); // failure
			}
			if (j - i > 256) {
				free(cfg->ALPN_PROTOS_LV);
				cfg->ALPN_PROTOS_LV = NULL;
				*error = "alpn protocol too long";
				return (0);
			}
			cfg->ALPN_PROTOS_LV[i] = (unsigned char)(j - i - 1);
			i = j;
		}
	}
	if (i == j) {
		// alpn-protos ends with a comma - we let it slide
		cfg->ALPN_PROTOS_LV_LEN = l;
	} else {
		if (j - i > 256) {
			free(cfg->ALPN_PROTOS_LV);
			cfg->ALPN_PROTOS_LV = NULL;
			*error = "alpn protocol too long";
			return (0);
		}
		cfg->ALPN_PROTOS_LV[i] = (unsigned char)(j - i - 1);
		cfg->ALPN_PROTOS_LV_LEN = l + 1;
	}
	return (1); // ok!
}

int
config_parse_cli(int argc, char **argv, hitch_config *cfg, int *retval)
{
	static int tls = 0, ssl = 0;
	static int client = 0;
	int c, i;

	optind = 1;

	AN(retval);
	*retval = 0;

	struct option long_options[] = {
		{ CFG_CONFIG, 1, NULL, CFG_PARAM_CFGFILE },
		{ "tls", 0, &tls, 1},
		{ "ssl", 0, &ssl, 1},
		{ "client", 0, &client, 1},
		{ CFG_CIPHERS, 1, NULL, 'c' },
		{ CFG_PREFER_SERVER_CIPHERS, 0, NULL, 'O' },
		{ CFG_BACKEND, 1, NULL, 'b' },
		{ CFG_FRONTEND, 1, NULL, 'f' },
		{ CFG_WORKERS, 1, NULL, 'n' },
		{ CFG_BACKLOG, 1, NULL, 'B' },
#ifdef USE_SHARED_CACHE
		{ CFG_SHARED_CACHE, 1, NULL, 'C' },
		{ CFG_SHARED_CACHE_LISTEN, 1, NULL, 'U' },
		{ CFG_SHARED_CACHE_PEER, 1, NULL, 'P' },
		{ CFG_SHARED_CACHE_MCASTIF, 1, NULL, 'M' },
#endif
		{ CFG_PIDFILE, 1, NULL, 'p' },
		{ CFG_KEEPALIVE, 1, NULL, 'k' },
		{ CFG_CHROOT, 1, NULL, 'r' },
		{ CFG_USER, 1, NULL, 'u' },
		{ CFG_GROUP, 1, NULL, 'g' },
		{ CFG_QUIET, 0, NULL, 'q' },
		{ CFG_SYSLOG, 0, NULL, 's' },
		{ CFG_SYSLOG_FACILITY, 1, NULL, CFG_PARAM_SYSLOG_FACILITY },
		{ CFG_DAEMON, 0, &cfg->DAEMONIZE, 1 },
		{ CFG_WRITE_IP, 0, &cfg->WRITE_IP_OCTET, 1 },
		{ CFG_WRITE_PROXY_V1, 0, &cfg->WRITE_PROXY_LINE_V1, 1 },
		{ CFG_WRITE_PROXY_V2, 0, &cfg->WRITE_PROXY_LINE_V2, 1 },
		{ CFG_WRITE_PROXY, 0, &cfg->WRITE_PROXY_LINE_V2, 1 },
		{ CFG_PROXY_PROXY, 0, &cfg->PROXY_PROXY_LINE, 1 },
		{ CFG_ALPN_PROTOS, 1, NULL, CFG_PARAM_ALPN_PROTOS },
		{ CFG_SNI_NOMATCH_ABORT, 0, &cfg->SNI_NOMATCH_ABORT, 1 },
		{ CFG_OCSP_DIR, 1, NULL, 'o' },
		{ "test", 0, NULL, 't' },
		{ "version", 0, NULL, 'V' },
		{ "help", 0, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
#define SHORT_OPTS "c:e:Ob:f:n:B:C:U:p:P:M:k:r:u:g:qstVho:"

	if (argc == 1) {
		config_print_usage(argv[0]);
		*retval = 0;
		return (1);
	}

	/* First do a pass over the args string to see if there was a
	 * config file present. If so, apply its options first in
	 * order to let them be overridden by the command line.  */
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, SHORT_OPTS,
			long_options, &option_index);
		if (c == -1)
			break;
		else if (c == '?') {
			config_error_set("Invalid command line parameters. "
			    "Run %s --help for instructions.",
			    basename(argv[0]));
			*retval = 1;
			return (1);
		}
		else if (c == CFG_PARAM_CFGFILE) {
			if (config_file_parse(optarg, cfg) != 0) {
				*retval = 1;
				return (1);
			}
		}
	}

	int tls_protos_config_file = cfg->SELECTED_TLS_PROTOS;

	optind = 1;
	while (1) {
		int ret = 0;
		int option_index = 0;
		c = getopt_long(argc, argv, SHORT_OPTS,
			long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case CFG_PARAM_CFGFILE:
			/* Handled above */
			break;
#define CFG_ARG(opt, key)							\
		case opt:							\
			ret = config_param_validate(key, optarg, cfg, NULL, 0);	\
			break;
#define CFG_ON(opt, key)							\
		case opt:							\
			ret = config_param_validate(key, CFG_BOOL_ON, cfg, 	\
			    NULL, 0);						\
			break;
CFG_ARG(CFG_PARAM_SYSLOG_FACILITY, CFG_SYSLOG_FACILITY);
CFG_ARG(CFG_PARAM_ALPN_PROTOS, CFG_ALPN_PROTOS);
CFG_ARG('c', CFG_CIPHERS);
CFG_ARG('e', CFG_SSL_ENGINE);
CFG_ARG('b', CFG_BACKEND);
CFG_ARG('f', CFG_FRONTEND);
CFG_ARG('n', CFG_WORKERS);
CFG_ARG('B', CFG_BACKLOG);
#ifdef USE_SHARED_CACHE
CFG_ARG('C', CFG_SHARED_CACHE);
CFG_ARG('U', CFG_SHARED_CACHE_LISTEN);
CFG_ARG('P', CFG_SHARED_CACHE_PEER);
CFG_ARG('M', CFG_SHARED_CACHE_MCASTIF);
#endif
CFG_ARG('p', CFG_PIDFILE);
CFG_ARG('k', CFG_KEEPALIVE);
CFG_ARG('r', CFG_CHROOT);
CFG_ARG('u', CFG_USER);
CFG_ARG('g', CFG_GROUP);
CFG_ARG('o', CFG_OCSP_DIR);
CFG_ON('O', CFG_PREFER_SERVER_CIPHERS);
CFG_ON('q', CFG_QUIET);
CFG_ON('s', CFG_SYSLOG);
#undef CFG_ARG
#undef CFG_ON
		case 't':
			cfg->TEST = 1;
			break;
		case 'V':
			printf("%s %s\n", basename(argv[0]), VERSION);
			*retval = 0;
			return (1);
			break;
		case 'h':
			config_print_usage(argv[0]);
			*retval = 0;
			return (1);
			break;

		default:
			config_error_set("Invalid command line parameters. "
			    "Run %s --help for instructions.",
			    basename(argv[0]));
			*retval = 1;
			return (1);
		}

		if (ret != 0) {
			*retval = 1;
			return (1);
		}
	}

	if ((tls || ssl) && tls_protos_config_file != 0) {
		config_error_set("Deprecated options --tls and --ssl cannot be"
		    " used to override tls-protos in a config file.");
		*retval = 1;
		return (1);
	}
	if (tls && ssl) {
		config_error_set("Options --tls and --ssl are mutually"
		    " exclusive.");
		*retval = 1;
		return (1);
	} else {
		if (ssl)
			cfg->SELECTED_TLS_PROTOS = SSL_OPTION_PROTOS;
		else if (tls)
			cfg->SELECTED_TLS_PROTOS = TLS_OPTION_PROTOS;
	}
	if (cfg->SELECTED_TLS_PROTOS == 0)
		cfg->SELECTED_TLS_PROTOS = DEFAULT_TLS_PROTOS;

	if (client)
		cfg->PMODE = SSL_CLIENT;

	if ((!!cfg->WRITE_IP_OCTET + !!cfg->PROXY_PROXY_LINE +
		!!cfg->WRITE_PROXY_LINE_V1 + !!cfg->WRITE_PROXY_LINE_V2) >= 2) {
		config_error_set("Options --write-ip, --write-proxy-proxy,"
		    " --write-proxy-v1 and --write-proxy-v2 are"
		    " mutually exclusive.");
		*retval = 1;
		return (1);
	}


	if (cfg->DAEMONIZE) {
		cfg->SYSLOG = 1;
		cfg->QUIET = 1;
	}

#ifdef USE_SHARED_CACHE
	if (cfg->SHCUPD_IP != NULL && ! cfg->SHARED_CACHE) {
		config_error_set("Shared cache update listener is defined,"
		    " but shared cache is disabled.");
		*retval = 1;
		return (1);
	}
#endif

	/* ALPN/NPN protocol negotiation additional configuration and error
	   handling */
	if (cfg->ALPN_PROTOS != NULL) {
		char *error;
		if (!create_alpn_callback_data(cfg, &error)) {
			if (error)
				config_error_set("alpn-protos configuration"
				    " \"%s\" is bad. %s",
				    cfg->ALPN_PROTOS, error);
			else
				config_error_set("alpn-protos configuration"
				    " \"%s\" is bad. See man page for more"
				    " info.",
				    cfg->ALPN_PROTOS);
			*retval = 1;
			return (1);
		}
		AN(cfg->ALPN_PROTOS_LV);
		int multi_proto =
		    cfg->ALPN_PROTOS_LV[0] != cfg->ALPN_PROTOS_LV_LEN - 1;
		if (multi_proto && !cfg->WRITE_PROXY_LINE_V2) {
			config_error_set("alpn-protos is specified with"
			    " more than one protocol while proxy-v2 is "
			    " not selected. This is a configuration"
			    " error.");
			*retval = 1;
			return (1);
			/* Note that this test was carried out indepenently of
			   the availability of ALPN / NPN */
		}
#if defined(OPENSSL_WITH_NPN) || defined(OPENSSL_WITH_ALPN)
		/*
		if (cfg->WRITE_PROXY_LINE_V2)
			fprintf(stderr, ALPN_NPN_PREFIX_STR
			    " Negotiated protocol will be communicated to the"
			    " backend.\n");
		*/
#ifndef OPENSSL_WITH_ALPN
		fprintf(stderr, ALPN_NPN_PREFIX_STR " Warning: Hitch has been"
		    " compiled against a version of OpenSSL without ALPN"
		    " support.\n");
#endif
#else
		/* No support for ALPN / NPN support in OpenSSL */
		if (multi_proto ||
		    0 != strncmp(cfg->ALPN_PROTOS_LV, "\x8http/1.1", 9)) {
			config_error_set("This is compiled against OpenSSL version"
			    " %lx, which does not have NPN or ALPN support,"
			    " yet alpn-protos has been set to %s.",
			    OPENSSL_VERSION_NUMBER, cfg->ALPN_PROTOS);
			*retval = 1;
			return (1);
		}
		else
			fprintf(stderr, "This is compiled against OpenSSL version"
			    " %lx, which does not have NPN or ALPN support."
			    " alpn-protos setting \"http/1.1\" will be ignored.\n",
			    OPENSSL_VERSION_NUMBER);
#endif
	}

	// Any arguments left are presumed to be PEM files
	argc -= optind;
	argv += optind;
	for (i = 0; i < argc; i++) {
		if (config_param_validate(CFG_PEM_FILE, argv[i], cfg, NULL, 0)) {
			*retval = 1;
			return (1);
		}
	}

	if (cfg->PMODE == SSL_SERVER && cfg->CERT_DEFAULT == NULL) {
		struct front_arg *fa, *fatmp;
		HASH_ITER(hh, cfg->LISTEN_ARGS, fa, fatmp)
			if (HASH_CNT(hh, fa->certs) == 0) {
				config_error_set("No x509 certificate PEM file "
				    "specified for frontend '%s'!", fa->pspec);
				*retval = 1;
				return (1);
			}
	}

	if (cfg->OCSP_DIR != NULL) {
		struct stat sb;

		if (stat(cfg->OCSP_DIR, &sb) != 0) {
			fprintf(stderr,
			    "{ocsp} Warning: Unable to stat directory '%s': %s'."
			    " OCSP stapling will be disabled.\n",
			    cfg->OCSP_DIR, strerror(errno));
			free(cfg->OCSP_DIR);
			cfg->OCSP_DIR = NULL;
		} else {
			if (!S_ISDIR(sb.st_mode)) {
				fprintf(stderr, "{ocsp} Bad ocsp-dir "
				    "'%s': Not a directory."
				    " OCSP stapling will be disabled.\n", cfg->OCSP_DIR);
				free(cfg->OCSP_DIR);
				cfg->OCSP_DIR = NULL;
			}
		}
	}

	return (0);
}
