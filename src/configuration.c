/**
 * configuration.c
 *
 * Original author: Brane F. Gracnar
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
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

#include "config.h"
#include "miniobj.h"
#include "configuration.h"

#define AZ(foo)		do { assert((foo) == 0); } while (0)
#define AN(foo)		do { assert((foo) != 0); } while (0)

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
#define CFG_WRITE_XFF "write-xff"
#define CFG_READ_PROXY "read-proxy"
#define CFG_PEM_FILE "pem-file"
#define CFG_PEM_KEYPASS "pem-keypass"
#define CFG_PROXY_PROXY "proxy-proxy"
#define CFG_BACKEND_CONNECT_TIMEOUT "backend-connect-timeout"
#define CFG_SSL_HANDSHAKE_TIMEOUT "ssl-handshake-timeout"
#define CFG_RECV_BUFSIZE "recv-bufsize"
#define CFG_SEND_BUFSIZE "send-bufsize"
#define CFG_LOG_FILENAME "log-filename"
#define CFG_RING_SLOTS "ring-slots"
#define CFG_RING_DATA_LEN "ring-data-len"
#define CFG_PIDFILE "pidfile"
#define CFG_SNI_NOMATCH_ABORT "sni-nomatch-abort"

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

// END: configuration parameters

static char error_buf[CONFIG_BUF_SIZE];
static char tmp_buf[150];

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

char *
config_error_get(void)
{
	return error_buf;
}

hitch_config *
config_new(void)
{
	hitch_config *r;
	struct front_arg *fa;

	r = calloc(1, sizeof(hitch_config));
	AN(r);

	// set default values

	r->ETYPE              = ENC_TLS;
	r->PMODE              = SSL_SERVER;
	r->WRITE_IP_OCTET     = 0;
	r->WRITE_PROXY_LINE_V1= 0;
	r->WRITE_PROXY_LINE_V2= 0;
	r->PROXY_PROXY_LINE   = 0;
	r->WRITE_XFF_LINE     = 0;
	r->CHROOT             = NULL;
	r->UID                = -1;
	r->GID                = -1;
	r->BACK_IP            = strdup("127.0.0.1");
	r->BACK_PORT          = strdup("8000");
	r->NCORES             = 1;
	r->CIPHER_SUITE       = NULL;
	r->ENGINE             = NULL;
	r->BACKLOG            = 100;
	r->SNI_NOMATCH_ABORT  = 0;
	r->CERT_DEFAULT = NULL;
	r->CERT_FILES = NULL;
	r->LISTEN_ARGS = NULL;
	ALLOC_OBJ(fa, FRONT_ARG_MAGIC);
	fa->port = strdup("8443");
	fa->pspec = strdup("default");
	HASH_ADD_KEYPTR(hh, r->LISTEN_ARGS, fa->pspec, strlen(fa->pspec), fa);
	r->LISTEN_DEFAULT = fa;

#ifdef USE_SHARED_CACHE
	r->SHARED_CACHE       = 0;
	r->SHCUPD_IP          = NULL;
	r->SHCUPD_PORT        = NULL;

	for (int i = 0 ; i < MAX_SHCUPD_PEERS; i++)
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

	return r;
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
		free(fa->ip);
		free(fa->port);
		free(fa->pspec);
		CHECK_OBJ_ORNULL(fa->cert, CFG_CERT_FILE_MAGIC);
		if (fa->cert != NULL) {
			fa->cert->ref--;
			if (fa->cert->ref == 0) {
				free(fa->cert->filename);
				FREE_OBJ(fa->cert);
			}
		}
		FREE_OBJ(fa);
	}
	free(cfg->BACK_IP);
	free(cfg->BACK_PORT);
	HASH_ITER(hh, cfg->CERT_FILES, cf, cftmp) {
		CHECK_OBJ_NOTNULL(cf, CFG_CERT_FILE_MAGIC);
		HASH_DEL(cfg->CERT_FILES, cf);
		free(cf->filename);
		FREE_OBJ(cf);
	}

	if (cfg->CERT_DEFAULT != NULL) {
		free(cfg->CERT_DEFAULT->filename);
		FREE_OBJ(cfg->CERT_DEFAULT);
	}
	free(cfg->CIPHER_SUITE);
	free(cfg->ENGINE);
	free(cfg->PIDFILE);

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

int
config_parse_content(char *line, char **key, char **value)
{
	assert(line != NULL);

	if (line[0] == '#')
		return 1;  // NOOP

	if (strlen(line) < 1 || line[0] == '\n' || strcmp(line, "\r\n") == 0)
		return 1;

	while (*line != '\0' && isspace(*line)) line++;
	*key = line;
	while(*line != '\0' && (isalnum(*line) || *line == '-')) line++;
	if (*line == '\0' || *(line+1) == '\0')
		return -1;
	*line = '\0'; // key end.
	line++;

	while(*line != '\0' && (*line != '=')) line++;
	if (*line != '=')
		return -3;

	if (*line == '\0' || *(line+1) == '\0')
		return -1;
	line++;

	while(*line != '\0' && (isspace(*line) || *line == '"' || *line == '\'')) line++;
	if (*line == '\0')
		return -1;
	*value = line;

	while (*line != '\0' && *line != '"' && *line != '\'' && !isspace(*line)) line++;
	*line = '\0';  // value end.

	if (strlen(*key) <= 1 || strlen(*value) < 1)
		return -1;

	return(0);
}

char *
config_assign_str(char **dst, char *v)
{
	assert(v != NULL);

	if (strlen(v) <= 0) return(NULL);
	if (*dst != NULL)
		free(*dst);

	*dst = strdup(v);
	return *dst;
}

int
config_param_val_bool(char *val, int *res)
{
	assert(val != NULL);

	if (strcasecmp(val, CFG_BOOL_ON) == 0 || strcasecmp(val, "yes") == 0 ||
	    strcasecmp(val, "y") == 0 || strcasecmp(val, "true") == 0 ||
	    strcasecmp(val, "t") == 0 || strcasecmp(val, "1") == 0) {
		*res = 1;
	}

	return 1;
}

int
config_param_host_port_wildcard(const char *str, char **addr,
    char **port, char **cert, int wildcard_okay)
{
	const char *cert_ptr = NULL;

	if (str == NULL) {
		config_error_set("Invalid/unset host/port string.");
		return 0;
	}

	if (strlen(str) > ADDR_LEN) {
		config_error_set("Host address too long.");
		return 0;
	}

	// address/port buffers
	char port_buf[PORT_LEN];
	char addr_buf[ADDR_LEN];

	memset(port_buf, '\0', sizeof(port_buf));
	memset(addr_buf, '\0', sizeof(addr_buf));

	// NEW FORMAT: [address]:port
	if (*str == '[') {
		const char *ptr = str + 1;
		const char *x = strrchr(ptr, ']');
		if (x == NULL) {
			config_error_set("Invalid address '%s'.", str);
			return 0;
		}

		// address
		if ((unsigned)(x - ptr) >= sizeof(addr_buf)) {
			config_error_set("Invalid address '%s'.", str);
			return 0;
		}
		strncpy(addr_buf, ptr, (x - ptr));

		// port
		if (x[1] != ':' || x[2] == '\0') {
			config_error_set("Invalid port specifier in string '%s'.", str);
			return 0;
		}
		ptr = x + 2;
		x = strchr(ptr, '+');
		if (x == NULL)
			memcpy(port_buf, ptr, sizeof(port_buf) - 1);
		else
			memcpy(port_buf, ptr, (x - ptr));

		// cert
		if (cert && x) {
			cert_ptr = x + 1;
		}
	}
	// OLD FORMAT: address,port
	else {
		config_error_set("Invalid address string '%s'", str);
		return 0;
	}

	// printf("PARSED ADDR '%s', PORT '%s'\n", addr_buf, port_buf);

	int p = atoi(port_buf);
	if (p < 1 || p > 65536) {
		config_error_set("Invalid port number '%s'", port_buf);
		return 0;
	}

	if (strcmp(addr_buf, "*") == 0) {
		if (wildcard_okay)
			free(*addr);
		else {
			config_error_set("Invalid address: wildcards are not allowed.");
			return 0;
		}
	} else {
		*addr = strdup(addr_buf);
	}
	*port = strdup(port_buf);
	if (cert_ptr != NULL)
		*cert = strdup(cert_ptr);

	/* printf("ADDR FINAL: '%s', '%s', '%s'\n", *addr, *port, */
	/*     cert ? *cert : ""); */

	return 1;
}

int
config_param_host_port(char *str, char **addr, char **port)
{
	return config_param_host_port_wildcard(str, addr, port, NULL, 0);
}


int
config_param_val_int(char *str, int *dst, int positive_only)
{
	int num;

	assert(str != NULL);
	num = atoi(str);

	if (positive_only && num < 0) {
		config_error_set("Not a positive number.");
		return 0;
	}

	*dst = num;
	return 1;
}

int
config_param_val_long(char *str, long *dst, int positive_only)
{
	long num;
	assert(str != NULL);

	num = atol(str);

	if (positive_only && num <= 0) {
		config_error_set("Not a positive number.");
		return 0;
	}

	*dst = num;
	return 1;
}

int
config_param_pem_file(char *filename, struct cfg_cert_file **cfptr)
{
	struct stat st;
	struct cfg_cert_file *cert;

	*cfptr = NULL;

	if (strlen(filename) <= 0)
		return (0);

	if (stat(filename, &st) != 0) {
		config_error_set("Unable to stat x509 "
		    "certificate PEM file '%s': ", filename,
		    strerror(errno));
		return (0);
	}
	if (! S_ISREG(st.st_mode)) {
		config_error_set("Invalid x509 certificate "
		    "PEM file '%s': Not a file.", filename);
		return (0);
	}

	ALLOC_OBJ(cert, CFG_CERT_FILE_MAGIC);
	AN(cert);
	config_assign_str(&cert->filename, filename);
	cert->mtim = st.st_mtime;
#if defined(HAVE_STRUCT_STAT_ST_MTIM)
	cert->mtim += st.st_mtim.tv_nsec * 1e-9;
#elif defined(HAVE_STRUCT_STAT_ST_MTIMESPEC)
	cert->mtim += st.st_mtimespec.tv_nsec * 1e-9;
#endif


	*cfptr = cert;
	cert->ref++;
	return (1);

}
#ifdef USE_SHARED_CACHE
/* Parse mcast and ttl options */
int
config_param_shcupd_mcastif(char *str, char **iface, char **ttl)
{
	char buf[150];
	char *sp;

	if (strlen(str) >= sizeof buf) {
		config_error_set("Invalid option for IFACE[,TTL]");
		return 0;
	}

	sp = strchr(str, ',');
	if (!sp) {
		if (!strcmp(str, "*"))
			*iface = NULL;
		else
			*iface = str;
		*ttl = NULL;
		return 1;
	}
	else if (!strncmp(str, "*", sp - str)) {
		*iface = NULL;
	}
	else {
		*sp = 0;
		*iface = str;
	}
	*ttl = sp + 1;

	return 1;
}

int
config_param_shcupd_peer(char *str, hitch_config *cfg)
{
	if (cfg == NULL) {
		config_error_set("Configuration pointer is NULL.");
		return 0;
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
		return 0;
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
		if (addr != NULL) free(addr);
		if (port != NULL) free(port);
	} else {
		cfg->SHCUPD_PEERS[offset].ip = addr;
		cfg->SHCUPD_PEERS[offset].port = port;
	}

	return r;
}

#endif /* USE_SHARED_CACHE */

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
		cfg->ETYPE = ENC_TLS;
	} else if (strcmp(k, "ssl") == 0) {
		cfg->ETYPE = ENC_SSL;
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

		ALLOC_OBJ(fa, FRONT_ARG_MAGIC);
		r = config_param_host_port_wildcard(v,
		    &fa->ip, &fa->port, &certfile, 1);
		if (r != 0) {
			if (cfg->LISTEN_DEFAULT != NULL) {
				/* drop default listen arg. */
				struct front_arg *def = NULL;
				HASH_FIND_STR(cfg->LISTEN_ARGS, "default", def);
				AN(def);
				HASH_DEL(cfg->LISTEN_ARGS, def);
				free(def->ip);
				free(def->port);
				free(def->cert);
				free(def->pspec);
				FREE_OBJ(def);
				cfg->LISTEN_DEFAULT = NULL;
			}
			fa->pspec = strdup(v);
			HASH_ADD_KEYPTR(hh, cfg->LISTEN_ARGS, fa->pspec,
			    strlen(fa->pspec), fa);
			if (certfile != NULL) {
				r = config_param_pem_file(certfile, &cert);
				if (r != 0) {
					AN(cert);
					fa->cert = cert;
				}
				free(certfile);
			}
		} else {
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
					    "'%s': Not a directory.", v,
					    strerror(errno));
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
   } else if (strcmp(k, CFG_WRITE_XFF) == 0) {
		r = config_param_val_bool(v, &cfg->WRITE_XFF_LINE);
	} else if (strcmp(k, CFG_READ_PROXY) == 0) {
		    r = config_param_val_bool(v, &cfg->READ_PROXY_LINE);
	} else if (strcmp(k, CFG_PEM_FILE) == 0) {
		struct cfg_cert_file *cert;
		r = config_param_pem_file(v, &cert);
		if (r != 0) {
			AN(cert);
			if (cfg->CERT_DEFAULT != NULL) {
				struct cfg_cert_file *tmp = cfg->CERT_DEFAULT;
				HASH_ADD_KEYPTR(hh, cfg->CERT_FILES,
				    tmp->filename, strlen(tmp->filename),
				    tmp);
			}
			cfg->CERT_DEFAULT = cert;
		}
	} else if (strcmp(k, CFG_PEM_KEYPASS) == 0) {
		// this should only be null if we haven't hit the value yet.
		// if we hit it a second time it's an error
		if (cfg->PEM_KEYPASS == NULL) {
			config_assign_str(&cfg->PEM_KEYPASS, v);
		} else {
			config_error_set("Duplicate PEM private key passwords");
		}
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

int
config_file_parse(char *file, hitch_config *cfg)
{
	char line[CONFIG_BUF_SIZE];
	char *key, *value;
	FILE *fd = NULL;

	int r;

	AN(cfg);

	// should we read stdin?
	if (file == NULL || strlen(file) < 1 || strcmp(file, "-") == 0)
		fd = stdin;
	else
		fd = fopen(file, "r");

	if (fd == NULL) {
		config_error_set("Unable to open configuration file '%s': %s\n",
		    file, strerror(errno));
		return (1);
	}

	int i = 0;
	while (1) {
		if (fgets(line, sizeof(line)-1, fd) == NULL)
			break;
		i++;

		r = config_parse_content((char*)&line, &key, &value);
		if (r != 0) 	/* comments/blank lines */
			continue;
		// printf("File '%s', line %d, key: '%s', value: '%s'\n", file, i, key, value);

		if (config_param_validate(key, value, cfg, file, i) != 0) {
			fclose(fd);
			return (1);
		}
	}

	fclose(fd);
	return (0);
}

char *
config_disp_str(char *str)
{
	return (str == NULL) ? "" : str;
}

char *
config_disp_bool(int v)
{
	return (v > 0) ? CFG_BOOL_ON : "off";
}

char *
config_disp_uid(uid_t uid)
{
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if (uid == 0 && geteuid() != 0) return tmp_buf;
	struct passwd *pw = getpwuid(uid);
	if (pw) {
		memcpy(tmp_buf, pw->pw_name, strlen(pw->pw_name));
	}
	return tmp_buf;
}

char *
config_disp_gid (gid_t gid)
{
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if (gid == 0 && geteuid() != 0) return tmp_buf;
	struct group *gr = getgrgid(gid);
	if (gr) {
		memcpy(tmp_buf, gr->gr_name, strlen(gr->gr_name));
	}
	return tmp_buf;
}

char *
config_disp_hostport(char *host, char *port)
{
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if (host == NULL && port == NULL)
		return "";

	strcat(tmp_buf, "[");
	if (host == NULL)
		strcat(tmp_buf, "*");
	else {
		strncat(tmp_buf, host, 40);
	}
	strcat(tmp_buf, "]:");
	strncat(tmp_buf, port, 5);
	return tmp_buf;
}

const char *
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
			return "UNKNOWN";
	}
}

void
config_print_usage_fd(char *prog, hitch_config *cfg, FILE *out)
{
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
	fprintf(out, "  -U  --shared-cache-listen=HOST,PORT\n");
	fprintf(out, "                              Accept cache updates on UDP (Default: \"%s\")\n", config_disp_hostport(cfg->SHCUPD_IP, cfg->SHCUPD_PORT));
	fprintf(out, "                              NOTE: This option requires enabled SSL session cache.\n");
	fprintf(out, "  -P  --shared-cache-peer=HOST,PORT\n");
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
	fprintf(out, "      --write-xff            Write X-Forwarded-For header before actual data\n" );
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->WRITE_XFF_LINE));
	fprintf(out, "      --read-proxy           Read HAProxy's PROXY (IPv4 or IPv6) protocol line\n" );
	fprintf(out, "                             before actual data.  This address will be sent to\n");
	fprintf(out, "                             the backend if one of --write-ip or --write-proxy\n");
	fprintf(out, "                             is specified.\n");
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->READ_PROXY_LINE));
	fprintf(out, "      --proxy-proxy          Proxy HaProxy's PROXY (IPv4 or IPv6) protocol line\n" );
	fprintf(out, "                             before actual data (PROXY v1 only)\n");
	fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->PROXY_PROXY_LINE));
	fprintf(out, "      --sni-nomatch-abort    Abort handshake when client "
			"submits an unrecognized SNI server name\n" );
	fprintf(out, "                             (Default: %s)\n",
			config_disp_bool(cfg->SNI_NOMATCH_ABORT));
	fprintf(out, "\n");
	fprintf(out, "  -t  --test                 Test configuration and exit\n");
	fprintf(out, "  -p  --pidfile=FILE         PID file\n");
	fprintf(out, "  -V  --version              Print program version and exit\n");
	fprintf(out, "  -h  --help                 This help message\n");
}

void
config_print_usage(char *prog, hitch_config *cfg)
{
	config_print_usage_fd(prog, cfg, stdout);
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
		{ CFG_WRITE_XFF, 0, &cfg->WRITE_XFF_LINE, 1 },
		{ CFG_READ_PROXY, 0, &cfg->READ_PROXY_LINE, 1 },
		{ CFG_PROXY_PROXY, 0, &cfg->PROXY_PROXY_LINE, 1 },
		{ CFG_SNI_NOMATCH_ABORT, 0, &cfg->SNI_NOMATCH_ABORT, 1 },
		{ "test", 0, NULL, 't' },
		{ "version", 0, NULL, 'V' },
		{ "help", 0, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1) {
		config_print_usage(argv[0], cfg);
		*retval = 0;
		return (1);
	}

	while (1) {
		int ret = 0;
		int option_index = 0;
		c = getopt_long(argc, argv,
			"c:e:Ob:f:n:B:C:U:p:P:M:k:r:u:g:qstVh",
			long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case CFG_PARAM_CFGFILE:
			if (config_file_parse(optarg, cfg) != 0) {
				*retval = 1;
				return (1);
			}
			break;
		case CFG_PARAM_SYSLOG_FACILITY:
			ret = config_param_validate(CFG_SYSLOG_FACILITY, optarg, cfg, NULL, 0);
			break;
		case 'c':
			ret = config_param_validate(CFG_CIPHERS, optarg, cfg, NULL, 0);
			break;
		case 'e':
			ret = config_param_validate(CFG_SSL_ENGINE, optarg, cfg, NULL, 0);
			break;
		case 'O':
			ret = config_param_validate(CFG_PREFER_SERVER_CIPHERS, CFG_BOOL_ON, cfg, NULL, 0);
			break;
		case 'b':
			ret = config_param_validate(CFG_BACKEND, optarg, cfg, NULL, 0);
			break;
		case 'f':
			ret = config_param_validate(CFG_FRONTEND, optarg, cfg, NULL, 0);
			break;
		case 'n':
			ret = config_param_validate(CFG_WORKERS, optarg, cfg, NULL, 0);
			break;
		case 'B':
			ret = config_param_validate(CFG_BACKLOG, optarg, cfg, NULL, 0);
			break;
#ifdef USE_SHARED_CACHE
		case 'C':
			ret = config_param_validate(CFG_SHARED_CACHE, optarg, cfg, NULL, 0);
			break;
		case 'U':
			ret = config_param_validate(CFG_SHARED_CACHE_LISTEN, optarg, cfg, NULL, 0);
			break;
		case 'P':
			ret = config_param_validate(CFG_SHARED_CACHE_PEER, optarg, cfg, NULL, 0)s;
			break;
		case 'M':
			ret =config_param_validate(CFG_SHARED_CACHE_MCASTIF, optarg, cfg, NULL, 0);
			break;
#endif
		case 'p':
			ret = config_param_validate(CFG_PIDFILE, optarg, cfg, NULL, 0);
			break;
		case 'k':
			ret = config_param_validate(CFG_KEEPALIVE, optarg, cfg, NULL, 0);
			break;
		case 'r':
			ret = config_param_validate(CFG_CHROOT, optarg, cfg, NULL, 0);
			break;
		case 'u':
			ret = config_param_validate(CFG_USER, optarg, cfg, NULL, 0);
			break;
		case 'g':
			ret = config_param_validate(CFG_GROUP, optarg, cfg, NULL, 0);
			break;
		case 'q':
			ret = config_param_validate(CFG_QUIET, CFG_BOOL_ON, cfg, NULL, 0);
			break;
		case 's':
			ret = config_param_validate(CFG_SYSLOG, CFG_BOOL_ON, cfg, NULL, 0);
			break;
		case 't':
			cfg->TEST = 1;
			break;
		case 'V':
			printf("%s %s\n", basename(argv[0]), VERSION);
			*retval = 0;
			return (1);
			break;
		case 'h':
			config_print_usage(argv[0], cfg);
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

	if (tls && ssl) {
		config_error_set("Options --tls and --ssl are mutually"
		    " exclusive.");
		*retval = 1;
		return (1);
	} else {
		if (ssl)
			cfg->ETYPE = ENC_SSL;
		else if (tls)
			cfg->ETYPE = ENC_TLS;
	}

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
		config_error_set("No x509 certificate PEM file specified!");
		*retval = 1;
		return (1);
	}

	return (0);
}
