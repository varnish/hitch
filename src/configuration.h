/**
 * configuration.h
 *
 * Author: Brane F. Gracnar
 *
 */

#ifndef CONFIGURATION_H_INCLUDED
#define CONFIGURATION_H_INCLUDED

#include <sys/types.h>
#include <openssl/ssl.h>

#include "foreign/uthash.h"

/* This macro disables NPN even in openssl/ssl.h */
#ifdef OPENSSL_NO_NEXTPROTONEG
#  undef OPENSSL_WITH_NPN
#endif

#ifdef OPENSSL_WITH_ALPN
#  define ALPN_NPN_PREFIX_STR "{alpn}"
#else
#  ifdef OPENSSL_WITH_NPN
#    define ALPN_NPN_PREFIX_STR "{npn}"
#  endif
#endif

#ifdef USE_SHARED_CACHE
#  include "shctx.h"
#  ifndef MAX_SHCUPD_PEERS
#    define MAX_SHCUPD_PEERS 15
#  endif
typedef struct shcupd_peer_opt {
	char *ip;
	char *port;
} shcupd_peer_opt;
#endif

typedef enum {
#define TLS_PROTO(e, n, s)			\
	e = n,
#include "tls_proto_tbl.h"

} TLS_PROTOCOL;

#define DEFAULT_TLS_PROTOS (TLSv1_2_PROTO | TLSv1_3_PROTO)
#define TLS_OPTION_PROTOS \
	(TLSv1_0_PROTO | TLSv1_1_PROTO | DEFAULT_TLS_PROTOS)
#define SSL_OPTION_PROTOS (SSLv3_PROTO | TLS_OPTION_PROTOS)

typedef enum {
	SSL_SERVER,
	SSL_CLIENT
} PROXY_MODE;

struct cfg_cert_file {
	unsigned	magic;
#define CFG_CERT_FILE_MAGIC 0x58c280d2
	char 		*filename;
	char		*priv_key_filename;
	char		*ocspfn;
	double		ocsp_mtim;
	int		mark;
	int		ocsp_vfy;
	double		mtim;
	int		client_verify;
	char		*client_verify_ca;
	UT_hash_handle	hh;
};

struct front_arg {
	unsigned		magic;
#define FRONT_ARG_MAGIC		0x07a16cb5
	char			*ip;
	char			*port;
	struct cfg_cert_file	*certs;
	char			*pspec;
	int			match_global_certs;
	int			sni_nomatch_abort;
	int			prefer_server_ciphers;
	char			*ciphers_tlsv12;
	char			*ciphersuites_tlsv13;
	int			selected_protos;
	int			client_verify;
	char			*client_verify_ca;
	int			mark;
	UT_hash_handle		hh;
};

/* configuration structure */
struct __hitch_config {
	PROXY_MODE		PMODE;
	int			SELECTED_TLS_PROTOS;
	int			WRITE_IP_OCTET;
	int			WRITE_PROXY_LINE_V1;
	int			WRITE_PROXY_LINE_V2;
	int			PROXY_PROXY_LINE;
	unsigned		PROXY_TLV;
	unsigned		PROXY_AUTHORITY;
	unsigned		PROXY_CLIENT_CERT;
	char			*ALPN_PROTOS;
	unsigned char		*ALPN_PROTOS_LV;
	unsigned		ALPN_PROTOS_LV_LEN;
	char			*CHROOT;
	int			UID;
	int			GID;
	struct front_arg	*LISTEN_ARGS;
	struct front_arg	*LISTEN_DEFAULT;
	char			*BACK_IP;
	char			*BACK_PORT;
	char			*BACK_PATH;
	long			NCORES;
	struct cfg_cert_file	*CERT_FILES;
	struct cfg_cert_file	*CERT_DEFAULT;
	char			*CIPHERS_TLSv12;
	char			*CIPHERSUITES_TLSv13;
	int			CLIENT_VERIFY;
	char			*CLIENT_VERIFY_CA;
	char			*ENGINE;
	int			BACKLOG;
#ifdef USE_SHARED_CACHE
	int			SHARED_CACHE;
	char			*SHCUPD_IP;
	char			*SHCUPD_PORT;
	shcupd_peer_opt		SHCUPD_PEERS[MAX_SHCUPD_PEERS+1];
	char			*SHCUPD_MCASTIF;
	char			*SHCUPD_MCASTTTL;
#endif
	int			LOG_LEVEL;
	int			SYSLOG;
	int			SYSLOG_FACILITY;
	int			TCP_KEEPALIVE_TIME;
	int			BACKEND_REFRESH_TIME;
	int			DAEMONIZE;
	int			PREFER_SERVER_CIPHERS;
	int			BACKEND_CONNECT_TIMEOUT;
	int			SSL_HANDSHAKE_TIMEOUT;
	int			RECV_BUFSIZE;
	int			SEND_BUFSIZE;
	char			*LOG_FILENAME;
	int			RING_SLOTS;
	int			RING_DATA_LEN;
	char			*PIDFILE;
	int			SNI_NOMATCH_ABORT;
	int			TEST;
	char			*PEM_DIR;
	char			*PEM_DIR_GLOB;
	char			*ECDH_CURVE;
	int			OCSP_VFY;
	char			*OCSP_DIR;
	double			OCSP_RESP_TMO;
	double			OCSP_CONN_TMO;
	int			OCSP_REFRESH_INTERVAL;
	char 			*DEBUG_LISTEN_ADDR;
#ifdef TCP_FASTOPEN_WORKS
	int			TFO;
#endif
};

typedef struct __hitch_config hitch_config;

const char * config_error_get (void);
hitch_config * config_new (void);
void config_destroy (hitch_config *cfg);
int config_parse_cli(int argc, char **argv, hitch_config *cfg);

#endif  /* CONFIGURATION_H_INCLUDED */
