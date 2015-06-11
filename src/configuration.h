/**
 * configuration.h
 *
 * Author: Brane F. Gracnar
 *
 */

#include <sys/types.h>
#include "vqueue.h"

#ifdef USE_SHARED_CACHE
  #include "shctx.h"

  #ifndef MAX_SHCUPD_PEERS
    #define MAX_SHCUPD_PEERS 15
  #endif

typedef struct shcupd_peer_opt {
     char *ip;
     char *port;
} shcupd_peer_opt;

#endif

typedef enum {
    ENC_TLS,
    ENC_SSL
} ENC_TYPE;

typedef enum {
    SSL_SERVER,
    SSL_CLIENT
} PROXY_MODE;

struct cert_files {
    char *CERT_FILE;
    struct cert_files *NEXT;
};

struct front_arg {
	unsigned		magic;
#define FRONT_ARG_MAGIC		0x07a16cb5
	char			*ip;
	char			*port;
	char			*cert;
	VTAILQ_ENTRY(front_arg)	list;
};

VTAILQ_HEAD(front_arg_head, front_arg);

/* configuration structure */
struct __hitch_config {
    ENC_TYPE ETYPE;
    PROXY_MODE PMODE;
    int WRITE_IP_OCTET;
    int WRITE_PROXY_LINE_V2;
    int WRITE_PROXY_LINE;
    int PROXY_PROXY_LINE;
    char *CHROOT;
    int UID;
    int GID;
    struct front_arg_head LISTEN_ARGS;
    struct front_arg *LISTEN_DEFAULT;
    char *BACK_IP;
    char *BACK_PORT;
    long NCORES;
    struct cert_files *CERT_FILES;
    char *CIPHER_SUITE;
    char *ENGINE;
    int BACKLOG;
#ifdef USE_SHARED_CACHE
    int SHARED_CACHE;
    char *SHCUPD_IP;
    char *SHCUPD_PORT;
    shcupd_peer_opt SHCUPD_PEERS[MAX_SHCUPD_PEERS+1];
    char *SHCUPD_MCASTIF;
    char *SHCUPD_MCASTTTL;
#endif
    int QUIET;
    int SYSLOG;
    int SYSLOG_FACILITY;
    int TCP_KEEPALIVE_TIME;
    int DAEMONIZE;
    int PREFER_SERVER_CIPHERS;
    int BACKEND_CONNECT_TIMEOUT;
    int SSL_HANDSHAKE_TIMEOUT;
    int RECV_BUFSIZE;
    int SEND_BUFSIZE;
    char* LOG_FILENAME;
    int RING_SLOTS;
    int RING_DATA_LEN;
    char *PIDFILE;
    int SNI_NOMATCH_ABORT;
};

typedef struct __hitch_config hitch_config;

char * config_error_get (void);
hitch_config * config_new (void);
void config_destroy (hitch_config *cfg);
int config_file_parse (char *file, hitch_config *cfg);
void config_parse_cli(int argc, char **argv, hitch_config *cfg);
