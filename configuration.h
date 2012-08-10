/**
 * configuration.h
 *
 * Author: Brane F. Gracnar
 *
 */

#include <sys/types.h>

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

/* configuration structure */
struct __stud_config {
    ENC_TYPE ETYPE;
    PROXY_MODE PMODE;
    int WRITE_IP_OCTET;
    int WRITE_PROXY_LINE;
    int PROXY_PROXY_LINE;
    char *CHROOT;
    uid_t UID;
    gid_t GID;
    char *FRONT_IP;
    char *FRONT_PORT;
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
};

typedef struct __stud_config stud_config;

char * config_error_get (void);
stud_config * config_new (void);
void config_destroy (stud_config *cfg);
int config_file_parse (char *file, stud_config *cfg);
void config_parse_cli(int argc, char **argv, stud_config *cfg);
