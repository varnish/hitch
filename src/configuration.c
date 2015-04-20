/**
 * configuration.c
 *
 * Author: Brane F. Gracnar
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <syslog.h>

#include "configuration.h"
#include "version.h"

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
#define CFG_PEM_FILE "pem-file"
#define CFG_PROXY_PROXY "proxy-proxy"

#ifdef USE_SHARED_CACHE
  #define CFG_SHARED_CACHE "shared-cache"
  #define CFG_SHARED_CACHE_LISTEN "shared-cache-listen"
  #define CFG_SHARED_CACHE_PEER "shared-cache-peer"
  #define CFG_SHARED_CACHE_MCASTIF "shared-cache-if"
#endif

#ifndef NO_CONFIG_FILE
  #define FMT_STR "%s = %s\n"
  #define FMT_QSTR "%s = \"%s\"\n"
  #define FMT_ISTR "%s = %d\n"

  #define CONFIG_MAX_LINES 10000
  #define CONFIG_BUF_SIZE 1024
  #define CFG_PARAM_CFGFILE 10000
  #define CFG_PARAM_DEFCFG 10001

  #define CFG_CONFIG "config"
  #define CFG_CONFIG_DEFAULT "default-config"
#endif
// END: configuration parameters

static char var_buf[CONFIG_BUF_SIZE];
static char val_buf[CONFIG_BUF_SIZE];
static char error_buf[CONFIG_BUF_SIZE];
static char tmp_buf[150];

// for testing configuration only
#include <openssl/ssl.h>
SSL_CTX * init_openssl();

static void config_error_set (char *fmt, ...) {
  memset(error_buf, '\0', sizeof(error_buf));
  va_list args;
  va_start(args, fmt);
  vsnprintf(error_buf, (sizeof(error_buf) - 1), fmt, args);
  va_end(args);
}

char * config_error_get (void) {
  return error_buf;
}

void config_die (char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fprintf(stderr, "\n");

  exit(1);
}

stud_config * config_new (void) {
  stud_config *r = NULL;
  r = malloc(sizeof(stud_config));
  if (r == NULL) {
    config_error_set("Unable to allocate memory for configuration structure: %s", strerror(errno));
    return NULL;
  }

  // set default values

  r->ETYPE              = ENC_TLS;
  r->PMODE              = SSL_SERVER;
  r->WRITE_IP_OCTET     = 0;
  r->WRITE_PROXY_LINE   = 0;
  r->PROXY_PROXY_LINE   = 0;
  r->CHROOT             = NULL;
  r->UID                = 0;
  r->GID                = 0;
  r->FRONT_IP           = NULL;
  r->FRONT_PORT         = strdup("8443");
  r->BACK_IP            = strdup("127.0.0.1");
  r->BACK_PORT          = strdup("8000");
  r->NCORES             = 1;
  r->CERT_FILES         = NULL;
  r->CIPHER_SUITE       = NULL;
  r->ENGINE             = NULL;
  r->BACKLOG            = 100;

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

  return r;
}

void config_destroy (stud_config *cfg) {
  // printf("config_destroy() in pid %d: %p\n", getpid(), cfg);
  if (cfg == NULL) return;

  // free all members!
  if (cfg->CHROOT != NULL) free(cfg->CHROOT);
  if (cfg->FRONT_IP != NULL) free(cfg->FRONT_IP);
  if (cfg->FRONT_PORT != NULL) free(cfg->FRONT_PORT);
  if (cfg->BACK_IP != NULL) free(cfg->BACK_IP);
  if (cfg->BACK_PORT != NULL) free(cfg->BACK_PORT);
  if (cfg->CERT_FILES != NULL) {
    struct cert_files *curr = cfg->CERT_FILES, *next;
    while (cfg->CERT_FILES != NULL) {
      next = curr->NEXT;
      free(curr);
      curr = next;
    }
  }
  if (cfg->CIPHER_SUITE != NULL) free(cfg->CIPHER_SUITE);
  if (cfg->ENGINE != NULL) free(cfg->ENGINE);

#ifdef USE_SHARED_CACHE
  if (cfg->SHCUPD_IP != NULL) free(cfg->SHCUPD_IP);
  if (cfg->SHCUPD_PORT != NULL) free(cfg->SHCUPD_PORT);

  for (int i = 0; i < MAX_SHCUPD_PEERS; i++) {
    if (cfg->SHCUPD_PEERS[i].ip != NULL)
      free(cfg->SHCUPD_PEERS[i].ip);
    if (cfg->SHCUPD_PEERS[i].port != NULL)
      free(cfg->SHCUPD_PEERS[i].port);
  }

  if (cfg->SHCUPD_MCASTIF != NULL) free(cfg->SHCUPD_MCASTIF);
  if (cfg->SHCUPD_MCASTTTL != NULL) free(cfg->SHCUPD_MCASTTTL);
#endif

  free(cfg);
}

char * config_get_param (char *str) {
  char *ptr;
  int i;

  if (str == NULL) return NULL;
  /** empty string? */
  if (strlen(str) < 1 || str[0] == '\n' || strcmp(str, "\r\n") == 0) return NULL;

  ptr = str;

  /** comments? */
  if (str[0] == '#') return NULL;
  /** first alpha character */
  while (ptr != NULL && ! isalpha(*ptr))
    ptr++;

  /** overwrite alpha chars */
  memset(var_buf, '\0', sizeof(var_buf));
  i = 0;
  while(ptr != NULL && (isalnum(*ptr) || *ptr == '-')) {
    var_buf[i] = *ptr;
    i++;
    ptr++;
  }

  if (strlen(var_buf) < 1) return NULL;
  return var_buf;
}

char * config_get_value (char *str) {
  char *ptr;
  int i = 0;

  if (str == NULL) return NULL;
  if (strlen(str) < 1) return NULL;

  /** find '=' char */
  ptr = str;
  while (ptr != NULL && (*ptr) != '=')
    ptr++;
  ptr++;

  /** skip whitespaces **/
  while (ptr != NULL && ! isgraph(*ptr))
    ptr++;

  /** no value found? */
  if (ptr == NULL) return NULL;

  /** overwrite alpha chars */
  memset(val_buf, '\0', sizeof(val_buf));
  while(ptr != NULL && isgraph(*ptr)) {
    val_buf[i++] = *ptr;
    ptr++;
  }

  if (strlen(val_buf) < 1) return NULL;
  return val_buf;
}

char * str_rtrim(char *str) {
  char *ptr;
  int   len;

  len = strlen(str);
  ptr = str + len - 1;
  while (ptr >= str && (isspace((int)*ptr ) || (char) *ptr == '"' || (char) *ptr == '\'')) --ptr;

  ptr[1] = '\0';

  return str;
}

char * str_ltrim(char *str) {
  char *ptr;
  int  len;

  for (ptr = str; (*ptr && (isspace((int)*ptr) || (char) *ptr == '"' || (char) *ptr == '\'')); ++ptr);

  len = strlen(ptr);
  memmove(str, ptr, len + 1);

  return str;
}

char * str_trim(char *str) {
  char *ptr;
  ptr = str_rtrim(str);
  str = str_ltrim(ptr);
  return str;
}

char * config_assign_str (char **dst, char *v) {
  if (*dst == NULL) {
    if (v != NULL && strlen(v) > 0)
      *dst = strdup(v);
  } else {
    if (v != NULL && strlen(v) > 0) {
      // we assume that there is enough room for v in *dst
      memset(*dst, '\0', strlen(v) + 1);
      memcpy(*dst, v, strlen(v));
    }
    else
      free(*dst);
  }
  return *dst;
}

int config_param_val_bool (char *val, int *res) {
  if (val == NULL) return 0;
  if (
    strcasecmp(val, CFG_BOOL_ON) == 0 ||
    strcasecmp(val, "yes") == 0 ||
    strcasecmp(val, "y") == 0 ||
    strcasecmp(val, "true") == 0 ||
    strcasecmp(val, "t") == 0 ||
    strcasecmp(val, "1") == 0) {
    *res = 1;
  }

  return 1;
}

char * config_param_val_str (char *val) {
  return strdup(val);
}

int config_param_host_port_wildcard (char *str, char **addr, char **port, int wildcard_okay) {
  int len = (str != NULL) ? strlen(str) : 0;
  if (str == NULL || ! len) {
    config_error_set("Invalid/unset host/port string.");
    return 0;
  }

  // address/port buffers
  char port_buf[PORT_LEN];
  char addr_buf[ADDR_LEN];

  memset(port_buf, '\0', sizeof(port_buf));
  memset(addr_buf, '\0', sizeof(addr_buf));

  // NEW FORMAT: [address]:port
  if (*str == '[') {
    char *ptr = str + 1;
    char *x = strrchr(ptr, ']');
    if (x == NULL) {
      config_error_set("Invalid address '%s'.", str);
      return 0;
    }

    // address
    memcpy(addr_buf, ptr, (x - ptr));

    // port
    x += 2;
    memcpy(port_buf, x, sizeof(port_buf) - 1);
  }
  // OLD FORMAT: address,port
  else {
    char *x = strrchr(str, ',');
    if (x == NULL) {
      config_error_set("Invalid address string '%s'", str);
      return 0;
    }
    // addr
    int addr_len = x - str;
    memcpy(addr_buf, str, addr_len);
    // port
    memcpy(port_buf, (++x), sizeof(port_buf));
  }

  // printf("PARSED ADDR '%s', PORT '%s'\n", addr_buf, port_buf);

  // check port
  int p = atoi(port_buf);
  if (p < 1 || p > 65536) {
    config_error_set("Invalid port number '%s'", port_buf);
    return 0;
  }

  // write
  if (strcmp(addr_buf, "*") == 0) {
    if (wildcard_okay)
      free(*addr);
    else {
      config_error_set("Invalid address: wildcards are not allowed.");
      return 0;
    }
  } else {
    //if (*addr != NULL) free(*addr);
    *addr = strdup(addr_buf);
  }
  // if (**port != NULL) free(*port);
  *port = strdup(port_buf);

  // printf("ADDR FINAL: '%s', '%s'\n", *addr, *port);

  return 1;
}

int config_param_host_port (char *str, char **addr, char **port) {
  return config_param_host_port_wildcard(str, addr, port, 0);
}

int config_param_val_int (char *str, int *dst) {
  *dst = (str != NULL) ? atoi(str) : 0;
  return 1;
}

int config_param_val_int_pos (char *str, int *dst) {
  int num = 0;
  if (str != NULL)
    num = atoi(str);

  if (num < 1) {
    config_error_set("Not a positive number.");
    return 0;
  }

  *dst = num;
  return 1;
}

int config_param_val_intl (char *str, long int *dst) {
  *dst = (str != NULL) ? atol(str) : 0;
  return 1;
}

int config_param_val_intl_pos (char *str, long int *dst) {
  long int num = 0;
  if (str != NULL)
    num = atol(str);

  if (num < 1) {
    config_error_set("Not a positive number.");
    return 0;
  }

  *dst = num;
  return 1;
}

#ifdef USE_SHARED_CACHE
/* Parse mcast and ttl options */
int config_param_shcupd_mcastif (char *str, char **iface, char **ttl) {
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

int config_param_shcupd_peer (char *str, stud_config *cfg) {
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
    if (cfg->SHCUPD_PEERS[i].ip == NULL && cfg->SHCUPD_PEERS[i].port == NULL) {
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

void config_param_validate (char *k, char *v, stud_config *cfg, char *file, int line) {
  int r = 1;
  struct stat st;

  if (strcmp(k, "tls") == 0) {
    cfg->ETYPE = ENC_TLS;
  }
  else if (strcmp(k, "ssl") == 0) {
    cfg->ETYPE = ENC_SSL;
  }
  else if (strcmp(k, CFG_CIPHERS) == 0) {
    if (v != NULL && strlen(v) > 0) {
      config_assign_str(&cfg->CIPHER_SUITE, v);
    }
  }
  else if (strcmp(k, CFG_SSL_ENGINE) == 0) {
    if (v != NULL && strlen(v) > 0) {
      config_assign_str(&cfg->ENGINE, v);
    }
  }
  else if (strcmp(k, CFG_PREFER_SERVER_CIPHERS) == 0) {
    r = config_param_val_bool(v, &cfg->PREFER_SERVER_CIPHERS);
  }
  else if (strcmp(k, CFG_FRONTEND) == 0) {
    r = config_param_host_port_wildcard(v, &cfg->FRONT_IP, &cfg->FRONT_PORT, 1);
  }
  else if (strcmp(k, CFG_BACKEND) == 0) {
    r = config_param_host_port(v, &cfg->BACK_IP, &cfg->BACK_PORT);
  }
  else if (strcmp(k, CFG_WORKERS) == 0) {
    r = config_param_val_intl_pos(v, &cfg->NCORES);
  }
  else if (strcmp(k, CFG_BACKLOG) == 0) {
    r = config_param_val_int(v, &cfg->BACKLOG);
    if (r && cfg->BACKLOG < -1) cfg->BACKLOG = -1;
  }
  else if (strcmp(k, CFG_KEEPALIVE) == 0) {
    r = config_param_val_int_pos(v, &cfg->TCP_KEEPALIVE_TIME);
  }
#ifdef USE_SHARED_CACHE
  else if (strcmp(k, CFG_SHARED_CACHE) == 0) {
    r = config_param_val_int(v, &cfg->SHARED_CACHE);
  }
  else if (strcmp(k, CFG_SHARED_CACHE_LISTEN) == 0) {
    if (v != NULL && strlen(v) > 0)
      r = config_param_host_port_wildcard(v, &cfg->SHCUPD_IP, &cfg->SHCUPD_PORT, 1);
  }
  else if (strcmp(k, CFG_SHARED_CACHE_PEER) == 0) {
    r = config_param_shcupd_peer(v, cfg);
  }
  else if (strcmp(k, CFG_SHARED_CACHE_MCASTIF) == 0) {
    r = config_param_shcupd_mcastif(v, &cfg->SHCUPD_MCASTIF, &cfg->SHCUPD_MCASTTTL);
  }
#endif
  else if (strcmp(k, CFG_CHROOT) == 0) {
    if (v != NULL && strlen(v) > 0) {
      // check directory
      if (stat(v, &st) != 0) {
        config_error_set("Unable to stat directory '%s': %s'.", v, strerror(errno));
        r = 0;
      } else {
        if (! S_ISDIR(st.st_mode)) {
          config_error_set("Bad chroot directory '%s': Not a directory.", v, strerror(errno));
          r = 0;
        } else {
          config_assign_str(&cfg->CHROOT, v);
        }
      }
    }
  }
  else if (strcmp(k, CFG_USER) == 0) {
    if (v != NULL && strlen(v) > 0) {
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
  }
  else if (strcmp(k, CFG_GROUP) == 0) {
    if (v != NULL && strlen(v) > 0) {
      struct group *grp;
      grp = getgrnam(v);
      if (!grp) {
        config_error_set("Invalid group '%s'.", v);
        r = 0;
      } else {
        cfg->GID = grp->gr_gid;
      }
    }
  }
  else if (strcmp(k, CFG_QUIET) == 0) {
    r = config_param_val_bool(v, &cfg->QUIET);
  }
  else if (strcmp(k, CFG_SYSLOG) == 0) {
    r = config_param_val_bool(v, &cfg->SYSLOG);
  }
  else if (strcmp(k, CFG_SYSLOG_FACILITY) == 0) {
    r = 1;
    if (!strcmp(v, "auth") || !strcmp(v, "authpriv"))
      cfg->SYSLOG_FACILITY = LOG_AUTHPRIV;
    else if (!strcmp(v, "cron"))
      cfg->SYSLOG_FACILITY = LOG_CRON;
    else if (!strcmp(v, "daemon"))
      cfg->SYSLOG_FACILITY = LOG_DAEMON;
    else if (!strcmp(v, "ftp"))
      cfg->SYSLOG_FACILITY = LOG_FTP;
    else if (!strcmp(v, "local0"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL0;
    else if (!strcmp(v, "local1"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL1;
    else if (!strcmp(v, "local2"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL2;
    else if (!strcmp(v, "local3"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL3;
    else if (!strcmp(v, "local4"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL4;
    else if (!strcmp(v, "local5"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL5;
    else if (!strcmp(v, "local6"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL6;
    else if (!strcmp(v, "local7"))
      cfg->SYSLOG_FACILITY = LOG_LOCAL7;
    else if (!strcmp(v, "lpr"))
      cfg->SYSLOG_FACILITY = LOG_LPR;
    else if (!strcmp(v, "mail"))
      cfg->SYSLOG_FACILITY = LOG_MAIL;
    else if (!strcmp(v, "news"))
      cfg->SYSLOG_FACILITY = LOG_NEWS;
    else if (!strcmp(v, "user"))
      cfg->SYSLOG_FACILITY = LOG_USER;
    else if (!strcmp(v, "uucp"))
      cfg->SYSLOG_FACILITY = LOG_UUCP;
    else {
      config_error_set("Invalid facility '%s'.", v);
      r = 0;
    }
  }
  else if (strcmp(k, CFG_DAEMON) == 0) {
    r = config_param_val_bool(v, &cfg->DAEMONIZE);
  }
  else if (strcmp(k, CFG_WRITE_IP) == 0) {
    r = config_param_val_bool(v, &cfg->WRITE_IP_OCTET);
  }
  else if (strcmp(k, CFG_WRITE_PROXY) == 0) {
    r = config_param_val_bool(v, &cfg->WRITE_PROXY_LINE);
  }
  else if (strcmp(k, CFG_PROXY_PROXY) == 0) {
    r = config_param_val_bool(v, &cfg->PROXY_PROXY_LINE);
  }
  else if (strcmp(k, CFG_PEM_FILE) == 0) {
    if (v != NULL && strlen(v) > 0) {
      if (stat(v, &st) != 0) {
        config_error_set("Unable to stat x509 certificate PEM file '%s': ", v, strerror(errno));
        r = 0;
      }
      else if (! S_ISREG(st.st_mode)) {
        config_error_set("Invalid x509 certificate PEM file '%s': Not a file.", v);
        r = 0;
      } else {
        struct cert_files *cert = calloc(1, sizeof(*cert));
        config_assign_str(&cert->CERT_FILE, v);
        cert->NEXT = cfg->CERT_FILES;
        cfg->CERT_FILES = cert;
      }
    }
  }
  else {
    fprintf(
      stderr,
      "Ignoring unknown configuration key '%s' in configuration file '%s', line %d\n",
      k, file, line
    );
  }

  if (! r) {
    if (file != NULL)
      config_die("Error in configuration file '%s', line %d: %s\n", file, line, config_error_get());
    else
      config_die("Invalid parameter '%s': %s", k, config_error_get());
  }
}

#ifndef NO_CONFIG_FILE
int config_file_parse (char *file, stud_config *cfg) {
  if (cfg == NULL)
    config_die("Undefined stud options; THIS IS A BUG!\n");

  char line[CONFIG_BUF_SIZE];
  FILE *fd = NULL;

  // should we read stdin?
  if (file == NULL || strlen(file) < 1 || strcmp(file, "-") == 0) {
    fd = stdin;
  } else {
    fd = fopen(file, "r");
  }
  if (fd == NULL)
      config_die("Unable to open configuration file '%s': %s\n", file, strerror(errno));

  // read config
  int i = 0;
  while (i < CONFIG_MAX_LINES) {
    memset(line, '\0', sizeof(line));
    if (fgets(line, (sizeof(line) - 1), fd) == NULL) break;
    i++;

    // get configuration key
    char *key, *val;
    key = config_get_param(line);
    if (key == NULL) continue;

    // get configuration key value...
    val = config_get_value(line);
    if (val == NULL) continue;
    str_trim(val);

    // printf("File '%s', line %d, key: '%s', value: '%s'\n", file, i, key, val);

    // validate configuration key => value
    config_param_validate(key, val, cfg, file, i);
  }

  fclose(fd);

  return 1;
}
#endif /* NO_CONFIG_FILE */

char * config_disp_str (char *str) {
  return (str == NULL) ? "" : str;
}

char * config_disp_bool (int v) {
  return (v > 0) ? CFG_BOOL_ON : "off";
}

char * config_disp_uid (uid_t uid) {
  memset(tmp_buf, '\0', sizeof(tmp_buf));
  if (uid == 0 && geteuid() != 0) return tmp_buf;
  struct passwd *pw = getpwuid(uid);
  if (pw) {
    memcpy(tmp_buf, pw->pw_name, strlen(pw->pw_name));
  }
  return tmp_buf;
}

char * config_disp_gid (gid_t gid) {
  memset(tmp_buf, '\0', sizeof(tmp_buf));
  if (gid == 0 && geteuid() != 0) return tmp_buf;
  struct group *gr = getgrgid(gid);
  if (gr) {
    memcpy(tmp_buf, gr->gr_name, strlen(gr->gr_name));
  }
  return tmp_buf;
}

char * config_disp_hostport (char *host, char *port) {
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

const char * config_disp_log_facility (int facility) {
  switch (facility)
  {
    case LOG_AUTHPRIV:
      return "authpriv";
    case LOG_CRON:
      return "cron";
    case LOG_DAEMON:
      return "daemon";
    case LOG_FTP:
      return "ftp";
    case LOG_LOCAL0:
      return "local0";
    case LOG_LOCAL1:
      return "local1";
    case LOG_LOCAL2:
      return "local2";
    case LOG_LOCAL3:
      return "local3";
    case LOG_LOCAL4:
      return "local4";
    case LOG_LOCAL5:
      return "local5";
    case LOG_LOCAL6:
      return "local6";
    case LOG_LOCAL7:
      return "local7";
    case LOG_LPR:
      return "lpr";
    case LOG_MAIL:
      return "mail";
    case LOG_NEWS:
      return "news";
    case LOG_USER:
      return "user";
    case LOG_UUCP:
      return "uucp";
    default:
      return "UNKNOWN";
  }
}

void config_print_usage_fd (char *prog, stud_config *cfg, FILE *out) {
  if (out == NULL) out = stderr;
  fprintf(out, "Usage: %s [OPTIONS] PEM\n\n", basename(prog));
  fprintf(out, "This is stud, The Scalable TLS Unwrapping Daemon.\n\n");
#ifndef NO_CONFIG_FILE
  fprintf(out, "CONFIGURATION:\n");
  fprintf(out, "\n");
  fprintf(out, "        --config=FILE      Load configuration from specified file.\n");
  fprintf(out, "        --default-config   Prints default configuration to stdout.\n");
  fprintf(out, "\n");
#endif
  fprintf(out, "ENCRYPTION METHODS:\n");
  fprintf(out, "\n");
  fprintf(out, "      --tls                   TLSv1 (default)\n");
  fprintf(out, "      --ssl                   SSLv3 (implies no TLSv1)\n");
  fprintf(out, "  -c  --ciphers=SUITE         Sets allowed ciphers (Default: \"%s\")\n", config_disp_str(cfg->CIPHER_SUITE));
  fprintf(out, "  -e  --ssl-engine=NAME       Sets OpenSSL engine (Default: \"%s\")\n", config_disp_str(cfg->ENGINE));
  fprintf(out, "  -O  --prefer-server-ciphers Prefer server list order\n");
  fprintf(out, "\n");
  fprintf(out, "SOCKET:\n");
  fprintf(out, "\n");
  fprintf(out, "  --client                    Enable client proxy mode\n");
  fprintf(out, "  -b  --backend=HOST,PORT     Backend [connect] (default is \"%s\")\n", config_disp_hostport(cfg->BACK_IP, cfg->BACK_PORT));
  fprintf(out, "  -f  --frontend=HOST,PORT    Frontend [bind] (default is \"%s\")\n", config_disp_hostport(cfg->FRONT_IP, cfg->FRONT_PORT));

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
  fprintf(out, "      --write-proxy          Write HaProxy's PROXY (IPv4 or IPv6) protocol line\n" );
  fprintf(out, "                             before actual data\n");
  fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->WRITE_PROXY_LINE));
  fprintf(out, "      --proxy-proxy          Proxy HaProxy's PROXY (IPv4 or IPv6) protocol line\n" );
  fprintf(out, "                             before actual data\n");
  fprintf(out, "                             (Default: %s)\n", config_disp_bool(cfg->PROXY_PROXY_LINE));
  fprintf(out, "\n");
  fprintf(out, "  -t  --test                 Test configuration and exit\n");
  fprintf(out, "  -V  --version              Print program version and exit\n");
  fprintf(out, "  -h  --help                 This help message\n");
}

#ifndef NO_CONFIG_FILE
void config_print_default (FILE *fd, stud_config *cfg) {
  if (fd == NULL) return;
  fprintf(fd, "#\n");
  fprintf(fd, "# stud(8), The Scalable TLS Unwrapping Daemon's configuration\n");
  fprintf(fd, "#\n");
  fprintf(fd, "\n");
  fprintf(fd, "# NOTE: all config file parameters can be overriden\n");
  fprintf(fd, "#       from command line!\n");
  fprintf(fd, "\n");

  fprintf(fd, "# Listening address. REQUIRED.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, "# syntax: [HOST]:PORT\n");
  fprintf(fd, FMT_QSTR, CFG_FRONTEND, config_disp_hostport(cfg->FRONT_IP, cfg->FRONT_PORT));
  fprintf(fd, "\n");

  fprintf(fd, "# Upstream server address. REQUIRED.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, "# syntax: [HOST]:PORT.\n");
  fprintf(fd, FMT_QSTR, CFG_BACKEND, config_disp_hostport(cfg->BACK_IP, cfg->BACK_PORT));
  fprintf(fd, "\n");

  fprintf(fd, "# SSL x509 certificate file. REQUIRED.\n");
  fprintf(fd, "# List multiple certs to use SNI. Certs are used in the order they\n");
  fprintf(fd, "# are listed; the last cert listed will be used if none of the others match\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_PEM_FILE, "");
  fprintf(fd, "\n");

  fprintf(fd, "# SSL protocol.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# tls = on\n");
  fprintf(fd, "# ssl = off\n");
  fprintf(fd, "\n");

  fprintf(fd, "# List of allowed SSL ciphers.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# Run openssl ciphers for list of available ciphers.\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_CIPHERS, config_disp_str(cfg->CIPHER_SUITE));
  fprintf(fd, "\n");

  fprintf(fd, "# Enforce server cipher list order\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_PREFER_SERVER_CIPHERS, config_disp_bool(cfg->PREFER_SERVER_CIPHERS));
  fprintf(fd, "\n");

  fprintf(fd, "# Use specified SSL engine\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_SSL_ENGINE, config_disp_str(cfg->ENGINE));
  fprintf(fd, "\n");

  fprintf(fd, "# Number of worker processes\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: integer\n");
  fprintf(fd, FMT_ISTR, CFG_WORKERS, (int) cfg->NCORES);
  fprintf(fd, "\n");

  fprintf(fd, "# Listen backlog size\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: integer\n");
  fprintf(fd, FMT_ISTR, CFG_BACKLOG, cfg->BACKLOG);
  fprintf(fd, "\n");

  fprintf(fd, "# TCP socket keepalive interval in seconds\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: integer\n");
  fprintf(fd, FMT_ISTR, CFG_KEEPALIVE, cfg->TCP_KEEPALIVE_TIME);
  fprintf(fd, "\n");

#ifdef USE_SHARED_CACHE
  fprintf(fd, "# SSL session cache size\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: integer\n");
  fprintf(fd, FMT_ISTR, CFG_SHARED_CACHE, cfg->SHARED_CACHE);
  fprintf(fd, "\n");

  fprintf(fd, "# Accept shared SSL cache updates on specified listener.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, "# syntax: [HOST]:PORT\n");
  fprintf(fd, FMT_QSTR, CFG_SHARED_CACHE_LISTEN, config_disp_hostport(cfg->SHCUPD_IP, cfg->SHCUPD_PORT));
  fprintf(fd, "\n");

  fprintf(fd, "# Shared cache peer address.\n");
  fprintf(fd, "# Multiple stud processes on multiple hosts (host limit: %d)\n", MAX_SHCUPD_PEERS);
  fprintf(fd, "# can share SSL session cache by sending updates to peers.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# NOTE: This parameter can be specified multiple times in order\n");
  fprintf(fd, "#       to specify multiple peers.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, "# syntax: [HOST]:PORT\n");
  fprintf(fd, "# " FMT_QSTR, CFG_SHARED_CACHE_PEER, config_disp_hostport(NULL, NULL));
  for (int i = 0; i < MAX_SHCUPD_PEERS; i++) {
    if (cfg->SHCUPD_PEERS[i].ip == NULL && cfg->SHCUPD_PEERS[i].port == NULL) break;
    fprintf(fd, FMT_QSTR, CFG_SHARED_CACHE_PEER, config_disp_hostport(cfg->SHCUPD_PEERS[i].ip, cfg->SHCUPD_PEERS[i].port));
  }
  fprintf(fd, "\n");

  fprintf(fd, "# Shared cache interface name and optional TTL\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, "# syntax: iface[,TTL]\n");
  fprintf(fd, "# %s = \"%s", CFG_SHARED_CACHE_MCASTIF, config_disp_str(cfg->SHCUPD_MCASTIF));
  if (cfg->SHCUPD_MCASTTTL != NULL && strlen(cfg->SHCUPD_MCASTTTL) > 0) {
    fprintf(fd, ",%s", cfg->SHCUPD_MCASTTTL);
  }
  fprintf(fd, "\"\n");
  fprintf(fd, "\n");
#endif

  fprintf(fd, "# Chroot directory\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_CHROOT, config_disp_str(cfg->CHROOT));
  fprintf(fd, "\n");

  fprintf(fd, "# Set uid after binding a socket\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_USER, config_disp_uid(cfg->UID));
  fprintf(fd, "\n");

  fprintf(fd, "# Set gid after binding a socket\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_GROUP, config_disp_gid(cfg->GID));
  fprintf(fd, "\n");

  fprintf(fd, "# Quiet execution, report only error messages\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_QUIET, config_disp_bool(cfg->QUIET));
  fprintf(fd, "\n");

  fprintf(fd, "# Use syslog for logging\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_SYSLOG, config_disp_bool(cfg->SYSLOG));
  fprintf(fd, "\n");

  fprintf(fd, "# Syslog facility to use\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: string\n");
  fprintf(fd, FMT_QSTR, CFG_SYSLOG_FACILITY, config_disp_log_facility(cfg->SYSLOG_FACILITY));
  fprintf(fd, "\n");

  fprintf(fd, "# Run as daemon\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_DAEMON, config_disp_bool(cfg->DAEMONIZE));
  fprintf(fd, "\n");

  fprintf(fd, "# Report client address by writing IP before sending data\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# NOTE: This option is mutually exclusive with option %s and %s.\n", CFG_WRITE_PROXY, CFG_PROXY_PROXY);
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_WRITE_IP, config_disp_bool(cfg->WRITE_IP_OCTET));
  fprintf(fd, "\n");

  fprintf(fd, "# Report client address using SENDPROXY protocol, see\n");
  fprintf(fd, "# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt\n");
  fprintf(fd, "# for details.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# NOTE: This option is mutually exclusive with option %s and %s.\n", CFG_WRITE_IP, CFG_PROXY_PROXY);
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_WRITE_PROXY, config_disp_bool(cfg->WRITE_PROXY_LINE));
  fprintf(fd, "\n");

  fprintf(fd, "# Proxy an existing SENDPROXY protocol header through this request.\n");
  fprintf(fd, "#\n");
  fprintf(fd, "# NOTE: This option is mutually exclusive with option %s and %s.\n", CFG_WRITE_IP, CFG_WRITE_PROXY);
  fprintf(fd, "#\n");
  fprintf(fd, "# type: boolean\n");
  fprintf(fd, FMT_STR, CFG_PROXY_PROXY, config_disp_bool(cfg->PROXY_PROXY_LINE));
  fprintf(fd, "\n");

  fprintf(fd, "# EOF\n");
}
#endif /* NO_CONFIG_FILE */

void config_print_usage (char *prog, stud_config *cfg) {
  config_print_usage_fd(prog, cfg, stdout);
}

void config_parse_cli(int argc, char **argv, stud_config *cfg) {
  static int tls = 0, ssl = 0;
  static int client = 0;
  int c, i;
  int test_only = 0;
  char *prog;

  struct option long_options[] = {
#ifndef NO_CONFIG_FILE
    { CFG_CONFIG, 1, NULL, CFG_PARAM_CFGFILE },
    { CFG_CONFIG_DEFAULT, 0, NULL, CFG_PARAM_DEFCFG },
#endif

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
    { CFG_KEEPALIVE, 1, NULL, 'k' },
    { CFG_CHROOT, 1, NULL, 'r' },
    { CFG_USER, 1, NULL, 'u' },
    { CFG_GROUP, 1, NULL, 'g' },
    { CFG_QUIET, 0, NULL, 'q' },
    { CFG_SYSLOG, 0, NULL, 's' },
    { CFG_SYSLOG_FACILITY, 1, NULL, CFG_PARAM_SYSLOG_FACILITY },
    { CFG_DAEMON, 0, &cfg->DAEMONIZE, 1 },
    { CFG_WRITE_IP, 0, &cfg->WRITE_IP_OCTET, 1 },
    { CFG_WRITE_PROXY, 0, &cfg->WRITE_PROXY_LINE, 1 },
    { CFG_PROXY_PROXY, 0, &cfg->PROXY_PROXY_LINE, 1 },

    { "test", 0, NULL, 't' },
    { "version", 0, NULL, 'V' },
    { "help", 0, NULL, 'h' },
    { 0, 0, 0, 0 }
  };

  while (1) {
    int option_index = 0;
    c = getopt_long(
      argc, argv,
      "c:e:Ob:f:n:B:C:U:P:M:k:r:u:g:qstVh",
      long_options, &option_index
    );

    if (c == -1)
      break;

    switch (c) {
      case 0:
        break;
#ifndef NO_CONFIG_FILE
      case CFG_PARAM_CFGFILE:
        if (!config_file_parse(optarg, cfg))
          config_die("%s", config_error_get());
        break;
      case CFG_PARAM_DEFCFG:
        config_print_default(stdout, cfg);
        exit(0);
        break;
#endif
      case CFG_PARAM_SYSLOG_FACILITY:
        config_param_validate(CFG_SYSLOG_FACILITY, optarg, cfg, NULL, 0);
        break;
      case 'c':
        config_param_validate(CFG_CIPHERS, optarg, cfg, NULL, 0);
        break;
      case 'e':
        config_param_validate(CFG_SSL_ENGINE, optarg, cfg, NULL, 0);
         break;
      case 'O':
        config_param_validate(CFG_PREFER_SERVER_CIPHERS, CFG_BOOL_ON, cfg, NULL, 0);
        break;
      case 'b':
        config_param_validate(CFG_BACKEND, optarg, cfg, NULL, 0);
        break;
      case 'f':
        config_param_validate(CFG_FRONTEND, optarg, cfg, NULL, 0);
        break;
      case 'n':
        config_param_validate(CFG_WORKERS, optarg, cfg, NULL, 0);
        break;
      case 'B':
        config_param_validate(CFG_BACKLOG, optarg, cfg, NULL, 0);
        break;
#ifdef USE_SHARED_CACHE
      case 'C':
        config_param_validate(CFG_SHARED_CACHE, optarg, cfg, NULL, 0);
        break;
      case 'U':
        config_param_validate(CFG_SHARED_CACHE_LISTEN, optarg, cfg, NULL, 0);
        break;
      case 'P':
        config_param_validate(CFG_SHARED_CACHE_PEER, optarg, cfg, NULL, 0);
        break;
      case 'M':
        config_param_validate(CFG_SHARED_CACHE_MCASTIF, optarg, cfg, NULL, 0);
        break;
#endif
      case 'k':
        config_param_validate(CFG_KEEPALIVE, optarg, cfg, NULL, 0);
        break;
      case 'r':
        config_param_validate(CFG_CHROOT, optarg, cfg, NULL, 0);
        break;
      case 'u':
        config_param_validate(CFG_USER, optarg, cfg, NULL, 0);
        break;
      case 'g':
        config_param_validate(CFG_GROUP, optarg, cfg, NULL, 0);
        break;
      case 'q':
        config_param_validate(CFG_QUIET, CFG_BOOL_ON, cfg, NULL, 0);
        break;
      case 's':
        config_param_validate(CFG_SYSLOG, CFG_BOOL_ON, cfg, NULL, 0);
        break;
      case 't':
        test_only = 1;
        break;
      case 'V':
        printf("%s %s\n", basename(argv[0]), STUD_VERSION);
        exit(0);
        break;
      case 'h':
        config_print_usage(argv[0], cfg);
        exit(0);
        break;

      default:
        config_die("Invalid command line parameters. Run %s --help for instructions.", basename(argv[0]));
    }
  }

  prog = argv[0];

  if (tls && ssl)
    config_die("Options --tls and --ssl are mutually exclusive.");
  else {
    if (ssl)
      cfg->ETYPE = ENC_SSL;
    else if (tls)
      cfg->ETYPE = ENC_TLS;
  }

  if (client) {
      cfg->PMODE = SSL_CLIENT;
  }

  if (cfg->WRITE_IP_OCTET && cfg->WRITE_PROXY_LINE)
    config_die("Options --write-ip and --write-proxy are mutually exclusive.");

  if (cfg->WRITE_PROXY_LINE && cfg->PROXY_PROXY_LINE)
    config_die("Options --write-proxy and --proxy-proxy are mutually exclusive.");

  if (cfg->WRITE_IP_OCTET && cfg->PROXY_PROXY_LINE)
    config_die("Options --write-ip and --proxy-proxy are mutually exclusive.");

  if (cfg->DAEMONIZE) {
    cfg->SYSLOG = 1;
    cfg->QUIET = 1;
  }

#ifdef USE_SHARED_CACHE
  if (cfg->SHCUPD_IP != NULL && ! cfg->SHARED_CACHE)
    config_die("Shared cache update listener is defined, but shared cache is disabled.");
#endif

  // Any arguments left are presumed to be PEM files
  argc -= optind;
  argv += optind;
  for (i = 0; i < argc; i++) {
    config_param_validate(CFG_PEM_FILE, argv[i], cfg, NULL, 0);
  }
  if (cfg->PMODE == SSL_SERVER && cfg->CERT_FILES == NULL) {
    config_die("No x509 certificate PEM file specified!");
  }

  // was this only a test?
  if (test_only) {
    fprintf(stderr, "Trying to initialize SSL contexts with your certificates");
    if (!init_openssl()) {
      config_die("Error initializing OpenSSL.");
    }
    printf("%s configuration looks ok.\n", basename(prog));
    exit(0);
  }
}
