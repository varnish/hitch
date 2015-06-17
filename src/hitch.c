/**
  * Copyright 2015 Varnish Software AB
  * Copyright 2011 Bump Technologies, Inc. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without modification, are
  * permitted provided that the following conditions are met:
  *
  *    1. Redistributions of source code must retain the above copyright notice, this list of
  *       conditions and the following disclaimer.
  *
  *    2. Redistributions in binary form must reproduce the above copyright notice, this list
  *       of conditions and the following disclaimer in the documentation and/or other materials
  *       provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY BUMP TECHNOLOGIES, INC. ``AS IS'' AND ANY EXPRESS OR IMPLIED
  * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
  * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BUMP TECHNOLOGIES, INC. OR
  * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
  * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  * The views and conclusions contained in the software and documentation are those of the
  * authors and should not be interpreted as representing official policies, either expressed
  * or implied, of Bump Technologies, Inc.
  *
  **/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>
#include <grp.h>

#include <ctype.h>
#include <sched.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/asn1.h>
#include <ev.h>

#include "vqueue.h"
#include "ringbuffer.h"
#include "miniobj.h"
#include "shctx.h"
#include "vpf.h"
#include "configuration.h"

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

/* For Mac OS X */
#ifndef TCP_KEEPIDLE
# ifdef TCP_KEEPALIVE
#  define TCP_KEEPIDLE TCP_KEEPALIVE
# endif
#endif
#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

/* Do we have SNI support? */
#ifndef OPENSSL_NO_TLSEXT
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#define OPENSSL_NO_TLSEXT
#endif
#endif

/* Globals */
static struct ev_loop *loop;
static struct addrinfo *backaddr;
static pid_t master_pid;
static int child_num;
static pid_t *child_pids;
static SSL_CTX *default_ctx;
static SSL_SESSION *client_session;

struct listen_sock {
	unsigned			magic;
#define LISTEN_SOCK_MAGIC 		0x5b04e577
	VTAILQ_ENTRY(listen_sock)	list;
	ev_io				listener;
	int				sock;
	const char			*name;
	const char			*cert;
	SSL_CTX				*sctx;
	struct sockaddr_storage		addr;
};

VTAILQ_HEAD(listen_sock_head, listen_sock);

static struct listen_sock_head listen_socks;
static unsigned nlisten_socks;

#define LOG_REOPEN_INTERVAL 60
static FILE* logf;
static struct stat logf_st;
static time_t logf_check_t;

#ifdef USE_SHARED_CACHE
static ev_io shcupd_listener;
static int shcupd_socket;
struct addrinfo *shcupd_peers[MAX_SHCUPD_PEERS+1];
static unsigned char shared_secret[SHA_DIGEST_LENGTH];
#endif /*USE_SHARED_CACHE*/

#define AZ(foo)		do { assert((foo) == 0); } while (0)
#define AN(foo)		do { assert((foo) != 0); } while (0)

long openssl_version;
int create_workers;
hitch_config *CONFIG;
static struct vpf_fh *pfh = NULL;

static char tcp_proxy_line[128] = "";


/* What agent/state requests the shutdown--for proper half-closed
 * handling */
typedef enum _SHUTDOWN_REQUESTOR {
    SHUTDOWN_HARD,
    SHUTDOWN_CLEAR,
    SHUTDOWN_SSL
} SHUTDOWN_REQUESTOR;

#ifndef OPENSSL_NO_TLSEXT
/*
 * SSL context linked list. Someday it might be nice to have a more clever data
 * structure here, but assuming the number of SNI certs is small it probably
 * doesn't matter.
 */
typedef struct ctx_list {
	unsigned		magic;
#define CTX_LIST_MAGIC		0xc179597c
	char			*servername;
	int			is_wildcard;
	char			*filename;
	SSL_CTX			*ctx;
	VTAILQ_ENTRY(ctx_list)	list;
} ctx_list;


VTAILQ_HEAD(ctx_list_head, ctx_list);
static struct ctx_list_head sni_ctxs;
#endif /* OPENSSL_NO_TLSEXT */


union ha_proxy_v2_addr {
    struct {        /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
    } ipv4;
    struct {        /* for TCP/UDP over IPv6, len = 36 */
         uint8_t  src_addr[16];
         uint8_t  dst_addr[16];
         uint16_t src_port;
         uint16_t dst_port;
    } ipv6;
    struct {        /* for AF_UNIX sockets, len = 216 */
         uint8_t src_addr[108];
         uint8_t dst_addr[108];
    } unix;
};

struct ha_proxy_v2_hdr {
	uint8_t sig[12];
	uint8_t ver_cmd;
	uint8_t fam;
	uint16_t len;	/* number of following bytes part of the header */
	union ha_proxy_v2_addr addr;
};

/*
 * Proxied State
 *
 * All state associated with one proxied connection
 */
typedef struct proxystate {
    unsigned magic;
#define PROXYSTATE_MAGIC 0xcf877ed9
    ringbuffer ring_ssl2clear;          /* Pushing bytes from secure to clear stream */
    ringbuffer ring_clear2ssl;          /* Pushing bytes from clear to secure stream */

    ev_io ev_r_ssl;                     /* Secure stream write event */
    ev_io ev_w_ssl;                     /* Secure stream read event */

    ev_io ev_r_handshake;               /* Secure stream handshake write event */
    ev_io ev_w_handshake;               /* Secure stream handshake read event */
    ev_timer ev_t_handshake; /* handshake timer */

    ev_io ev_w_connect;                 /* Backend connect event */
    ev_timer ev_t_connect; /* backend connect timer */

    ev_io ev_r_clear;                   /* Clear stream write event */
    ev_io ev_w_clear;                   /* Clear stream read event */
    ev_io ev_proxy;                     /* proxy read event */

    int fd_up;                          /* Upstream (client) socket */
    int fd_down;                        /* Downstream (backend) socket */

    int want_shutdown:1;                /* Connection is half-shutdown */
    int handshaked:1;                   /* Initial handshake happened */
    int clear_connected:1;              /* Clear stream is connected  */
    int renegotiation:1;                /* Renegotation is occuring */

    SSL *ssl;                           /* OpenSSL SSL state */

    struct sockaddr_storage remote_ip;  /* Remote ip returned from `accept` */
    int connect_port;	/* local port for connection */
} proxystate;

static void VWLOG (int level, const char* fmt, va_list ap)
{
    if (logf) {
	struct timeval tv;
	struct tm tm;
	char buf[1024];
	int n;
	va_list ap1;

	gettimeofday(&tv,NULL);
	if (logf != stdout && logf != stderr && tv.tv_sec >= logf_check_t+LOG_REOPEN_INTERVAL) {
	    struct stat st;
	    if (stat(CONFIG->LOG_FILENAME, &st) < 0
		    || st.st_dev != logf_st.st_dev
		    || st.st_ino != logf_st.st_ino)
	    {
		fclose(logf);
		if ((logf = fopen(CONFIG->LOG_FILENAME, "a")) != NULL) {
		    fstat(fileno(logf), &logf_st);
		} else {
		    memset(&logf_st, 0, sizeof(logf_st));
		}
	    }
	    logf_check_t = tv.tv_sec;
	}

	localtime_r(&tv.tv_sec, &tm);
	n = strftime(buf, sizeof(buf), "%Y%m%dT%H%M%S", &tm);
	sprintf(buf+n, ".%06d [%5d] %s", (int)tv.tv_usec, getpid(), fmt);
	va_copy(ap1, ap);
	vfprintf(logf, buf, ap1);
    }
    if (CONFIG->SYSLOG) {
	vsyslog(level, fmt, ap);
    }
}

static void WLOG (int level, const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    VWLOG(level, fmt, ap);
    va_end(ap);
}

#define LOG(...)							\
	do {								\
		if (!CONFIG->QUIET)					\
			WLOG(LOG_INFO, __VA_ARGS__ );			\
	} while (0)
#define ERR(...)	WLOG(LOG_ERR, __VA_ARGS__ )


#define SOCKERR(msg)						\
	do {							\
		if (errno == ECONNRESET) {			\
			LOG(msg ": %s\n", strerror(errno));	\
		} else {					\
			ERR(msg ": %s\n", strerror(errno));	\
		}						\
	} while (0)


static void
logproxy (int level, const proxystate* ps, const char* fmt, ...)
{
    char buf[1024];
    char hbuf[INET6_ADDRSTRLEN+1];
    char sbuf[8];
    int n;
    va_list ap;
    socklen_t salen;

    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);

    salen = (ps->remote_ip.ss_family == AF_INET) ?
	sizeof(struct sockaddr) : sizeof(struct sockaddr_in6);
    n = getnameinfo((struct sockaddr *) &ps->remote_ip, salen, hbuf,
	sizeof hbuf, sbuf, sizeof sbuf, NI_NUMERICHOST | NI_NUMERICSERV);
    if (n != 0) {
	    strcpy(hbuf, "n/a");
	    strcpy(sbuf, "n/a");
    }

    va_start(ap, fmt);
    if (ps->remote_ip.ss_family == AF_INET)
	    snprintf(buf, sizeof(buf), "%s:%s :%d %d:%d %s",
		hbuf, sbuf, ps->connect_port, ps->fd_up, ps->fd_down, fmt);
    else
	    snprintf(buf, sizeof(buf), "[%s]:%s :%d %d:%d %s",
		hbuf, sbuf, ps->connect_port, ps->fd_up, ps->fd_down, fmt);
    VWLOG(level, buf, ap);
}

#define LOGPROXY(...)							\
	do {								\
		if (!CONFIG->QUIET && (logf || CONFIG->SYSLOG))		\
			logproxy(LOG_INFO, __VA_ARGS__ );		\
	} while(0)

#define ERRPROXY(...)							\
	do {								\
		if (logf || CONFIG->SYSLOG)				\
			logproxy(LOG_ERR, __VA_ARGS__ );		\
	} while (0)


#define NULL_DEV "/dev/null"

/* set a file descriptor (socket) to non-blocking mode */
static void setnonblocking(int fd) {
    int flag = 1;

    if (ioctl(fd, FIONBIO, &flag) < 0) {
	SOCKERR("Error setting FIONBIO");
    }
}


/* set a tcp socket to use TCP Keepalive */
static void settcpkeepalive(int fd) {
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        SOCKERR("Error activating SO_KEEPALIVE on client socket");
    }

    optval = CONFIG->TCP_KEEPALIVE_TIME;
    optlen = sizeof(optval);
#ifdef TCP_KEEPIDLE
    if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        SOCKERR("Error setting TCP_KEEPIDLE on client socket");
    }
#endif
}

static void fail(const char* s) {
    ERR("%s: %s\n", s, strerror(errno));
    exit(1);
}

void die (char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(1);
}

#ifndef OPENSSL_NO_DH
static int init_dh(SSL_CTX *ctx, const char *cert) {
    DH *dh;
    BIO *bio;

    assert(cert);

    bio = BIO_new_file(cert, "r");
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!dh) {
        ERR("{core} Note: no DH parameters found in %s\n", cert);
        return -1;
    }

    LOG("{core} Using DH parameters from %s\n", cert);
    SSL_CTX_set_tmp_dh(ctx, dh);
    LOG("{core} DH initialized with %d bit key\n", 8*DH_size(dh));
    DH_free(dh);

#ifndef OPENSSL_NO_EC
#ifdef NID_X9_62_prime256v1
    EC_KEY *ecdh = NULL;
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    LOG("{core} ECDH Initialized with NIST P-256\n");
#endif /* NID_X9_62_prime256v1 */
#endif /* OPENSSL_NO_EC */

    return 0;
}
#endif /* OPENSSL_NO_DH */

/* This callback function is executed while OpenSSL processes the SSL
 * handshake and does SSL record layer stuff.  It's used to trap
 * client-initiated renegotiations.
 */
static void info_callback(const SSL *ssl, int where, int ret) {
    proxystate *ps;
    (void)ret;
    if (where & SSL_CB_HANDSHAKE_START) {
        CAST_OBJ_NOTNULL(ps, SSL_get_app_data(ssl), PROXYSTATE_MAGIC);
        if (ps->handshaked) {
            ps->renegotiation = 1;
            LOG("{core} SSL renegotiation asked by client\n");
        }
    }
}

#ifdef USE_SHARED_CACHE

/* Handle incoming message updates */
static void handle_shcupd(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    unsigned char msg[SHSESS_MAX_ENCODED_LEN], hash[EVP_MAX_MD_SIZE];
    ssize_t r;
    unsigned int hash_len;
    uint32_t encdate;
    long now = (time_t)ev_now(loop);

    while ( ( r = recv(w->fd, msg, sizeof(msg), 0) ) > 0 ) {

        /* msg len must be greater than 1 Byte of data + sig length */
        if (r < (int)(1+sizeof(shared_secret)))
           continue;

        /* compute sig */
        r -= sizeof(shared_secret);
        HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret), msg, r, hash, &hash_len);

        if (hash_len != sizeof(shared_secret)) /* should never append */
           continue;

        /* check sign */
        if(memcmp(msg+r, hash, hash_len))
           continue;

        /* msg len must be greater than 1 Byte of data + encdate length */
        if (r < (int)(1+sizeof(uint32_t)))
           continue;

        /* drop too unsync updates */
        r -= sizeof(uint32_t);
        encdate = *((uint32_t *)&msg[r]);
        if (!(abs((int)(int32_t)now-ntohl(encdate)) < SSL_CTX_get_timeout(default_ctx)))
           continue;

        shctx_sess_add(msg, r, now);
    }
}

/* Send remote updates messages callback */
void shcupd_session_new(unsigned char *msg, unsigned int len, long cdate) {
    unsigned int hash_len;
    struct addrinfo **pai = shcupd_peers;
    uint32_t ncdate;

    /* add session creation encoded date to footer */
    ncdate = htonl((uint32_t)cdate);
    memcpy(msg+len, &ncdate, sizeof(ncdate));
    len += sizeof(ncdate);

    /* add msg sign */
    HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret),
                     msg, len, msg+len, &hash_len);
    len += hash_len;

    /* send msg to peers */
    while (*pai) {
        sendto(shcupd_socket, msg, len, 0, (*pai)->ai_addr, (*pai)->ai_addrlen);
        pai++;
    }
}

/* Compute a sha1 secret from an ASN1 rsa private key */
static int compute_secret(RSA *rsa, unsigned char *secret) {
    unsigned char *buf,*p;
    unsigned int length;

    length = i2d_RSAPrivateKey(rsa, NULL);
    if (length <= 0)
        return -1;

    p = buf = (unsigned char *)malloc(length*sizeof(unsigned char));
    if (!buf)
        return -1;

    i2d_RSAPrivateKey(rsa,&p);

    SHA1(buf, length, secret);

    free(buf);

    return 0;
}

/* Create udp socket to receive and send updates */
static int create_shcupd_socket() {
    struct addrinfo *ai, hints;
    struct addrinfo **pai = shcupd_peers;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->SHCUPD_IP, CONFIG->SHCUPD_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    /* check if peers inet family addresses match */
    while (*pai) {
        if ((*pai)->ai_family != ai->ai_family) {
            ERR("Share host and peers inet family differs\n");
            exit(1);
        }
        pai++;
    }

    int s = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);

    if (s == -1)
      fail("{socket: shared cache updates}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif

    setnonblocking(s);

    if (ai->ai_addr->sa_family == AF_INET) {
        struct ip_mreqn mreqn;

        memset(&mreqn, 0, sizeof(mreqn));
        mreqn.imr_multiaddr.s_addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

        if (CONFIG->SHCUPD_MCASTIF) {
            if (isalpha(*CONFIG->SHCUPD_MCASTIF)) { /* appears to be an iface name */
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
                    ERR("Error iface name is too long [%s]\n",CONFIG->SHCUPD_MCASTIF);
                    exit(1);
                }

                memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF, strlen(CONFIG->SHCUPD_MCASTIF));
                if (ioctl(s, SIOCGIFINDEX, &ifr)) {
                    fail("{ioctl: SIOCGIFINDEX}");
                }

                mreqn.imr_ifindex = ifr.ifr_ifindex;
            }
            else if (strchr(CONFIG->SHCUPD_MCASTIF,'.')) { /* appears to be an ipv4 address */
                mreqn.imr_address.s_addr = inet_addr(CONFIG->SHCUPD_MCASTIF);
            }
            else { /* appears to be an iface index */
                mreqn.imr_ifindex = atoi(CONFIG->SHCUPD_MCASTIF);
            }
        }

        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn)) < 0) {
            if (errno != EINVAL) { /* EINVAL if it is not a multicast address,
                                                not an error we consider unicast */
                fail("{setsockopt: IP_ADD_MEMBERSIP}");
            }
        }
        else { /* this is a multicast address */
            unsigned char loop = 0;

            if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
               fail("{setsockopt: IP_MULTICAST_LOOP}");
            }
        }

        /* optional set sockopts for sending to multicast msg */
        if (CONFIG->SHCUPD_MCASTIF &&
            setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) < 0) {
            fail("{setsockopt: IP_MULTICAST_IF}");
        }

        if (CONFIG->SHCUPD_MCASTTTL) {
             unsigned char ttl;

             ttl = (unsigned char)atoi(CONFIG->SHCUPD_MCASTTTL);
             if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
                 fail("{setsockopt: IP_MULTICAST_TTL}");
             }
        }

     }
#ifdef IPV6_ADD_MEMBERSHIP
     else if (ai->ai_addr->sa_family == AF_INET6) {
        struct ipv6_mreq mreq;

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                                       sizeof(mreq.ipv6mr_multiaddr));

        if (CONFIG->SHCUPD_MCASTIF) {
            if (isalpha(*CONFIG->SHCUPD_MCASTIF)) { /* appears to be an iface name */
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
                    ERR("Error iface name is too long [%s]\n",CONFIG->SHCUPD_MCASTIF);
                    exit(1);
                }

                memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF, strlen(CONFIG->SHCUPD_MCASTIF));
                if (ioctl(s, SIOCGIFINDEX, &ifr)) {
                    fail("{ioctl: SIOCGIFINDEX}");
                }

                mreq.ipv6mr_interface = ifr.ifr_ifindex;
            }
            else { /* option appears to be an iface index */
                mreq.ipv6mr_interface = atoi(CONFIG->SHCUPD_MCASTIF);
            }
        }

        if (setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            if (errno != EINVAL) { /* EINVAL if it is not a multicast address,
                                                not an error we consider unicast */
                fail("{setsockopt: IPV6_ADD_MEMBERSIP}");
            }
        }
        else { /* this is a multicast address */
            unsigned int loop = 0;

            if(setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
               fail("{setsockopt: IPV6_MULTICAST_LOOP}");
            }
        }

        /* optional set sockopts for sending to multicast msg */
        if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                               &mreq.ipv6mr_interface, sizeof(mreq.ipv6mr_interface)) < 0) {
            fail("{setsockopt: IPV6_MULTICAST_IF}");
        }

        if (CONFIG->SHCUPD_MCASTTTL) {
            int hops;

            hops = atoi(CONFIG->SHCUPD_MCASTTTL);
            if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0) {
                fail("{setsockopt: IPV6_MULTICAST_HOPS}");
            }
        }
    }
#endif /* IPV6_ADD_MEMBERSHIP */

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

    freeaddrinfo(ai);

    return s;
}

#endif /*USE_SHARED_CACHE */

RSA *load_rsa_privatekey(SSL_CTX *ctx, const char *file) {
    BIO *bio;
    RSA *rsa;

    bio = BIO_new_file(file, "r");
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL,
          ctx->default_passwd_callback, ctx->default_passwd_callback_userdata);
    BIO_free(bio);

    return rsa;
}

#ifndef OPENSSL_NO_TLSEXT
static int
sni_match(const struct ctx_list *cl, const char *srvname)
{
	if (!cl->is_wildcard)
		return (strcasecmp(srvname, cl->servername) == 0);
	else {
		char *s = strchr(srvname, '.');
		if (s == NULL)
			return 0;
		return (strcasecmp(s, cl->servername + 1) == 0);
	}
}

/*
 * Switch the context of the current SSL object to the most appropriate one
 * based on the SNI header
 */
int sni_switch_ctx(SSL *ssl, int *al, void *data) {
	(void)data;
	(void)al;
	const char *servername;
	const ctx_list *cl;

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return SSL_TLSEXT_ERR_NOACK;

	VTAILQ_FOREACH(cl, &sni_ctxs, list) {
		CHECK_OBJ_NOTNULL(cl, CTX_LIST_MAGIC);
		if (sni_match(cl, servername)) {
			SSL_set_SSL_CTX(ssl, cl->ctx);
			return SSL_TLSEXT_ERR_OK;
		}
	}

	/* No matching certs */
	if (CONFIG->SNI_NOMATCH_ABORT)
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	else
		return SSL_TLSEXT_ERR_NOACK;
}
#endif /* OPENSSL_NO_TLSEXT */


/*
 * Initialize an SSL context
 */

SSL_CTX *make_ctx(const char *pemfile) {
    SSL_CTX *ctx;
    RSA *rsa;

    long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL |
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

#ifdef SSL_OP_NO_COMPRESSION
    ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
    if (CONFIG->ETYPE == ENC_TLS)
	    ssloptions |= SSL_OP_NO_SSLv3;
    ctx = SSL_CTX_new((CONFIG->PMODE == SSL_CLIENT) ?
                SSLv23_client_method() : SSLv23_server_method());

    SSL_CTX_set_options(ctx, ssloptions);
    SSL_CTX_set_info_callback(ctx, info_callback);

    if (CONFIG->CIPHER_SUITE) {
        if (SSL_CTX_set_cipher_list(ctx, CONFIG->CIPHER_SUITE) != 1) {
            ERR_print_errors_fp(stderr);
        }
    }

    if (CONFIG->PREFER_SERVER_CIPHERS) {
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    if (CONFIG->PMODE == SSL_CLIENT) {
        return ctx;
    }

    /* SSL_SERVER Mode stuff */
    if (SSL_CTX_use_certificate_chain_file(ctx, pemfile) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    rsa = load_rsa_privatekey(ctx, pemfile);
    if (!rsa) {
       ERR("Error loading rsa private key\n");
       exit(1);
    }

    if (SSL_CTX_use_RSAPrivateKey(ctx, rsa) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

#ifndef OPENSSL_NO_DH
    init_dh(ctx, pemfile);
#endif /* OPENSSL_NO_DH */

#ifndef OPENSSL_NO_TLSEXT
    if (!SSL_CTX_set_tlsext_servername_callback(ctx, sni_switch_ctx)) {
        ERR("Error setting up SNI support\n");
    }
#endif /* OPENSSL_NO_TLSEXT */

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        if (shared_context_init(ctx, CONFIG->SHARED_CACHE) < 0) {
            ERR("Unable to alloc memory for shared cache.\n");
            exit(1);
        }
        if (CONFIG->SHCUPD_PORT) {
            if (compute_secret(rsa, shared_secret) < 0) {
                ERR("Unable to compute shared secret.\n");
                exit(1);
            }

            /* Force tls tickets cause keys differs */
            SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

            if (*shcupd_peers) {
                shsess_set_new_cbk(shcupd_session_new);
            }
        }
    }
#endif

    RSA_free(rsa);
    return ctx;
}

#ifndef OPENSSL_NO_TLSEXT
static int
load_cert_ctx(SSL_CTX *ctx, const char *file)
{
	X509 *x509;
	X509_NAME *x509_name;
	X509_NAME_ENTRY *x509_entry;
	BIO *f;
	STACK_OF(GENERAL_NAME) *names = NULL;
	GENERAL_NAME *name;
	int i;

#define PUSH_CTX(asn1_str, ctx)						\
	do {								\
		struct ctx_list *cl;					\
		ALLOC_OBJ(cl, CTX_LIST_MAGIC);				\
		ASN1_STRING_to_UTF8(					\
			(unsigned char **)&cl->servername, asn1_str);	\
		cl->is_wildcard =					\
		    (strstr(cl->servername, "*.") == cl->servername);	\
		cl->filename = strdup(file);				\
		cl->ctx = ctx;						\
		VTAILQ_INSERT_TAIL(&sni_ctxs, cl, list);		\
	} while (0)

	f = BIO_new(BIO_s_file());
	// TODO: error checking
	if (!BIO_read_filename(f, file)) {
		ERR("Could not read cert '%s'\n", file);
		return (1);
	}
	x509 = PEM_read_bio_X509_AUX(f, NULL, NULL, NULL);
	BIO_free(f);

	// First, look for Subject Alternative Names
	names = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
		name = sk_GENERAL_NAME_value(names, i);
		if (name->type == GEN_DNS) {
			PUSH_CTX(name->d.dNSName, ctx);
		}
	}
	if (sk_GENERAL_NAME_num(names) > 0) {
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		// If we actally found some, don't bother looking any further
		X509_free(x509);
		return (0);
	} else if (names != NULL) {
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
	}

	// Now we're left looking at the CN on the cert
	x509_name = X509_get_subject_name(x509);
	i = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1);
	if (i < 0) {
		ERR("Could not find Subject Alternative Names"
		    " or a CN on cert %s\n", file);
		X509_free(x509);
		return (1);
	}
	x509_entry = X509_NAME_get_entry(x509_name, i);
	AN(x509_entry);
	PUSH_CTX(x509_entry->value, ctx);
	X509_free(x509);
	return (0);
}
#endif /* OPENSSL_NO_TLSEXT */

/* Check that we don't needlessly load a cert that's already loaded. */
static SSL_CTX *
find_ctx(const char *file) {
	struct ctx_list *cl;
	VTAILQ_FOREACH(cl, &sni_ctxs, list) {
		if (strcmp(cl->filename, file) == 0)
			return (cl->ctx);
	}

	return (NULL);
}

/* Init library and load specified certificate.
 * Establishes a SSL_ctx, to act as a template for
 * each connection */
void init_openssl(void) {
	struct cert_files *cf;
	struct listen_sock *ls;
	SSL_CTX *ctx;
	SSL_library_init();
	SSL_load_error_strings();

	assert(CONFIG->CERT_FILES != NULL);

	// The first file (i.e., the last file listed in config) is always the
	// "default" cert
	default_ctx = make_ctx(CONFIG->CERT_FILES->CERT_FILE);
	AN(default_ctx);

#ifndef OPENSSL_NO_TLSEXT
	load_cert_ctx(default_ctx, CONFIG->CERT_FILES->CERT_FILE);

	// Go through the list of PEMs and make some SSL contexts for
	// them. We also keep track of the names associated with each
	// cert so we can do SNI on them later
	for (cf = CONFIG->CERT_FILES->NEXT; cf != NULL; cf = cf->NEXT) {
		if (find_ctx(cf->CERT_FILE) == NULL) {
			ctx = make_ctx(cf->CERT_FILE);
			AN(ctx);
			load_cert_ctx(ctx, cf->CERT_FILE);
		}
	}

	for (ls = VTAILQ_FIRST(&listen_socks); ls != NULL;
	     ls = VTAILQ_NEXT(ls, list)) {
		if (ls->cert) {
			ctx = find_ctx(ls->cert);
			if (ctx == NULL) {
				ctx = make_ctx(ls->cert);
				AN(ctx);
				load_cert_ctx(ctx, ls->cert);
			}
			ls->sctx = ctx;
		}
	}

#undef APPEND_CTX
#endif /* OPENSSL_NO_TLSEXT */

	if (CONFIG->ENGINE) {
		ENGINE *e = NULL;
		ENGINE_load_builtin_engines();
		if (!strcmp(CONFIG->ENGINE, "auto"))
			ENGINE_register_all_complete();
		else {
			if ((e = ENGINE_by_id(CONFIG->ENGINE)) == NULL ||
			    !ENGINE_init(e) ||
			    !ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
				ERR_print_errors_fp(stderr);
				exit(1);
			}
			LOG("{core} will use OpenSSL engine %s.\n",
			    ENGINE_get_id(e));
			ENGINE_finish(e);
			ENGINE_free(e);
		}
	}
}

/* Create the bound socket in the parent process */
static int
create_listen_sock(const struct front_arg *fa)
{
	struct addrinfo *ai, hints, *it;
	struct listen_sock *ls;
	char buf[INET6_ADDRSTRLEN+20];
	char abuf[INET6_ADDRSTRLEN];
	char pbuf[8];
	int n;

	CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	const int gai_err = getaddrinfo(fa->ip, fa->port,
	    &hints, &ai);
	if (gai_err != 0) {
		ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
		exit(1);
	}

	for (it = ai; it != NULL; it = it->ai_next) {
		ALLOC_OBJ(ls, LISTEN_SOCK_MAGIC);
		int s = socket(it->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (s == -1)
			fail("{socket: main}");

		int t = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
		setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
		setnonblocking(s);
		if (CONFIG->RECV_BUFSIZE > 0) {
			setsockopt(s, SOL_SOCKET, SO_RCVBUF,
			    &CONFIG->RECV_BUFSIZE,
			    sizeof(CONFIG->RECV_BUFSIZE));
		}
		if (CONFIG->SEND_BUFSIZE > 0) {
			setsockopt(s, SOL_SOCKET, SO_SNDBUF,
			    &CONFIG->SEND_BUFSIZE,
			    sizeof(CONFIG->SEND_BUFSIZE));
		}

		if (bind(s, it->ai_addr, it->ai_addrlen)) {
			fail("{bind-socket}");
		}

#ifndef NO_DEFER_ACCEPT
#if TCP_DEFER_ACCEPT
		int timeout = 1;
		setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT,
		    &timeout, sizeof(int));
#endif /* TCP_DEFER_ACCEPT */
#endif
		if (listen(s, CONFIG->BACKLOG) != 0) {
			fail("{listen-socket}");
		}

		ls->sock = s;
		memcpy(&ls->addr, it->ai_addr, it->ai_addrlen);

		n = getnameinfo(it->ai_addr, it->ai_addrlen, abuf,
		    sizeof abuf, pbuf, sizeof pbuf,
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (n != 0) {
			fail("{getnameinfo}");
		}

		if (it->ai_addr->sa_family == AF_INET6) {
			sprintf(buf, "[%s]:%s", abuf, pbuf);
		} else {
			sprintf(buf, "%s:%s", abuf, pbuf);
		}
		ls->name = strdup(buf);
		AN(ls->name);
		ls->cert = fa->cert;

		VTAILQ_INSERT_TAIL(&listen_socks, ls, list);
		nlisten_socks++;

		LOG("{core} Listening on %s\n", ls->name);
	}

	freeaddrinfo(ai);
	return (0);
}

/* Initiate a clear-text nonblocking connect() to the backend IP on behalf
 * of a newly connected upstream (encrypted) client*/
static int create_back_socket() {
    int s = socket(backaddr->ai_family, SOCK_STREAM, IPPROTO_TCP);

    if (s == -1)
      return -1;

    int flag = 1;
    int ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
    if (ret == -1) {
      ERR("Couldn't setsockopt to backend (TCP_NODELAY): %s\n", strerror(errno));
    }
    setnonblocking(s);

    return s;
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void safe_enable_io(proxystate *ps, ev_io *w) {
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
    if (!ps->want_shutdown)
        ev_io_start(loop, w);
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void shutdown_proxy(proxystate *ps, SHUTDOWN_REQUESTOR req) {
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
    LOGPROXY(ps, "proxy shutdown req=%d\n", req);
    if (ps->want_shutdown || req == SHUTDOWN_HARD) {
        ev_io_stop(loop, &ps->ev_w_ssl);
        ev_io_stop(loop, &ps->ev_r_ssl);
        ev_io_stop(loop, &ps->ev_w_handshake);
        ev_io_stop(loop, &ps->ev_r_handshake);
        ev_timer_stop(loop, &ps->ev_t_handshake);
        ev_io_stop(loop, &ps->ev_w_connect);
        ev_timer_stop(loop, &ps->ev_t_connect);
        ev_io_stop(loop, &ps->ev_w_clear);
        ev_io_stop(loop, &ps->ev_r_clear);
        ev_io_stop(loop, &ps->ev_proxy);

        close(ps->fd_up);
        close(ps->fd_down);

        ERR_clear_error();

        SSL_set_shutdown(ps->ssl, SSL_SENT_SHUTDOWN);
        SSL_free(ps->ssl);

	ringbuffer_cleanup(&ps->ring_clear2ssl);
	ringbuffer_cleanup(&ps->ring_ssl2clear);
        free(ps);
    }
    else {
        ps->want_shutdown = 1;
        if (req == SHUTDOWN_CLEAR && ringbuffer_is_empty(&ps->ring_clear2ssl))
            shutdown_proxy(ps, SHUTDOWN_HARD);
        else if (req == SHUTDOWN_SSL && ringbuffer_is_empty(&ps->ring_ssl2clear))
            shutdown_proxy(ps, SHUTDOWN_HARD);
    }
}

/* Handle various socket errors */
static void handle_socket_errno(proxystate *ps, int backend) {
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return;

    if (backend) {
	ERR("{backend} Socket error: %s\n", strerror(errno));
    } else {
        LOG("{client} Socket error: %s\n", strerror(errno));
    }
    shutdown_proxy(ps, SHUTDOWN_CLEAR);
}
/* Start connect to backend */
static int start_connect(proxystate *ps) {
    int t = 1;
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
    t = connect(ps->fd_down, backaddr->ai_addr, backaddr->ai_addrlen);
    if (t == 0 || errno == EINPROGRESS || errno == EINTR) {
        ev_io_start(loop, &ps->ev_w_connect);
        ev_timer_start(loop, &ps->ev_t_connect);
        return 0;
    }
    ERR("{backend-connect}: %s\n", strerror(errno));
    shutdown_proxy(ps, SHUTDOWN_HARD);
    return -1;
}

/* Read some data from the backend when libev says data is available--
 * write it into the upstream buffer and make sure the write event is
 * enabled for the upstream socket */
static void clear_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps;
    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
    if (ps->want_shutdown) {
        ev_io_stop(loop, &ps->ev_r_clear);
        return;
    }
    int fd = w->fd;
    char * buf = ringbuffer_write_ptr(&ps->ring_clear2ssl);
    t = recv(fd, buf, ps->ring_clear2ssl.data_len, 0);

    if (t > 0) {
        ringbuffer_write_append(&ps->ring_clear2ssl, t);
        if (ringbuffer_is_full(&ps->ring_clear2ssl))
            ev_io_stop(loop, &ps->ev_r_clear);
        if (ps->handshaked)
            safe_enable_io(ps, &ps->ev_w_ssl);
    }
    else if (t == 0) {
        LOGPROXY(ps,"Connection closed by %s\n", fd == ps->fd_down ? "backend" : "client");
        shutdown_proxy(ps, SHUTDOWN_CLEAR);
    }
    else {
        assert(t == -1);
        handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
    }
}
/* Write some data, previously received on the secure upstream socket,
 * out of the downstream buffer and onto the backend socket */
static void clear_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps;
    int fd = w->fd;
    int sz;

    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
    assert(!ringbuffer_is_empty(&ps->ring_ssl2clear));

    char *next = ringbuffer_read_next(&ps->ring_ssl2clear, &sz);
    t = send(fd, next, sz, MSG_NOSIGNAL);

    if (t > 0) {
        if (t == sz) {
            ringbuffer_read_pop(&ps->ring_ssl2clear);
            if (ps->handshaked)
                safe_enable_io(ps, &ps->ev_r_ssl);
            if (ringbuffer_is_empty(&ps->ring_ssl2clear)) {
                if (ps->want_shutdown) {
                    shutdown_proxy(ps, SHUTDOWN_HARD);
                    return; // dealloc'd
                }
                ev_io_stop(loop, &ps->ev_w_clear);
            }
        }
        else {
            ringbuffer_read_skip(&ps->ring_ssl2clear, t);
        }
    }
    else {
        assert(t == -1);
        handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
    }
}

static void start_handshake(proxystate *ps, int err);

/* Continue/complete the asynchronous connect() before starting data transmission
 * between front/backend */
static void handle_connect(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps;

    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

    t = connect(ps->fd_down, backaddr->ai_addr, backaddr->ai_addrlen);
    if (!t || errno == EISCONN || !errno) {
        ev_io_stop(loop, &ps->ev_w_connect);
        ev_timer_stop(loop, &ps->ev_t_connect);

        if (!ps->clear_connected) {
            struct sockaddr_storage addr;
            socklen_t sl;

            sl = sizeof(addr);
            getsockname(ps->fd_down, (struct sockaddr*)&addr, &sl);
            ps->connect_port = ntohs(((struct sockaddr_in*)&addr)->sin_port);
            LOGPROXY(ps, "backend connected\n");

            ps->clear_connected = 1;

            /* if incoming buffer is not full */
            if (!ringbuffer_is_full(&ps->ring_clear2ssl))
                safe_enable_io(ps, &ps->ev_r_clear);

            /* if outgoing buffer is not empty */
            if (!ringbuffer_is_empty(&ps->ring_ssl2clear))
                // not safe.. we want to resume stream even during half-closed
                ev_io_start(loop, &ps->ev_w_clear);
        }
        else {
            /* Clear side already connected so connect is on secure side: perform handshake */
            start_handshake(ps, SSL_ERROR_WANT_WRITE);
        }
    }
    else if (errno == EINPROGRESS || errno == EINTR || errno == EALREADY) {
        /* do nothing, we'll get phoned home again... */
    }
    else {
        ERR("{backend-connect}: %s\n", strerror(errno));
        shutdown_proxy(ps, SHUTDOWN_HARD);
    }
}

static void connect_timeout(EV_P_ ev_timer *w, int revents)
{
    (void) loop;
    (void) revents;
    proxystate *ps;
    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
    ERRPROXY(ps,"backend connect timeout\n");
    //shutdown_proxy(ps, SHUTDOWN_HARD);
}

/* Upon receiving a signal from OpenSSL that a handshake is required, re-wire
 * the read/write events to hook up to the handshake handlers */
static void start_handshake(proxystate *ps, int err) {
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);

    ev_io_stop(loop, &ps->ev_r_ssl);
    ev_io_stop(loop, &ps->ev_w_ssl);

    ps->handshaked = 0;

    LOGPROXY(ps,"ssl handshake start\n");
    if (err == SSL_ERROR_WANT_READ)
        ev_io_start(loop, &ps->ev_r_handshake);
    else if (err == SSL_ERROR_WANT_WRITE)
        ev_io_start(loop, &ps->ev_w_handshake);
    ev_timer_start(loop, &ps->ev_t_handshake);
}

static void
write_proxy_v2(proxystate *ps, const struct sockaddr *local)
{
	struct ha_proxy_v2_hdr *p;
	union addr {
		struct sockaddr		sa;
		struct sockaddr_in	sa4;
		struct sockaddr_in6	sa6;
	} *l, *r;
	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	p = (struct ha_proxy_v2_hdr *)
	    ringbuffer_write_ptr(&ps->ring_ssl2clear);
	size_t len = 16;
	l = (union addr *) local;
	r = (union addr *) &ps->remote_ip;

	memcpy(&p->sig,"\r\n\r\n\0\r\nQUIT\n", 12);
	p->ver_cmd = 0x21; 	/* v2|PROXY */
	p->fam = l->sa.sa_family == AF_INET ? 0x11 : 0x21;
	p->len = l->sa.sa_family == AF_INET ? htons(12) : htons(36);

	if (l->sa.sa_family == AF_INET) {
		len += 12;

		/* src/client */
		memcpy(&p->addr.ipv4.src_addr, &r->sa4.sin_addr.s_addr,
		    sizeof p->addr.ipv4.src_addr);
		memcpy(&p->addr.ipv4.src_port, &r->sa4.sin_port,
		    sizeof p->addr.ipv4.src_port);

		/* dst/server */
		memcpy(&p->addr.ipv4.dst_addr, &l->sa4.sin_addr.s_addr,
		    sizeof p->addr.ipv4.dst_addr);
		memcpy(&p->addr.ipv4.dst_port, &l->sa4.sin_port,
		    sizeof p->addr.ipv4.dst_port);
	} else {
		assert (l->sa.sa_family == AF_INET6);
		len += 36;

		/* src/client */
		memcpy(&p->addr.ipv6.src_addr, &r->sa6.sin6_addr.s6_addr,
		    sizeof p->addr.ipv6.src_addr);
		memcpy(&p->addr.ipv6.src_port, &r->sa6.sin6_port,
		    sizeof p->addr.ipv6.src_port);

		/* dst/server */
		memcpy(&p->addr.ipv6.dst_addr, &l->sa6.sin6_addr.s6_addr,
		    sizeof p->addr.ipv6.dst_addr);
		memcpy(&p->addr.ipv6.dst_port, &l->sa6.sin6_port,
		    sizeof p->addr.ipv6.dst_port);
	}
	ringbuffer_write_append(&ps->ring_ssl2clear, len);
}

static void
write_proxy_v1(proxystate *ps, const struct sockaddr *local, socklen_t slen)
{
	char *p;
	char src_addr[INET6_ADDRSTRLEN+1], dst_addr[INET6_ADDRSTRLEN+1];
	char src_port[8], dst_port[8];
	size_t len;
	int n;

	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);

	p = ringbuffer_write_ptr(&ps->ring_ssl2clear);
	n = getnameinfo(local, slen, dst_addr, sizeof dst_addr, dst_port,
	    sizeof dst_port, NI_NUMERICHOST | NI_NUMERICSERV);
	assert (n == 0);

	n = getnameinfo((struct sockaddr *) &ps->remote_ip, slen, src_addr,
	    sizeof src_addr, src_port, sizeof src_port,
	    NI_NUMERICHOST | NI_NUMERICSERV);
	assert (n == 0);

	if (local->sa_family == AF_INET) {
		len = sprintf(p, "PROXY TCP4 %s %s %s %s\r\n", src_addr,
		    dst_addr, src_port, dst_port);
	} else {
		assert (local->sa_family == AF_INET6);
		len = sprintf(p, "PROXY TCP6 %s %s %s %s\r\n", src_addr,
		    dst_addr, src_port, dst_port);
	}
	assert (len > 0);
	ringbuffer_write_append(&ps->ring_ssl2clear, len);
}

static void
write_ip_octet(proxystate *ps)
{
	char *ring_pnt;

	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	ring_pnt = ringbuffer_write_ptr(&ps->ring_ssl2clear);
	assert(ps->remote_ip.ss_family == AF_INET ||
	    ps->remote_ip.ss_family == AF_INET6);
	*ring_pnt++ = (unsigned char) ps->remote_ip.ss_family;
	if (ps->remote_ip.ss_family == AF_INET6) {
		memcpy(ring_pnt,
		    &((struct sockaddr_in6 *)
			&ps->remote_ip)->sin6_addr.s6_addr, 16U);
		ringbuffer_write_append(&ps->ring_ssl2clear, 1U + 16U);
	}
	else {
		memcpy(ring_pnt, &((struct sockaddr_in *)
			&ps->remote_ip)->sin_addr.s_addr, 4U);
		ringbuffer_write_append(&ps->ring_ssl2clear, 1U + 4U);
	}
}
/* After OpenSSL is done with a handshake, re-wire standard read/write handlers
 * for data transmission */
static void end_handshake(proxystate *ps) {
	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	ev_io_stop(loop, &ps->ev_r_handshake);
	ev_io_stop(loop, &ps->ev_w_handshake);
	ev_timer_stop(loop, &ps->ev_t_handshake);

	LOGPROXY(ps,"ssl end handshake\n");
	/* Disable renegotiation (CVE-2009-3555) */
	if (ps->ssl->s3) {
		ps->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
	}
	ps->handshaked = 1;

	/* Check if clear side is connected */
	if (!ps->clear_connected) {
		if (CONFIG->WRITE_PROXY_LINE_V2 || CONFIG->WRITE_PROXY_LINE) {
			struct sockaddr_storage local;
			socklen_t slen = sizeof local;
			if (getsockname(ps->fd_up, (struct sockaddr *) &local,
				&slen) != 0) {
				SOCKERR("getsockname");
			}
			if (CONFIG->WRITE_PROXY_LINE)
				write_proxy_v1(ps, (struct sockaddr *) &local,
				    slen);
			else
				write_proxy_v2(ps, (struct sockaddr *) &local);
		}
		else if (CONFIG->WRITE_IP_OCTET) {
			write_ip_octet(ps);
		}
		/* start connect now */
		if (0 != start_connect(ps)) {
			return;
		}
	}
	else {
		/* hitch used in client mode, keep client session ) */
		if (!SSL_session_reused(ps->ssl)) {
			if (client_session)
				SSL_SESSION_free(client_session);
			client_session = SSL_get1_session(ps->ssl);
		}
	}

	/* if incoming buffer is not full */
	if (!ringbuffer_is_full(&ps->ring_ssl2clear))
		safe_enable_io(ps, &ps->ev_r_ssl);

	/* if outgoing buffer is not empty */
	if (!ringbuffer_is_empty(&ps->ring_clear2ssl))
		// not safe.. we want to resume stream even during half-closed
		ev_io_start(loop, &ps->ev_w_ssl);
}

static void client_proxy_proxy(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    char *proxy = tcp_proxy_line, *end = tcp_proxy_line + sizeof(tcp_proxy_line);
    proxystate *ps;
    BIO *b;

    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
    b = SSL_get_rbio(ps->ssl);

    // Copy characters one-by-one until we hit a \n or an error
    while (proxy != end && (t = BIO_read(b, proxy, 1)) == 1) {
        if (*proxy++ == '\n') break;
    }

    if (proxy == end) {
        LOG("{client} Unexpectedly long PROXY line. Perhaps a malformed request?");
        shutdown_proxy(ps, SHUTDOWN_SSL);
    }
    else if (t == 1) {
        if (ringbuffer_is_full(&ps->ring_ssl2clear)) {
            LOG("{client} Error writing PROXY line");
            shutdown_proxy(ps, SHUTDOWN_SSL);
            return;
        }

        char *ring = ringbuffer_write_ptr(&ps->ring_ssl2clear);
        memcpy(ring, tcp_proxy_line, proxy - tcp_proxy_line);
        ringbuffer_write_append(&ps->ring_ssl2clear, proxy - tcp_proxy_line);

        // Finished reading the PROXY header
        if (*(proxy - 1) == '\n') {
            ev_io_stop(loop, &ps->ev_proxy);

            // Start the real handshake
            start_handshake(ps, SSL_ERROR_WANT_READ);
        }
    }
    else if (!BIO_should_retry(b)) {
        LOG("{client} Unexpected error reading PROXY line");
        shutdown_proxy(ps, SHUTDOWN_SSL);
    }
}

static void
log_ssl_error (proxystate* ps, const char* what)
{
    int e;
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
    while ((e = ERR_get_error())) {
	char buf[1024];
	ERR_error_string_n(e, buf, sizeof(buf));
	ERRPROXY(ps, "%s: %s\n", what, buf);
    }
}

/* The libev I/O handler during the OpenSSL handshake phase.  Basically, just
 * let OpenSSL do what it likes with the socket and obey its requests for reads
 * or writes */
static void client_handshake(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps;

    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

    LOGPROXY(ps,"ssl client handshake revents=%x\n",revents);
    t = SSL_do_handshake(ps->ssl);
    if (t == 1) {
        end_handshake(ps);
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        LOGPROXY(ps,"ssl client handshake err=%d\n",err);
        if (err == SSL_ERROR_WANT_READ) {
            ev_io_stop(loop, &ps->ev_w_handshake);
            ev_io_start(loop, &ps->ev_r_handshake);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            ev_io_stop(loop, &ps->ev_r_handshake);
            ev_io_start(loop, &ps->ev_w_handshake);
        }
        else if (err == SSL_ERROR_ZERO_RETURN) {
            LOG("{%s} Connection closed (in handshake)\n", w->fd == ps->fd_up ? "client" : "backend");
            shutdown_proxy(ps, SHUTDOWN_SSL);
        }
        else {
            if (err == SSL_ERROR_SSL) {
                log_ssl_error(ps, "Handshake failure");
            } else {
        	LOG("{%s} Unexpected SSL error (in handshake): %d\n", w->fd == ps->fd_up ? "client" : "backend", err);
            }
            shutdown_proxy(ps, SHUTDOWN_SSL);
        }
    }
}

static void handshake_timeout(EV_P_ ev_timer *w, int revents)
{
    (void) loop;
    (void) revents;
    proxystate *ps;
    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
    LOGPROXY(ps,"SSL handshake timeout\n");
    shutdown_proxy(ps, SHUTDOWN_HARD);
}

#define SSLERR(ps,which,log) \
switch (err) { \
case SSL_ERROR_ZERO_RETURN: \
log(ps,"Connection closed by " which "\n"); \
    break; \
case SSL_ERROR_SYSCALL: \
    if (errno == 0) {\
        log(ps,"Connection closed by " which "\n"); \
    } else {\
	log(ps,"SSL socket error (" which "): %s\n",strerror(errno)); \
    }\
    break; \
default: \
    log(ps,"{" which "} Unexpected SSL_read error (" which "): %d\n",err); \
}

    /* Handle a socket error condition passed to us from OpenSSL */
static void handle_fatal_ssl_error(proxystate *ps, int err, int backend) {
    CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
    if (backend) {
	SSLERR(ps, "backend", ERRPROXY);
    } else {
	SSLERR(ps, "client", LOGPROXY);
    }
    shutdown_proxy(ps, SHUTDOWN_SSL);
}

/* Read some data from the upstream secure socket via OpenSSL,
 * and buffer anything we get for writing to the backend */
static void ssl_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps;

    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

    if (ps->want_shutdown) {
        ev_io_stop(loop, &ps->ev_r_ssl);
        return;
    }
    if (ringbuffer_is_full(&ps->ring_ssl2clear)) {
	ERRPROXY(ps, "attempt to read ssl when ring full");
	ev_io_stop(loop, &ps->ev_r_ssl);
	return;
    }
    char * buf = ringbuffer_write_ptr(&ps->ring_ssl2clear);
    t = SSL_read(ps->ssl, buf, ps->ring_ssl2clear.data_len);

    /* Fix CVE-2009-3555. Disable reneg if started by client. */
    if (ps->renegotiation) {
        shutdown_proxy(ps, SHUTDOWN_SSL);
        return;
    }

    if (t > 0) {
        ringbuffer_write_append(&ps->ring_ssl2clear, t);
        if (ringbuffer_is_full(&ps->ring_ssl2clear))
            ev_io_stop(loop, &ps->ev_r_ssl);
        if (ps->clear_connected)
            safe_enable_io(ps, &ps->ev_w_clear);
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_WRITE) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_READ) { } /* incomplete SSL data */
        else {
            if (err == SSL_ERROR_SSL) {
        	log_ssl_error(ps, "SSL_read error");
            } else {
        	LOG("{%s} SSL_read error: %d\n", w->fd == ps->fd_up ? "client" : "backend", err);
            }
            handle_fatal_ssl_error(ps, err, w->fd == ps->fd_up ? 0 : 1);
        }
    }
}

/* Write some previously-buffered backend data upstream on the
 * secure socket using OpenSSL */
static void ssl_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    int sz;
    proxystate *ps;

    CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

    assert(!ringbuffer_is_empty(&ps->ring_clear2ssl));
    char * next = ringbuffer_read_next(&ps->ring_clear2ssl, &sz);
    t = SSL_write(ps->ssl, next, sz);
    if (t > 0) {
        if (t == sz) {
            ringbuffer_read_pop(&ps->ring_clear2ssl);
            if (ps->clear_connected)
                safe_enable_io(ps, &ps->ev_r_clear); // can be re-enabled b/c we've popped
            if (ringbuffer_is_empty(&ps->ring_clear2ssl)) {
                if (ps->want_shutdown) {
                    shutdown_proxy(ps, SHUTDOWN_HARD);
                    return;
                }
                ev_io_stop(loop, &ps->ev_w_ssl);
            }
        }
        else {
            ringbuffer_read_skip(&ps->ring_clear2ssl, t);
        }
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {} /* incomplete SSL data */
        else {
            if (err == SSL_ERROR_SSL) {
        	log_ssl_error(ps, "SSL_write error");
            } else {
        	LOG("{%s} SSL_write error: %d\n", w->fd == ps->fd_up ? "client" : "backend", err);
            }
            handle_fatal_ssl_error(ps, err,  w->fd == ps->fd_up ? 0 : 1);
        }
    }
}

/* libev read handler for the bound sockets.  Socket is accepted,
 * the proxystate is allocated and initalized, and we're off the races
 * connecting to the backend */
static void handle_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct sockaddr_storage addr;
    proxystate *ps;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            ERR("{client} accept() failed; too many open files for this system\n");
            break;

        default:
            if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN && errno != ENOTTY && errno != ECONNABORTED) {
        	SOCKERR("{client} accept() failed");
            }
        }
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      SOCKERR("Couldn't setsockopt on client (TCP_NODELAY)");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      SOCKERR("Couldn't setsockopt on client (TCP_CWND)");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    int back = create_back_socket();

    if (back == -1) {
        close(client);
        ERR("{backend-socket}: %s\n", strerror(errno));
        return;
    }

    SSL_CTX * ctx = (SSL_CTX *)w->data;
    SSL *ssl = SSL_new(ctx);
    long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#ifdef SSL_MODE_RELEASE_BUFFERS
    mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
    SSL_set_mode(ssl, mode);
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, client);

    ALLOC_OBJ(ps, PROXYSTATE_MAGIC);

    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->clear_connected = 0;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    ps->connect_port = 0;

    ringbuffer_init(&ps->ring_clear2ssl, CONFIG->RING_SLOTS, CONFIG->RING_DATA_LEN);
    ringbuffer_init(&ps->ring_ssl2clear, CONFIG->RING_SLOTS, CONFIG->RING_DATA_LEN);

    /* set up events */
    ev_io_init(&ps->ev_r_ssl, ssl_read, client, EV_READ);
    ev_io_init(&ps->ev_w_ssl, ssl_write, client, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, client, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, client, EV_WRITE);
    ev_timer_init(&ps->ev_t_handshake, handshake_timeout, CONFIG->SSL_HANDSHAKE_TIMEOUT, 0.);

    ev_io_init(&ps->ev_proxy, client_proxy_proxy, client, EV_READ);

    ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);
    ev_timer_init(&ps->ev_t_connect, connect_timeout, CONFIG->BACKEND_CONNECT_TIMEOUT, 0.);

    ev_io_init(&ps->ev_w_clear, clear_write, back, EV_WRITE);
    ev_io_init(&ps->ev_r_clear, clear_read, back, EV_READ);

    ps->ev_r_ssl.data = ps;
    ps->ev_w_ssl.data = ps;
    ps->ev_r_clear.data = ps;
    ps->ev_w_clear.data = ps;
    ps->ev_proxy.data = ps;
    ps->ev_w_connect.data = ps;
    ps->ev_t_connect.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;
    ps->ev_t_handshake.data = ps;

    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);

    LOGPROXY(ps, "proxy connect\n");
    if (CONFIG->PROXY_PROXY_LINE) {
        ev_io_start(loop, &ps->ev_proxy);
    }
    else {
        start_handshake(ps, SSL_ERROR_WANT_READ); /* for client-first handshake */
    }
}


static void check_ppid(struct ev_loop *loop, ev_timer *w, int revents) {
	struct listen_sock *ls;
	(void) revents;
	pid_t ppid = getppid();
	if (ppid != master_pid) {
		ERR("{core} Process %d detected parent death, "
		    "closing listener sockets.\n", child_num);
		ev_timer_stop(loop, w);
		VTAILQ_FOREACH(ls, &listen_socks, list) {
			CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
			ev_io_stop(loop, &ls->listener);
			close(ls->sock);
		}
	}
}

static void handle_clear_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct sockaddr_storage addr;
    proxystate *ps;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            ERR("{client} accept() failed; too many open files for this system\n");
            break;

        default:
            if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
        	SOCKERR("{client} accept() failed");
        	exit(1);
            }
            break;
        }
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      ERR("Couldn't setsockopt on client (TCP_NODELAY): %s\n", strerror(errno));
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      ERR("Couldn't setsockopt on client (TCP_CWND): %s\n", strerror(errno));
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    int back = create_back_socket();

    if (back == -1) {
        close(client);
        ERR("{backend-socket}: %s\n", strerror(errno));
        return;
    }

    SSL_CTX * ctx = (SSL_CTX *)w->data;
    SSL *ssl = SSL_new(ctx);
    long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#ifdef SSL_MODE_RELEASE_BUFFERS
    mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
    SSL_set_mode(ssl, mode);
    SSL_set_connect_state(ssl);
    SSL_set_fd(ssl, back);
    if (client_session)
        SSL_set_session(ssl, client_session);

    ALLOC_OBJ(ps, PROXYSTATE_MAGIC);

    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->clear_connected = 1;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    ringbuffer_init(&ps->ring_clear2ssl, CONFIG->RING_SLOTS, CONFIG->RING_DATA_LEN);
    ringbuffer_init(&ps->ring_ssl2clear, CONFIG->RING_SLOTS, CONFIG->RING_DATA_LEN);

    /* set up events */
    ev_io_init(&ps->ev_r_clear, clear_read, client, EV_READ);
    ev_io_init(&ps->ev_w_clear, clear_write, client, EV_WRITE);

    ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);
    ev_timer_init(&ps->ev_t_connect, connect_timeout, CONFIG->BACKEND_CONNECT_TIMEOUT, 0.);

    ev_io_init(&ps->ev_r_handshake, client_handshake, back, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, back, EV_WRITE);
    ev_timer_init(&ps->ev_t_handshake, handshake_timeout, CONFIG->SSL_HANDSHAKE_TIMEOUT, 0.);

    ev_io_init(&ps->ev_w_ssl, ssl_write, back, EV_WRITE);
    ev_io_init(&ps->ev_r_ssl, ssl_read, back, EV_READ);

    ps->ev_r_ssl.data = ps;
    ps->ev_w_ssl.data = ps;
    ps->ev_r_clear.data = ps;
    ps->ev_w_clear.data = ps;
    ps->ev_w_connect.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;
    ps->ev_t_handshake.data = ps;

    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);

    ev_io_start(loop, &ps->ev_r_clear);
    start_connect(ps); /* start connect */
}

/* Set up the child (worker) process including libev event loop, read event
 * on the bound sockets, etc */
static void
handle_connections(void)
{
	struct listen_sock *ls;
	LOG("{core} Process %d online\n", child_num);

	/* child cannot create new children... */
	create_workers = 0;

#if defined(CPU_ZERO) && defined(CPU_SET)
	cpu_set_t cpus;

	CPU_ZERO(&cpus);
	CPU_SET(child_num, &cpus);

	int res = sched_setaffinity(0, sizeof(cpus), &cpus);
	if (!res)
		LOG("{core} Successfully attached to CPU #%d\n", child_num);
	else
		ERR("{core-warning} Unable to attach to CPU #%d; "
		    "do you have that many cores?\n", child_num);
#endif

	loop = ev_default_loop(EVFLAG_AUTO);

	ev_timer timer_ppid_check;
	ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
	ev_timer_start(loop, &timer_ppid_check);

	VTAILQ_FOREACH(ls, &listen_socks, list) {
		ev_io_init(&ls->listener,
		    (CONFIG->PMODE == SSL_CLIENT) ?
		    handle_clear_accept : handle_accept,
		    ls->sock, EV_READ);
		if (ls->sctx)
			ls->listener.data = ls->sctx;
		else
			ls->listener.data = default_ctx;
		ev_io_start(loop, &ls->listener);
	}

	ev_loop(loop, 0);
	ERR("{core} Child %d exiting.\n", child_num);
	exit(1);
}

void change_root() {
    if (chroot(CONFIG->CHROOT) == -1)
        fail("chroot");
    if (chdir("/"))
        fail("chdir");
}

void drop_privileges() {
    if (CONFIG->GID >= 0 && setgroups(0, NULL) && setgid(CONFIG->GID) < 0)
        fail("setgid failed");
    if (CONFIG->UID >= 0 && setgroups(0, NULL) && setuid(CONFIG->UID) < 0)
        fail("setuid failed");
}


void init_globals(void) {
    /* backaddr */
    struct addrinfo hints;

    VTAILQ_INIT(&listen_socks);
    VTAILQ_INIT(&sni_ctxs);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    const int gai_err = getaddrinfo(CONFIG->BACK_IP, CONFIG->BACK_PORT,
                                    &hints, &backaddr);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
        exit(1);
    }

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        /* cache update peers addresses */
        shcupd_peer_opt *spo = CONFIG->SHCUPD_PEERS;
        struct addrinfo **pai = shcupd_peers;

        while (spo->ip) {
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = 0;
            const int gai_err = getaddrinfo(spo->ip,
                                spo->port ? spo->port : CONFIG->SHCUPD_PORT, &hints, pai);
            if (gai_err != 0) {
                ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
                exit(1);
            }
            spo++;
            pai++;
        }
    }
#endif
    /* child_pids */
    if ((child_pids = calloc(CONFIG->NCORES, sizeof(pid_t))) == NULL)
        fail("calloc");

    if (CONFIG->SYSLOG)
        openlog("hitch", LOG_CONS | LOG_PID | LOG_NDELAY, CONFIG->SYSLOG_FACILITY);
}

/* Forks COUNT children starting with START_INDEX.
 * Each child's index is stored in child_num and its pid is stored in child_pids[child_num]
 * so the parent can manage it later. */
void start_children(int start_index, int count) {
    /* don't do anything if we're not allowed to create new children */
    if (!create_workers) return;

    for (child_num = start_index; child_num < start_index + count; child_num++) {
        int pid = fork();
        if (pid == -1) {
            ERR("{core} fork() failed: %s; Goodbye cruel world!\n", strerror(errno));
            exit(1);
        }
        else if (pid == 0) { /* child */
            handle_connections();
            exit(0);
        }
        else { /* parent. Track new child. */
            child_pids[child_num] = pid;
        }
    }
}

/* Forks a new child to replace the old, dead, one with the given PID.*/
void replace_child_with_pid(pid_t pid) {
    int i;

    /* find old child's slot and put a new child there */
    for (i = 0; i < CONFIG->NCORES; i++) {
        if (child_pids[i] == pid) {
            start_children(i, 1);
            return;
        }
    }

    ERR("Cannot find index for child pid %d", pid);
}

/* Manage status changes in child processes */
static void do_wait(int __attribute__ ((unused)) signo) {

    int status;
    int pid = wait(&status);

    if (pid == -1) {
        if (errno == ECHILD) {
            ERR("{core} All children have exited! Restarting...\n");
            start_children(0, CONFIG->NCORES);
        }
        else if (errno == EINTR) {
            ERR("{core} Interrupted wait\n");
        }
        else {
            fail("wait");
        }
    }
    else {
        if (WIFEXITED(status)) {
            ERR("{core} Child %d exited with status %d. Replacing...\n", pid, WEXITSTATUS(status));
            replace_child_with_pid(pid);
        }
        else if (WIFSIGNALED(status)) {
            ERR("{core} Child %d was terminated by signal %d. Replacing...\n", pid, WTERMSIG(status));
            replace_child_with_pid(pid);
        }
    }
}

static void sigh_terminate (int __attribute__ ((unused)) signo) {
    /* don't create any more children */
    create_workers = 0;

    /* are we the master? */
    if (getpid() == master_pid) {
        LOG("{core} Received signal %d, shutting down.\n", signo);

        /* kill all children */
        int i;
        for (i = 0; i < CONFIG->NCORES; i++) {
            /* LOG("Stopping worker pid %d.\n", child_pids[i]); */
            if (child_pids[i] > 1 && kill(child_pids[i], SIGTERM) != 0) {
                ERR("{core} Unable to send SIGTERM to worker pid %d: %s\n", child_pids[i], strerror(errno));
            }
        }
        /* LOG("Shutdown complete.\n"); */
    }

    /* this is it, we're done... */
    exit(0);
}

void init_signals() {
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;

    /* Avoid getting PIPE signal when writing to a closed file descriptor */
    if (sigaction(SIGPIPE, &act, NULL) < 0)
        fail("sigaction - sigpipe");

    /* We don't care if someone stops and starts a child process with kill (1) */
    act.sa_flags = SA_NOCLDSTOP;

    act.sa_handler = do_wait;

    /* We do care when child processes change status */
    if (sigaction(SIGCHLD, &act, NULL) < 0)
        fail("sigaction - sigchld");

    /* catch INT and TERM signals */
    act.sa_flags = 0;
    act.sa_handler = sigh_terminate;
    if (sigaction(SIGINT, &act, NULL) < 0) {
        ERR("Unable to register SIGINT signal handler: %s\n", strerror(errno));
        exit(1);
    }
    if (sigaction(SIGTERM, &act, NULL) < 0) {
        ERR("Unable to register SIGTERM signal handler: %s\n", strerror(errno));
        exit(1);
    }
}

void daemonize () {
    if (logf == stdout || logf == stderr) {
	logf = NULL;
    }

    /* go to root directory */
    if (chdir("/") != 0) {
        ERR("Unable change directory to /: %s\n", strerror(errno));
        exit(1);
    }

    /* let's make some children, baby :) */
    pid_t pid = fork();
    if (pid < 0) {
        ERR("Unable to daemonize: fork failed: %s\n", strerror(errno));
        exit(1);
    }

    /* am i the parent? */
    if (pid != 0) {
        LOG("{core} Daemonized as pid %d.\n", pid);
        exit(0);
    }

    /* close standard streams */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    /* reopen standard streams to null device */
    stdin = fopen(NULL_DEV, "r");
    if (stdin == NULL) {
        ERR("Unable to reopen stdin to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    stdout = fopen(NULL_DEV, "w");
    if (stdout == NULL) {
        ERR("Unable to reopen stdout to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    stderr = fopen(NULL_DEV, "w");
    if (stderr == NULL) {
        ERR("Unable to reopen stderr to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }

    /* this is child, the new master */
    pid_t s = setsid();
    if (s < 0) {
        ERR("Unable to create new session, setsid(2) failed: %s :: %d\n", strerror(errno), s);
        exit(1);
    }

    LOG("Successfully daemonized as pid %d.\n", getpid());
}

void openssl_check_version() {
    /* detect OpenSSL version in runtime */
    openssl_version = SSLeay();

    /* check if we're running the same openssl that we were */
    /* compiled with */
    if ((openssl_version ^ OPENSSL_VERSION_NUMBER) & ~0xff0L) {
        ERR(
            "WARNING: {core} OpenSSL version mismatch; hitch was compiled with %lx, now using %lx.\n",
            (unsigned long int) OPENSSL_VERSION_NUMBER,
            (unsigned long int) openssl_version
        );
        /* now what? exit now? */
        /* exit(1); */
    }

    LOG("{core} Using OpenSSL version %lx.\n", (unsigned long int) openssl_version);
}

static void
remove_pfh(void)
{
	if (pfh && master_pid == getpid()) {
		VPF_Remove(pfh);
	}
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and respawn if any die */
int main(int argc, char **argv) {
    // initialize configuration
    struct front_arg *fa;
    CONFIG = config_new();

    if (CONFIG->LOG_FILENAME) {
	FILE* f;
	if ((f = fopen(CONFIG->LOG_FILENAME, "a")) == NULL) {
	    ERR("FATAL: Unable to open log file: %s: %s\n", CONFIG->LOG_FILENAME, strerror(errno));
	    exit(2);
	}
	logf = f;
	if (CONFIG->UID >=0 || CONFIG->GID >= 0) {
	    AZ(fchown(fileno(logf), CONFIG->UID, CONFIG->GID));
	}
	fstat(fileno(logf), &logf_st);
	logf_check_t = time(NULL);
    } else {
	logf = CONFIG->QUIET ? stderr : stdout;
    }
    setbuf(logf, NULL);

    // parse command line
    config_parse_cli(argc, argv, CONFIG);

    create_workers = 1;

    openssl_check_version();

    init_signals();

    init_globals();

    VTAILQ_FOREACH(fa, &CONFIG->LISTEN_ARGS, list)
	create_listen_sock(fa);

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHCUPD_PORT) {
        /* create socket to send(children) and
               receive(parent) cache updates */
        shcupd_socket = create_shcupd_socket();
    }
#endif /* USE_SHARED_CACHE */

    /* load certificates, pass to handle_connections */
    init_openssl();

    if (CONFIG->CHROOT && CONFIG->CHROOT[0])
        change_root();

    if (CONFIG->UID >= 0 || CONFIG->GID >= 0)
        drop_privileges();

    /* should we daemonize ?*/
    if (CONFIG->DAEMONIZE) {
        /* become a daemon */
        daemonize();
    }

    master_pid = getpid();

    if (CONFIG->PIDFILE) {
	    pfh = VPF_Open(CONFIG->PIDFILE, 0644, NULL);
	    if (pfh == NULL) {
		    ERR("FATAL: Could not open pid (-p) file (%s): %s\n",
			CONFIG->PIDFILE, strerror(errno));
		    exit(1);
	    }

	    AZ(VPF_Write(pfh));
	    atexit(remove_pfh);
    }

    start_children(0, CONFIG->NCORES);

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHCUPD_PORT) {
        /* start event loop to receive cache updates */

        loop = ev_default_loop(EVFLAG_AUTO);

        ev_io_init(&shcupd_listener, handle_shcupd, shcupd_socket, EV_READ);
        ev_io_start(loop, &shcupd_listener);

        ev_loop(loop, 0);
    }
#endif /* USE_SHARED_CACHE */

    for (;;) {
        /* Sleep and let the children work.
         * Parent will be woken up if a signal arrives */
        pause();
    }

    exit(0); /* just a formality; we never get here */
}
