/**
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

#include <ctype.h>
#include <sched.h>
#include <signal.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <ev.h>

#include "ringbuffer.h"
#include "shctx.h"
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

/* Globals */
static struct ev_loop *loop;
static struct addrinfo *backaddr;
static pid_t master_pid;
static ev_io listener;
static int listener_socket;
static int child_num;
static pid_t *child_pids;
static SSL_CTX *ssl_ctx;

#ifdef USE_SHARED_CACHE
static ev_io shcupd_listener;
static int shcupd_socket;
struct addrinfo *shcupd_peers[MAX_SHCUPD_PEERS+1];
static unsigned char shared_secret[SHA_DIGEST_LENGTH];

//typedef struct shcupd_peer_opt {
//     const char *ip;
//     const char *port;
//} shcupd_peer_opt;

#endif /*USE_SHARED_CACHE*/

long openssl_version;
int create_workers;
stud_config *CONFIG;

static char tcp_proxy_line[128] = "";

/* What agent/state requests the shutdown--for proper half-closed
 * handling */
typedef enum _SHUTDOWN_REQUESTOR {
    SHUTDOWN_HARD,
    SHUTDOWN_DOWN,
    SHUTDOWN_UP
} SHUTDOWN_REQUESTOR;

/*
 * Proxied State
 *
 * All state associated with one proxied connection
 */
typedef struct proxystate {
    ringbuffer ring_down; /* pushing bytes from client to backend */
    ringbuffer ring_up;   /* pushing bytes from backend to client */

    ev_io ev_r_up;        /* Upstream write event */
    ev_io ev_w_up;        /* Upstream read event */

    ev_io ev_r_handshake; /* Downstream write event */
    ev_io ev_w_handshake; /* Downstream read event */

    ev_io ev_r_down;      /* Downstream write event */
    ev_io ev_w_down;      /* Downstream read event */

    int fd_up;            /* Upstream (client) socket */
    int fd_down;          /* Downstream (backend) socket */

    int want_shutdown:1;  /* Connection is half-shutdown */
    int handshaked:1;     /* Initial handshake happened */
    int renegotiation:1;  /* Renegotation is occuring */

    SSL *ssl;             /* OpenSSL SSL state */

    struct sockaddr_storage remote_ip;  /* Remote ip returned from `accept` */
} proxystate;

#define LOG(...)                                        \
    do {                                                \
      if (!CONFIG->QUIET) fprintf(stdout, __VA_ARGS__); \
      if (CONFIG->SYSLOG) syslog(LOG_INFO, __VA_ARGS__);                    \
    } while(0)

#define ERR(...)                    \
    do {                            \
      fprintf(stderr, __VA_ARGS__); \
      if (CONFIG->SYSLOG) syslog(LOG_ERR, __VA_ARGS__); \
    } while(0)

#define NULL_DEV "/dev/null"

/* set a file descriptor (socket) to non-blocking mode */
static void setnonblocking(int fd) {
    int flag = 1;

    assert (ioctl(fd, FIONBIO, &flag) == 0);
}

/* set a tcp socket to use TCP Keepalive */
static void settcpkeepalive(int fd) {
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        ERR("Error activating SO_KEEPALIVE on client socket: %s", strerror(errno));
    }

    optval = CONFIG->TCP_KEEPALIVE_TIME;
    optlen = sizeof(optval);
#ifdef TCP_KEEPIDLE
    if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        ERR("Error setting TCP_KEEPIDLE on client socket: %s", strerror(errno));
    }
#endif
}

static void fail(const char* s) {
    perror(s);
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
    SSL_CTX_set_tmp_ecdh(ctx,ecdh);
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
    (void)ret;
    if (where & SSL_CB_HANDSHAKE_START) {
        proxystate *ps = (proxystate *)SSL_get_app_data(ssl);
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
        if (!(abs((int)(int32_t)now-ntohl(encdate)) < SSL_CTX_get_timeout(ssl_ctx)))
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

/* Init library and load specified certificate.
 * Establishes a SSL_ctx, to act as a template for
 * each connection */
SSL_CTX * init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = NULL;
    RSA *rsa;

    long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL | 
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

    if (CONFIG->ETYPE == ENC_TLS)
        ctx = SSL_CTX_new(TLSv1_server_method());
    else if (CONFIG->ETYPE == ENC_SSL)
        ctx = SSL_CTX_new(SSLv23_server_method());
    else
        assert(CONFIG->ETYPE == ENC_TLS || CONFIG->ETYPE == ENC_SSL);

#ifdef SSL_OP_NO_COMPRESSION
    ssloptions |= SSL_OP_NO_COMPRESSION;
#endif

    SSL_CTX_set_options(ctx, ssloptions);
    SSL_CTX_set_info_callback(ctx, info_callback);

    if (SSL_CTX_use_certificate_chain_file(ctx, CONFIG->CERT_FILE) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    rsa = load_rsa_privatekey(ctx, CONFIG->CERT_FILE);
    if(!rsa) {
       ERR("Error loading rsa private key\n");
       exit(1);
    }

    if (SSL_CTX_use_RSAPrivateKey(ctx,rsa) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

#ifndef OPENSSL_NO_DH
    init_dh(ctx, CONFIG->CERT_FILE);
#endif /* OPENSSL_NO_DH */

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
            LOG("{core} will use OpenSSL engine %s.\n", ENGINE_get_id(e));
            ENGINE_finish(e);
            ENGINE_free(e);
        }
    }

    if (CONFIG->CIPHER_SUITE)
        if (SSL_CTX_set_cipher_list(ctx, CONFIG->CIPHER_SUITE) != 1)
            ERR_print_errors_fp(stderr);

    if (CONFIG->PREFER_SERVER_CIPHERS)
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

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

static void prepare_proxy_line(struct sockaddr* ai_addr) {
    tcp_proxy_line[0] = 0;
    char tcp6_address_string[INET6_ADDRSTRLEN];

    if (ai_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)ai_addr;
        size_t res = snprintf(tcp_proxy_line,
                sizeof(tcp_proxy_line),
                "PROXY %%s %%s %s %%hu %hu\r\n",
                inet_ntoa(addr->sin_addr),
                ntohs(addr->sin_port));
        assert(res < sizeof(tcp_proxy_line));
    }
    else if (ai_addr->sa_family == AF_INET6 ) {
      struct sockaddr_in6* addr = (struct sockaddr_in6*)ai_addr;
      inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
      size_t res = snprintf(tcp_proxy_line,
			    sizeof(tcp_proxy_line),
			    "PROXY %%s %%s %s %%hu %hu\r\n",
			    tcp6_address_string,
			    ntohs(addr->sin6_port));
      assert(res < sizeof(tcp_proxy_line));
    }
    else {
        ERR("The --write-proxy mode is not implemented for this address family.\n");
        exit(1);
    }
}

/* Create the bound socket in the parent process */
static int create_main_socket() {
    struct addrinfo *ai, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->FRONT_IP, CONFIG->FRONT_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    int s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
    
    if (s == -1)
      fail("{socket: main}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
    setnonblocking(s);

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

#ifndef NO_DEFER_ACCEPT
#if TCP_DEFER_ACCEPT
    int timeout = 1; 
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int) );
#endif /* TCP_DEFER_ACCEPT */
#endif

    prepare_proxy_line(ai->ai_addr);

    freeaddrinfo(ai);
    listen(s, CONFIG->BACKLOG);

    return s;
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
      perror("Couldn't setsockopt to backend (TCP_NODELAY)\n");
    }

    int t = 1;
    setnonblocking(s);
    t = connect(s, backaddr->ai_addr, backaddr->ai_addrlen);
    if (t == 0 || errno == EINPROGRESS || errno == EINTR)
        return s;

    perror("{backend-connect}");

    return -1;
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void safe_enable_io(proxystate *ps, ev_io *w) {
    if (!ps->want_shutdown)
        ev_io_start(loop, w);
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void shutdown_proxy(proxystate *ps, SHUTDOWN_REQUESTOR req) {
    if (ps->want_shutdown || req == SHUTDOWN_HARD) {
        ev_io_stop(loop, &ps->ev_w_up);
        ev_io_stop(loop, &ps->ev_r_up);
        ev_io_stop(loop, &ps->ev_w_handshake);
        ev_io_stop(loop, &ps->ev_r_handshake);
        ev_io_stop(loop, &ps->ev_w_down);
        ev_io_stop(loop, &ps->ev_r_down);

        close(ps->fd_up);
        close(ps->fd_down);

        SSL_set_shutdown(ps->ssl, SSL_SENT_SHUTDOWN);
        SSL_free(ps->ssl);

        free(ps);
    }
    else {
        ps->want_shutdown = 1;
        if (req == SHUTDOWN_DOWN && ringbuffer_is_empty(&ps->ring_up))
            shutdown_proxy(ps, SHUTDOWN_HARD);
        else if (req == SHUTDOWN_UP && ringbuffer_is_empty(&ps->ring_down))
            shutdown_proxy(ps, SHUTDOWN_HARD);
    }
}

/* Handle various socket errors */
static void handle_socket_errno(proxystate *ps) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return;

    if (errno == ECONNRESET)
        ERR("{backend} Connection reset by peer\n");
    else if (errno == ETIMEDOUT)
        ERR("{backend} Connection to backend timed out\n");
    else if (errno == EPIPE)
        ERR("{backend} Broken pipe to backend (EPIPE)\n");
    else
        perror("{backend} [errno]");
    shutdown_proxy(ps, SHUTDOWN_DOWN);
}

/* Read some data from the backend when libev says data is available--
 * write it into the upstream buffer and make sure the write event is
 * enabled for the upstream socket */
static void back_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    if (ps->want_shutdown) {
        ev_io_stop(loop, &ps->ev_r_down);
        return;
    }
    int fd = w->fd;
    char * buf = ringbuffer_write_ptr(&ps->ring_up);
    t = recv(fd, buf, RING_DATA_LEN, 0);

    if (t > 0) {
        ringbuffer_write_append(&ps->ring_up, t);
        if (ringbuffer_is_full(&ps->ring_up))
            ev_io_stop(loop, &ps->ev_r_down);
        if (ps->handshaked)
            safe_enable_io(ps, &ps->ev_w_up);
    }
    else if (t == 0) {
        LOG("{backend} Connection closed\n");
        shutdown_proxy(ps, SHUTDOWN_DOWN);
    }
    else {
        assert(t == -1);
        handle_socket_errno(ps);
    }
}
/* Write some data, previously received on the secure upstream socket,
 * out of the downstream buffer and onto the backend socket */
static void back_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    int fd = w->fd;
    int sz;

    assert(!ringbuffer_is_empty(&ps->ring_down));

    char *next = ringbuffer_read_next(&ps->ring_down, &sz);
    t = send(fd, next, sz, MSG_NOSIGNAL);

    if (t > 0) {
        if (t == sz) {
            ringbuffer_read_pop(&ps->ring_down);
            if (ps->handshaked)
                safe_enable_io(ps, &ps->ev_r_up);
            if (ringbuffer_is_empty(&ps->ring_down)) {
                if (ps->want_shutdown) {
                    shutdown_proxy(ps, SHUTDOWN_HARD);
                    return; // dealloc'd
                }
                ev_io_stop(loop, &ps->ev_w_down);
            }
        }
        else {
            ringbuffer_read_skip(&ps->ring_down, t);
        }
    }
    else {
        assert(t == -1);
        handle_socket_errno(ps);
    }
}

static void start_handshake(proxystate *ps, int err);

/* Continue/complete the asynchronous connect() before starting data transmission
 * between front/backend */
static void handle_connect(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    char tcp6_address_string[INET6_ADDRSTRLEN];
    size_t written = 0;
    t = connect(ps->fd_down, backaddr->ai_addr, backaddr->ai_addrlen);
    if (!t || errno == EISCONN || !errno) {
        /* INIT */
        ev_io_stop(loop, &ps->ev_w_down);
        ev_io_init(&ps->ev_r_down, back_read, ps->fd_down, EV_READ);
        ev_io_init(&ps->ev_w_down, back_write, ps->fd_down, EV_WRITE);
        start_handshake(ps, SSL_ERROR_WANT_READ); /* for client-first handshake */
        ev_io_start(loop, &ps->ev_r_down);
        if (CONFIG->WRITE_PROXY_LINE) {
            char *ring_pnt = ringbuffer_write_ptr(&ps->ring_down);
            assert(ps->remote_ip.ss_family == AF_INET ||
		   ps->remote_ip.ss_family == AF_INET6);
	    if(ps->remote_ip.ss_family == AF_INET) {
	      struct sockaddr_in* addr = (struct sockaddr_in*)&ps->remote_ip;
	      written = snprintf(ring_pnt,
				 RING_DATA_LEN,
				 tcp_proxy_line,
				 "TCP4",
				 inet_ntoa(addr->sin_addr),
				 ntohs(addr->sin_port));
	    }
	    else if (ps->remote_ip.ss_family == AF_INET6) {
	      struct sockaddr_in6* addr = (struct sockaddr_in6*)&ps->remote_ip;
	      inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
	      written = snprintf(ring_pnt,
				 RING_DATA_LEN,
				 tcp_proxy_line,
				 "TCP6",
				 tcp6_address_string,
				 ntohs(addr->sin6_port));
	    }   
            ringbuffer_write_append(&ps->ring_down, written);
            ev_io_start(loop, &ps->ev_w_down);
        }
        else if (CONFIG->WRITE_IP_OCTET) {
            char *ring_pnt = ringbuffer_write_ptr(&ps->ring_down);
            assert(ps->remote_ip.ss_family == AF_INET ||
                   ps->remote_ip.ss_family == AF_INET6);
            *ring_pnt++ = (unsigned char) ps->remote_ip.ss_family;
            if (ps->remote_ip.ss_family == AF_INET6) {
                memcpy(ring_pnt, &((struct sockaddr_in6 *) &ps->remote_ip)
                       ->sin6_addr.s6_addr, 16U);
                ringbuffer_write_append(&ps->ring_down, 1U + 16U);
            } else {
                memcpy(ring_pnt, &((struct sockaddr_in *) &ps->remote_ip)
                       ->sin_addr.s_addr, 4U);
                ringbuffer_write_append(&ps->ring_down, 1U + 4U);
            }
            ev_io_start(loop, &ps->ev_w_down);
        }
    }
    else if (errno == EINPROGRESS || errno == EINTR || errno == EALREADY) {
        /* do nothing, we'll get phoned home again... */
    }
    else {
        perror("{backend-connect}");
        shutdown_proxy(ps, SHUTDOWN_HARD);
    }
}

/* Upon receiving a signal from OpenSSL that a handshake is required, re-wire
 * the read/write events to hook up to the handshake handlers */
static void start_handshake(proxystate *ps, int err) {
    ev_io_stop(loop, &ps->ev_r_up);
    ev_io_stop(loop, &ps->ev_w_up);

    ps->handshaked = 0;

    if (err == SSL_ERROR_WANT_READ)
        ev_io_start(loop, &ps->ev_r_handshake);
    else if (err == SSL_ERROR_WANT_WRITE)
        ev_io_start(loop, &ps->ev_w_handshake);
}

/* After OpenSSL is done with a handshake, re-wire standard read/write handlers
 * for data transmission */
static void end_handshake(proxystate *ps) {
    ev_io_stop(loop, &ps->ev_r_handshake);
    ev_io_stop(loop, &ps->ev_w_handshake);

    /* Disable renegotiation (CVE-2009-3555) */
    if (ps->ssl->s3) {
        ps->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
    }
    ps->handshaked = 1;

    /* if incoming buffer is not full */
    if (!ringbuffer_is_full(&ps->ring_down))
        safe_enable_io(ps, &ps->ev_r_up);

    /* if outgoing buffer is not empty */
    if (!ringbuffer_is_empty(&ps->ring_up))
        // not safe.. we want to resume stream even during half-closed
        ev_io_start(loop, &ps->ev_w_up);
}

/* The libev I/O handler during the OpenSSL handshake phase.  Basically, just
 * let OpenSSL do what it likes with the socket and obey its requests for reads
 * or writes */
static void client_handshake(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;

    t = SSL_do_handshake(ps->ssl);
    if (t == 1) {
        end_handshake(ps);
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            ev_io_stop(loop, &ps->ev_w_handshake);
            ev_io_start(loop, &ps->ev_r_handshake);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            ev_io_stop(loop, &ps->ev_r_handshake);
            ev_io_start(loop, &ps->ev_w_handshake);
        }
        else if (err == SSL_ERROR_ZERO_RETURN) {
            LOG("{client} Connection closed (in handshake)\n");
            shutdown_proxy(ps, SHUTDOWN_UP);
        }
        else {
            LOG("{client} Unexpected SSL error (in handshake): %d\n", err);
            shutdown_proxy(ps, SHUTDOWN_UP);
        }
    }
}

/* Handle a socket error condition passed to us from OpenSSL */
static void handle_fatal_ssl_error(proxystate *ps, int err) {
    if (err == SSL_ERROR_ZERO_RETURN)
        ERR("{client} Connection closed (in data)\n");
    else if (err == SSL_ERROR_SYSCALL)
        if (errno == 0)
            ERR("{client} Connection closed (in data)\n");
        else
            perror("{client} [errno] ");
    else
        ERR("{client} Unexpected SSL_read error: %d\n", err);
    shutdown_proxy(ps, SHUTDOWN_UP);
}

/* Read some data from the upstream secure socket via OpenSSL,
 * and buffer anything we get for writing to the backend */
static void client_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;    
    proxystate *ps = (proxystate *)w->data;
    if (ps->want_shutdown) {
        ev_io_stop(loop, &ps->ev_r_up);
        return;
    }
    char * buf = ringbuffer_write_ptr(&ps->ring_down);
    t = SSL_read(ps->ssl, buf, RING_DATA_LEN);

    /* Fix CVE-2009-3555. Disable reneg if started by client. */
    if (ps->renegotiation) {
        shutdown_proxy(ps, SHUTDOWN_UP);
        return;
    }

    if (t > 0) {
        ringbuffer_write_append(&ps->ring_down, t);
        if (ringbuffer_is_full(&ps->ring_down))
            ev_io_stop(loop, &ps->ev_r_up);
        safe_enable_io(ps, &ps->ev_w_down);
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_WRITE) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_READ) { } /* incomplete SSL data */
        else
            handle_fatal_ssl_error(ps, err);
    }
}

/* Write some previously-buffered backend data upstream on the
 * secure socket using OpenSSL */
static void client_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    int sz;
    proxystate *ps = (proxystate *)w->data;
    assert(!ringbuffer_is_empty(&ps->ring_up));
    char * next = ringbuffer_read_next(&ps->ring_up, &sz);
    t = SSL_write(ps->ssl, next, sz);
    if (t > 0) {
        if (t == sz) {
            ringbuffer_read_pop(&ps->ring_up);
            safe_enable_io(ps, &ps->ev_r_down); // can be re-enabled b/c we've popped
            if (ringbuffer_is_empty(&ps->ring_up)) {
                if (ps->want_shutdown) {
                    shutdown_proxy(ps, SHUTDOWN_HARD);
                    return;
                }
                ev_io_stop(loop, &ps->ev_w_up);
            }
        }
        else {
            ringbuffer_read_skip(&ps->ring_up, t);
        }
    }
    else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {} /* incomplete SSL data */
        else
            handle_fatal_ssl_error(ps, err);
    }
}

/* libev read handler for the bound socket.  Socket is accepted,
 * the proxystate is allocated and initalized, and we're off the races
 * connecting to the backend */
static void handle_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    struct sockaddr_storage addr;
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
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_NODELAY)\n");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_CWND)\n");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    int back = create_back_socket();

    if (back == -1) {
        close(client);
        perror("{backend-connect}");
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

    proxystate *ps = (proxystate *)malloc(sizeof(proxystate));

    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    ringbuffer_init(&ps->ring_up);
    ringbuffer_init(&ps->ring_down);

    /* set up events */
    ev_io_init(&ps->ev_r_up, client_read, client, EV_READ);
    ev_io_init(&ps->ev_w_up, client_write, client, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, client, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, client, EV_WRITE);

    ev_io_init(&ps->ev_w_down, handle_connect, back, EV_WRITE);
    ev_io_init(&ps->ev_r_down, back_read, back, EV_READ);

    ev_io_start(loop, &ps->ev_w_down);

    ps->ev_r_up.data = ps;
    ps->ev_w_up.data = ps;
    ps->ev_r_down.data = ps;
    ps->ev_w_down.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;

    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);
}


static void check_ppid(struct ev_loop *loop, ev_timer *w, int revents) {
    (void) revents;
    pid_t ppid = getppid();
    if (ppid != master_pid) {
        ERR("{core} Process %d detected parent death, closing listener socket.\n", child_num);
        ev_timer_stop(loop, w);
        ev_io_stop(loop, &listener);
        close(listener_socket);
    }

}


/* Set up the child (worker) process including libev event loop, read event
 * on the bound socket, etc */
static void handle_connections() {
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
        ERR("{core-warning} Unable to attach to CPU #%d; do you have that many cores?\n", child_num);
#endif

    loop = ev_default_loop(EVFLAG_AUTO);

    ev_timer timer_ppid_check;
    ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
    ev_timer_start(loop, &timer_ppid_check);

    ev_io_init(&listener, handle_accept, listener_socket, EV_READ);
    listener.data = ssl_ctx;
    ev_io_start(loop, &listener);

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
    if (setgid(CONFIG->GID))
        fail("setgid failed");
    if (setuid(CONFIG->UID))
        fail("setuid failed");
}


void init_globals() {
    /* backaddr */
    struct addrinfo hints;
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
        openlog("stud", LOG_CONS | LOG_PID | LOG_NDELAY, CONFIG->SYSLOG_FACILITY);
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
        printf("{core} Daemonized as pid %d.\n", pid);
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
	    "WARNING: {core} OpenSSL version mismatch; stud was compiled with %lx, now using %lx.\n",
	    (unsigned long int) OPENSSL_VERSION_NUMBER,
	    (unsigned long int) openssl_version
	);
	/* now what? exit now? */
	/* exit(1); */
    }

    LOG("{core} Using OpenSSL version %lx.\n", (unsigned long int) openssl_version);
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and respawn if any die */
int main(int argc, char **argv) {
    // initialize configuration
    CONFIG = config_new();
    
    // parse command line
    config_parse_cli(argc, argv, CONFIG);
    
    create_workers = 1;

    openssl_check_version();

    init_signals();

    init_globals();

    listener_socket = create_main_socket();

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHCUPD_PORT) {
        /* create socket to send(children) and
               receive(parent) cache updates */
    	shcupd_socket = create_shcupd_socket();
    }
#endif /* USE_SHARED_CACHE */

    /* load certificate, pass to handle_connections */
    ssl_ctx = init_openssl();

    if (CONFIG->CHROOT && CONFIG->CHROOT[0])
        change_root();

    if (CONFIG->UID || CONFIG->GID)
        drop_privileges();

    /* should we daemonize ?*/
    if (CONFIG->DAEMONIZE) {
        /* disable logging to stderr */
        CONFIG->QUIET = 1;
        CONFIG->SYSLOG = 1;

        /* become a daemon */
        daemonize();
    }

    master_pid = getpid();

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
