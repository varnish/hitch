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

#include <sched.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ev.h>

#include "ringbuffer.h"
#include "shctx.h"

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

/* Globals */
static struct ev_loop *loop;
static struct addrinfo *backaddr;
static pid_t master_pid;
static ev_io listener;
static int listener_socket;
static int child_num;

/* Command line Options */
typedef enum {
    ENC_TLS,
    ENC_SSL
} ENC_TYPE;

typedef struct stud_options {
    ENC_TYPE ETYPE;
    int WRITE_IP_OCTET;
    int WRITE_PROXY_LINE;
    const char* CHROOT;
    uid_t UID;
    gid_t GID;
    const char *FRONT_IP;
    const char *FRONT_PORT;
    const char *BACK_IP;
    const char *BACK_PORT;
    long NCORES;
    const char *CERT_FILE;
    const char *CIPHER_SUITE;
    int BACKLOG;
#ifdef USE_SHARED_CACHE
    int SHARED_CACHE;
#endif
    int QUIET;
} stud_options;

static stud_options OPTIONS = {
    ENC_TLS,      // ETYPE
    0,            // WRITE_IP_OCTET
    0,            // WRITE_PROXY_LINE
    NULL,         // CHROOT
    0,            // UID
    0,            // GID
    NULL,         // FRONT_IP
    "8443",       // FRONT_PORT
    "127.0.0.1",  // BACK_IP
    "8000",       // BACK_PORT
    1,            // NCORES
    NULL,         // CERT_FILE
    NULL,         // CIPHER_SUITE
    100,          // BACKLOG
#ifdef USE_SHARED_CACHE
    0,            // SHARED_CACHE
#endif
    0             // QUIET
};



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

    int want_shutdown;    /* Connection is half-shutdown */

    SSL *ssl;             /* OpenSSL SSL state */

    struct sockaddr_storage remote_ip;  /* Remote ip returned from `accept` */
} proxystate;

/* set a file descriptor (socket) to non-blocking mode */
static void setnonblocking(int fd) {
    int flag = 1;

    assert (ioctl(fd, FIONBIO, &flag) == 0);
}


static void fail(const char* s) {
    perror(s);
    exit(1);
}

#define LOG(...) \
    do { if (!OPTIONS.QUIET) fprintf(stdout, __VA_ARGS__); } while(0)

#define ERR(...) \
    do { fprintf(stderr, __VA_ARGS__); } while(0)

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

    return 0;
}
#endif /* OPENSSL_NO_DH */

/* Init library and load specified certificate.
 * Establishes a SSL_ctx, to act as a template for
 * each connection */
static SSL_CTX * init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = NULL;

    if (OPTIONS.ETYPE == ENC_TLS)
        ctx = SSL_CTX_new(TLSv1_server_method());
    else if (OPTIONS.ETYPE == ENC_SSL)
        ctx = SSL_CTX_new(SSLv23_server_method());
    else
        assert(OPTIONS.ETYPE == ENC_TLS || OPTIONS.ETYPE == ENC_SSL);

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_ALL |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    if (SSL_CTX_use_certificate_chain_file(ctx, OPTIONS.CERT_FILE) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_RSAPrivateKey_file(ctx, OPTIONS.CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

#ifndef OPENSSL_NO_DH
    init_dh(ctx, OPTIONS.CERT_FILE);
#endif /* OPENSSL_NO_DH */

    if (OPTIONS.CIPHER_SUITE)
        if (SSL_CTX_set_cipher_list(ctx, OPTIONS.CIPHER_SUITE) != 1)
            ERR_print_errors_fp(stderr);

#ifdef USE_SHARED_CACHE
    if (OPTIONS.SHARED_CACHE) {
        if (shared_context_init(ctx, OPTIONS.SHARED_CACHE) < 0) {
            ERR("Unable to alloc memory for shared cache.\n");
            exit(1);
        }
    }
#endif

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
    const int gai_err = getaddrinfo(OPTIONS.FRONT_IP, OPTIONS.FRONT_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    int s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
    setnonblocking(s);

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }
    int timeout = 1; 
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int) );
    prepare_proxy_line(ai->ai_addr);

    freeaddrinfo(ai);
    listen(s, OPTIONS.BACKLOG);

    return s;
}

/* Initiate a clear-text nonblocking connect() to the backend IP on behalf
 * of a newly connected upstream (encrypted) client*/
static int create_back_socket() {
    int s = socket(backaddr->ai_family, SOCK_STREAM, IPPROTO_TCP);
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
        if (OPTIONS.WRITE_PROXY_LINE) {
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
        else if (OPTIONS.WRITE_IP_OCTET) {
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
        assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt(TCP_NODELAY)\n");
    }
    

    setnonblocking(client);
    int back = create_back_socket();

    if (back == -1) {
        close(client);
        perror("{backend-connect}");
        return;
    }

    SSL_CTX * ctx = (SSL_CTX *)w->data;
    SSL *ssl = SSL_new(ctx);
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, client);

    proxystate *ps = (proxystate *)malloc(sizeof(proxystate));

    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->remote_ip = addr;
    ringbuffer_init(&ps->ring_up);
    ringbuffer_init(&ps->ring_down);

    /* set up events */
    ev_io_init(&ps->ev_r_up, client_read, client, EV_READ);
    ev_io_init(&ps->ev_w_up, client_write, client, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, client, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, client, EV_WRITE);

    ev_io_init(&ps->ev_w_down, handle_connect, back, EV_WRITE);

    ev_io_start(loop, &ps->ev_w_down);

    ps->ev_r_up.data = ps;
    ps->ev_w_up.data = ps;
    ps->ev_r_down.data = ps;
    ps->ev_w_down.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;

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
static void handle_connections(SSL_CTX *ctx) {
    LOG("{core} Process %d online\n", child_num);
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
    listener.data = ctx;
    ev_io_start(loop, &listener);

    ev_loop(loop, 0);
    ERR("{core} Child %d exiting.\n", child_num);
    exit(1);
}


/* Print usage w/error message and exit failure */
static void usage_fail(const char *prog, const char *msg) {
    if (msg)
        ERR("%s: %s\n", prog, msg);
    ERR("usage: %s [OPTION] PEM\n", prog);

    ERR(
"Encryption Methods:\n"
"  --tls                    (TLSv1, default)\n"
"  --ssl                    (SSLv3)\n"
"  -c CIPHER_SUITE          (set allowed ciphers)\n"
"\n"
"Socket:\n"
"  -b HOST,PORT             (backend [connect], default \"127.0.0.1,8000\")\n"
"  -f HOST,PORT             (frontend [bind], default \"*,8443\")\n"
"\n"
"Performance:\n"
"  -n CORES                 (number of worker processes, default 1)\n"
"  -B BACKLOG               (set listen backlog size, default 100)\n"
#ifdef USE_SHARED_CACHE
"  -C SHARED_CACHE          (set shared cache size in sessions, by default no shared cache)\n"
#endif
"\n"
"Security:\n"
"  -r PATH                  (chroot)\n"
"  -u USERNAME              (set gid/uid after binding the socket)\n"
"\n"
"Logging:\n"
"  -q                       Be quiet. Emit only error messages\n"
"\n"
"Special:\n"
"  --write-ip               (write 1 octet with the IP family followed by\n"
"                            4 (IPv4) or 16 (IPv6) octets little-endian\n"
"                            to backend before the actual data)\n"
"  --write-proxy            (write HaProxy's PROXY protocol line before actual data:\n"
"                            \"PROXY TCP[64] <source-ip> <dest-ip> <source-port> <dest-port>\\r\\n\"\n"
"                            Note, that dest-ip and dest-port are initialized once after the socket\n"
"                            is bound. This means that you will get 0.0.0.0 as dest-ip instead of \n"
"                            actual IP if that what the listening socket was bound to)\n"
);
    exit(1);
}


static void parse_host_and_port(const char *prog, const char *name, char *inp, int wildcard_okay, const char **ip, const char **port) {
    char buf[150];
    char *sp;

    if (strlen(inp) >= sizeof buf) {
        snprintf(buf, sizeof buf, "invalid option for %s HOST,PORT\n", name);
        usage_fail(prog, buf);
    }

    sp = strchr(inp, ',');
    if (!sp) {
        snprintf(buf, sizeof buf, "invalid option for %s HOST,PORT\n", name);
        usage_fail(prog, buf);
    }

    if (!strncmp(inp, "*", sp - inp)) {
        if (!wildcard_okay) {
            snprintf(buf, sizeof buf, "wildcard host specification invalid for %s\n", name);
            usage_fail(prog, buf);
        }
        *ip = NULL;
    }
    else {
        *sp = 0;
        *ip = inp;
    }
    *port = sp + 1;
}


/* Handle command line arguments modifying behavior */
static void parse_cli(int argc, char **argv) {
    const char *prog = argv[0];

    static int tls = 0, ssl = 0;
    int c;
    struct passwd* passwd;

    static struct option long_options[] =
    {
        {"tls", 0, &tls, 1},
        {"ssl", 0, &ssl, 1},
        {"write-ip", 0, &OPTIONS.WRITE_IP_OCTET, 1},
        {"write-proxy", 0, &OPTIONS.WRITE_PROXY_LINE, 1},
        {0, 0, 0, 0}
    };

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "hf:b:n:c:u:r:B:C:q",
                long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {

        case 0:
            break;

        case 'n':
            errno = 0;
            OPTIONS.NCORES = strtol(optarg, NULL, 10);
            if ((errno == ERANGE &&
                (OPTIONS.NCORES == LONG_MAX || OPTIONS.NCORES == LONG_MIN)) ||
                OPTIONS.NCORES < 1 || OPTIONS.NCORES > 128) {
                usage_fail(prog, "invalid option for -n CORES; please provide an integer between 1 and 128\n");
            }
            break;

        case 'b':
            parse_host_and_port(prog, "-b", optarg, 0, &(OPTIONS.BACK_IP), &(OPTIONS.BACK_PORT));
            break;

        case 'f':
            parse_host_and_port(prog, "-f", optarg, 1, &(OPTIONS.FRONT_IP), &(OPTIONS.FRONT_PORT));
            break;
            
        case 'c':
            OPTIONS.CIPHER_SUITE = optarg;
            break;

        case 'u':
            passwd = getpwnam(optarg);
            if (!passwd) {
                if (errno)
                    fail("getpwnam failed");
                else
                    ERR("user not found: %s\n", optarg);
                exit(1);
            }
            OPTIONS.UID = passwd->pw_uid;
            OPTIONS.GID = passwd->pw_gid;
            break;

        case 'r':
            if (optarg && optarg[0] == '/')
                OPTIONS.CHROOT = optarg;
            else {
                ERR("chroot must be absolute path: \"%s\"\n", optarg);
                exit(1);
            }
            break;

        case 'B':
            OPTIONS.BACKLOG = atoi(optarg);
            if ( OPTIONS.BACKLOG <= 0 ) {
                ERR("listen backlog can not be set to %d\n", OPTIONS.BACKLOG);
                exit(1);
            }
            break;

#ifdef USE_SHARED_CACHE
        case 'C':
            OPTIONS.SHARED_CACHE = atoi(optarg);
            if ( OPTIONS.SHARED_CACHE < 0 ) {
                ERR("shared cache size can not be set to %d\n", OPTIONS.SHARED_CACHE);
                exit(1);
            }
            break;
#endif

        case 'q':
            OPTIONS.QUIET = 1;
            break;

        default:
            usage_fail(prog, NULL);
        }
    }

    /* Post-processing */
    if (tls && ssl)
        usage_fail(prog, "Cannot specify both --tls and --ssl");

    if (ssl)
        OPTIONS.ETYPE = ENC_SSL; // implied.. else, TLS

    if (OPTIONS.WRITE_IP_OCTET && OPTIONS.WRITE_PROXY_LINE)
        usage_fail(prog, "Cannot specify both --write-ip and --write-proxy; pick one!");

    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage_fail(prog, "exactly one argument is required: path to PEM file with cert/key");

    OPTIONS.CERT_FILE = argv[0];
}


void change_root() {
    if (chroot(OPTIONS.CHROOT) == -1)
        fail("chroot");
    if (chdir("/"))
        fail("chdir");
}

void drop_privileges() {
    if (setgid(OPTIONS.GID))
        fail("setgid failed");
    if (setuid(OPTIONS.UID))
        fail("setuid failed");
}


/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and wait for them all to die
 * (which they shouldn't!) */
int main(int argc, char **argv) {
    parse_cli(argc, argv);

    signal(SIGPIPE, SIG_IGN);

    listener_socket = create_main_socket();

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    const int gai_err = getaddrinfo(OPTIONS.BACK_IP, OPTIONS.BACK_PORT,
                                    &hints, &backaddr);
    if (gai_err != 0) {
        ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
        exit(1);
    }

    /* load certificate, pass to handle_connections */
    SSL_CTX * ctx = init_openssl();

    master_pid = getpid();

    if (OPTIONS.CHROOT && OPTIONS.CHROOT[0])
        change_root();

    if (OPTIONS.UID || OPTIONS.GID)
        drop_privileges();

    for (child_num=0; child_num < OPTIONS.NCORES; child_num++) {
        int pid = fork();
        if (pid == -1) {
            ERR("{core} fork() failed! Goodbye cruel world!\n");
            exit(1);
        }
        else if (pid == 0) // child
            goto handle;
    }

    int child_status;
    int dead_child_pid = wait(&child_status);
    ERR("{core} A child (%d) died!  This should not happen! Goodbye cruel world!\n", dead_child_pid);
    kill(0, SIGTERM);
    exit(2);

handle:
    handle_connections(ctx);

    return 0;
}
