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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>

#include <sched.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ev.h>

#include "ringbuffer.h"

/* Globals */
static struct ev_loop *loop;
static struct sockaddr_in backaddr;

/* Command line Options */
typedef enum {
    ENC_TLS,
    ENC_SSL
} ENC_TYPE;

typedef struct stud_options {
    ENC_TYPE ETYPE;
    int WRITE_IP_OCTET;
    int FRONT_IP;
    int FRONT_PORT;
    int BACK_IP;
    int BACK_PORT;
    int NCORES;
    char *CERT_FILE;
} stud_options;

static stud_options OPTIONS;

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

    unsigned int remote_ip;  /* Remote ip returned from `accept` */
} proxystate;

/* set a file descriptor (socket) to non-blocking mode */
static void setnonblocking(int fd) {
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    int fcntl_nonblocking_ok = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    assert (fcntl_nonblocking_ok != -1);
}

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

    if (SSL_CTX_use_certificate_file(ctx, OPTIONS.CERT_FILE, SSL_FILETYPE_PEM) <= 0)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_use_RSAPrivateKey_file(ctx, OPTIONS.CERT_FILE, SSL_FILETYPE_PEM) <= 0)
        ERR_print_errors_fp(stderr);

    return ctx;
}

/* Create the bound IPv4 socket in the parent process */
static int create_main_socket() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
    setnonblocking(s);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = OPTIONS.FRONT_IP;
    addr.sin_port = OPTIONS.FRONT_PORT;
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("{bind-socket}");
        exit(1);
    }

    listen(s, 100);

    return s;
}

/* Initiate a clear-text nonblocking connect() to the backend IP on behalf
 * of a newly connected upstream (encrypted) client*/
static int create_back_socket() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int t = 1;
    setnonblocking(s);
    t = connect(s, (struct sockaddr *)&backaddr, sizeof(backaddr));
    assert(t == -1);
    if (errno == EINPROGRESS || errno == EINTR || errno == 0)
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
        fprintf(stderr, "{backend} Connection reset by peer\n");
    else if (errno == ETIMEDOUT)
        fprintf(stderr, "{backend} Connection to backend timed out\n");
    else if (errno == EPIPE)
        fprintf(stderr, "{backend} Broken pipe to backend (EPIPE)\n");
    else
        perror("{backend} [errno]");
    shutdown_proxy(ps, SHUTDOWN_DOWN);
}

/* Read some data from the backend when libev says data is available--
 * write it into the upstream buffer and make sure the write event is
 * enabled for the upstream socket */
static void back_read(struct ev_loop *loop, ev_io *w, int revents) {
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
        fprintf(stderr, "{backend} Connection closed\n");
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
    int t;
    proxystate *ps = (proxystate *)w->data;
    t = connect(ps->fd_down, (struct sockaddr *)&backaddr, sizeof(backaddr));
    if (!t || errno == EISCONN || !errno) {
        /* INIT */
        ev_io_stop(loop, &ps->ev_w_down);
        ev_io_init(&ps->ev_r_down, back_read, ps->fd_down, EV_READ);
        ev_io_init(&ps->ev_w_down, back_write, ps->fd_down, EV_WRITE);
        start_handshake(ps, SSL_ERROR_WANT_READ); /* for client-first handshake */
        ev_io_start(loop, &ps->ev_r_down);
        if (OPTIONS.WRITE_IP_OCTET) {
            memcpy(ringbuffer_write_ptr(&ps->ring_down), (void *)&ps->remote_ip, sizeof(unsigned int));
            ringbuffer_write_append(&ps->ring_down, sizeof(unsigned int));
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
            fprintf(stderr, "{client} Connection closed (in handshake)\n");
            shutdown_proxy(ps, SHUTDOWN_UP);
        }
        else {
            fprintf(stderr, "{client} Unexpected SSL error (in handshake): %d\n", err);
            shutdown_proxy(ps, SHUTDOWN_UP);
        }
    }
}

/* Handle a socket error condition passed to us from OpenSSL */
static void handle_fatal_ssl_error(proxystate *ps, int err) {
    if (err == SSL_ERROR_ZERO_RETURN)
        fprintf(stderr, "{client} Connection closed (in data)\n");
    else if (err == SSL_ERROR_SYSCALL)
        if (errno == 0)
            fprintf(stderr, "{client} Connection closed (in data)\n");
        else
            perror("{client} [errno] ");
    else
        fprintf(stderr, "{client} Unexpected SSL_read error: %d\n", err);
    shutdown_proxy(ps, SHUTDOWN_UP);
}

/* Read some data from the upstream secure socket via OpenSSL,
 * and buffer anything we get for writing to the backend */
static void client_read(struct ev_loop *loop, ev_io *w, int revents) {
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
    struct sockaddr addr;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, &addr, &sl);
    if (client == -1) {
        assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
        return;
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
    ps->remote_ip = ((struct sockaddr_in*)&addr)->sin_addr.s_addr;
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

/* Set up the child (worker) process including libev event loop, read event
 * on the bound socket, etc */
static void handle_connections(int x, int sock, SSL_CTX *ctx) {
    fprintf(stderr, "{core} Process %d online\n", x);
    cpu_set_t cpus;

    CPU_ZERO(&cpus);
    CPU_SET(x, &cpus);

    int res = sched_setaffinity(0, sizeof(cpus), &cpus);
    if (!res)
        fprintf(stderr, "{core} Successfully attached to CPU #%d\n", x);
    else
        fprintf(stderr, "{core-warning} Unable to attach to CPU #%d; do you have that many cores?\n", x);

    loop = ev_default_loop(EVFLAG_AUTO);
    ev_io listener;

    ev_ref(loop);

    ev_io_init(&listener, handle_accept, sock, EV_READ);
    listener.data = ctx;
    ev_io_start(loop, &listener);

    ev_loop(loop, 0);
    fprintf(stderr, "{core-error} Child %d returned from ev_loop()!\n", x);
    exit(1);
}


/* Print usage w/error message and exit failure */
static void usage_fail(char *prog, char *msg) {
    if (msg)
        fprintf(stderr, "%s: %s\n", prog, msg);
    fprintf(stderr, "usage: %s [OPTION] PEM\n", prog);

    fprintf(stderr,
"Encryption Methods:\n"
"  --tls                    (TLSv1, default)\n"
"  --ssl                    (SSLv2/SSLv3)\n"
"\n"
"Socket:\n"
"  -b HOST:PORT             (backend [connect], default \"127.0.0.1:8000\")\n"
"  -f HOST:PORT             (frontend [bind], default \"*:8443\")\n"
"\n"
"Performance:\n"
"  -n CORES                 (number of worker processes, default 1)\n"
"\n"
"Special:\n"
"  --write-ipv4             (write remote IPv4 in first 4 octets\n"
"                            little-endian to backend)\n"
);
    exit(1);
}


static void parse_host_and_port(char *prog, char *name, char *inp, int wildcard_okay, int *ip, int *port) {
    struct in_addr read_addr;
    char buf[150];
    char *sp;
    int res;

    if (strlen(inp) > 149) {
        sprintf(buf, "invalid option for %s HOST:PORT\n", name);
        usage_fail(prog, buf);
    }

    sp = strchr(inp, ':');
    if (!sp) {
        sprintf(buf, "invalid option for %s HOST:PORT\n", name);
        usage_fail(prog, buf);
    }

    if (!strncmp(inp, "*", sp - inp)) {
        if (!wildcard_okay) {
            sprintf(buf, "wildcard host specification invalid for %s\n", name);
            usage_fail(prog, buf);
        }
        *ip = INADDR_ANY;
    }
    else {
        strncpy(buf, inp, sp-inp);
        buf[sp-inp] = 0;
        res = inet_pton(AF_INET, buf, &read_addr);
        if (res != 1) {
            sprintf(buf, 
            "invalid format for %s HOST:PORT option; use \"127.0.0.1:8000\" or similar\n", name);
            usage_fail(prog, buf);
        }
        *ip = read_addr.s_addr;
    }

    *port = strtol(sp + 1, NULL, 10);
    if (errno || *port < 1 || *port > 65536) 
        usage_fail(prog, "invalid option for PORT; please provide a port number between 1 and 65536\n");
    *port = htons(*port);
}


/* Handle command line arguments modifying behavior */
static void parse_cli(int argc, char **argv) {
    char *prog = argv[0];
    OPTIONS.FRONT_IP = INADDR_ANY;
    OPTIONS.FRONT_PORT = htons(8443);

    OPTIONS.BACK_IP = (127 | 1 << 24);
    OPTIONS.BACK_PORT = htons(8000);

    OPTIONS.ETYPE = ENC_TLS;

    OPTIONS.NCORES = 1;

    OPTIONS.WRITE_IP_OCTET = 0;

    static int tls = 0, ssl = 0, writeip = 0;
    int c;

    static struct option long_options[] =
    {
        {"tls", 0, &tls, 1},
        {"ssl", 0, &ssl, 1},
        {"write-ipv4", 0, &writeip, 1},
        {0, 0, 0, 0}
    };

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "hf:b:n:",
                long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {

        case 0:
            break;

        case 'n':
            OPTIONS.NCORES = strtol(optarg, NULL, 10);
            if (errno || OPTIONS.NCORES < 1 || OPTIONS.NCORES > 128)
                usage_fail(prog, "invalid option for -n CORES; please provide an integer between 1 and 128\n");
            break;

        case 'b':
            parse_host_and_port(prog, "-b", optarg, 0, &(OPTIONS.BACK_IP), &(OPTIONS.BACK_PORT));
            break;

        case 'f':
            parse_host_and_port(prog, "-f", optarg, 1, &(OPTIONS.FRONT_IP), &(OPTIONS.FRONT_PORT));
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

    if (writeip)
        OPTIONS.WRITE_IP_OCTET = 1;

    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage_fail(prog, "exactly one argument is required: path to PEM file with cert/key");

    OPTIONS.CERT_FILE = argv[0];
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and wait for them all to die
 * (which they shouldn't!) */
int main(int argc, char **argv) {
    parse_cli(argc, argv);

    int s = create_main_socket();
    int x;

    backaddr.sin_family = AF_INET;
    backaddr.sin_addr.s_addr = OPTIONS.BACK_IP;
    backaddr.sin_port = OPTIONS.BACK_PORT;

    /* load certificate, pass to handle_connections */
    SSL_CTX * ctx = init_openssl();

    for (x=0; x < OPTIONS.NCORES; x++) {
        int pid = fork();
        if (pid == -1) {
            fprintf(stderr, "{core} fork() failed! Goodbye cruel world!\n");
            exit(1);
        }
        else if (pid == 0) // child
            goto handle;
    }

    int child_status;
    for (x=0; x < OPTIONS.NCORES; x++) {
        wait(&child_status);
        fprintf(stderr, "{core} A child died!  This should not happen! Goodbye cruel world!\n");
        exit(2);
    }

handle:
    handle_connections(x, s, ctx);

    return 0;
}
