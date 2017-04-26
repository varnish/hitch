/**
  * Copyright 2015-2016 Varnish Software
  * Copyright 2011 Bump Technologies, Inc. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions
  * are met:
  *
  *    1. Redistributions of source code must retain the above
  *       copyright notice, this list of conditions and the following
  *       disclaimer.
  *
  *    2. Redistributions in binary form must reproduce the above
  *       copyright notice, this list of conditions and the following
  *       disclaimer in the documentation and/or other materials
  *       provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY BUMP TECHNOLOGIES, INC. ``AS IS'' AND
  * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
  * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
  * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BUMP
  * TECHNOLOGIES, INC. OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
  * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  * The views and conclusions contained in the software and
  * documentation are those of the authors and should not be
  * interpreted as representing official policies, either expressed or
  * implied, of Bump Technologies, Inc.
  *
  */

#include "config.h"

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* TCP_NODELAY */
#include <net/if.h>

#include <libgen.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>  /* WAIT_PID */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifdef __sun
#include <sys/filio.h>
#endif

#include "configuration.h"
#include "hitch.h"
#include "hssl_locks.h"
#include "logging.h"
#include "ocsp.h"
#include "shctx.h"
#include "foreign/vpf.h"
#include "foreign/uthash.h"

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

/* logging.c */
extern FILE *logfile;
extern struct stat logf_st;
extern time_t logf_check_t;


/* Globals */
struct ev_loop *loop;
hitch_config *CONFIG;

/* Worker proc's read side of mgt->worker pipe(2) */
static ev_io mgt_rd;

static struct addrinfo *backaddr;
static pid_t master_pid;
static pid_t ocsp_proc_pid;
static int core_id;
static SSL_SESSION *client_session;

/* The current number of active client connections. */
static uint64_t n_conns;

/* Current generation of worker processes. Bumped after a sighup prior
 * to launching new children. */
static unsigned worker_gen;

static volatile unsigned n_sighup;
static volatile unsigned n_sigchld;

enum worker_state_e {
	WORKER_ACTIVE,
	WORKER_EXITING
};

static enum worker_state_e worker_state;

struct worker_proc {
	unsigned			magic;
#define WORKER_PROC_MAGIC		0xbc7fe9e6

	/* Writer end of pipe(2) for mgt -> worker ipc */
	int				pfd;
	pid_t				pid;
	unsigned			gen;
	int				core_id;
	VTAILQ_ENTRY(worker_proc)	list;
};

VTAILQ_HEAD(worker_proc_head, worker_proc);
static struct worker_proc_head worker_procs;
struct sslctx_s;
struct sni_name_s;

struct listen_sock {
	unsigned		magic;
#define LISTEN_SOCK_MAGIC	0xda96b2f6
	int			sock;
	char			*name;
	ev_io			listener;
	struct sockaddr_storage	addr;
	VTAILQ_ENTRY(listen_sock)	list;
};

VTAILQ_HEAD(listen_sock_head, listen_sock);

struct frontend {
	unsigned		magic;
#define FRONTEND_MAGIC	 	0x5b04e577
	int			match_global_certs;
	int			sni_nomatch_abort;
	struct sni_name_s	*sni_names;
	struct sslctx_s		*ssl_ctxs;
	char			*pspec;
	struct listen_sock_head	socks;
	VTAILQ_ENTRY(frontend)	list;
};

VTAILQ_HEAD(frontend_head, frontend);

static struct frontend_head frontends;

#ifdef USE_SHARED_CACHE
static ev_io shcupd_listener;
static int shcupd_socket;
struct addrinfo *shcupd_peers[MAX_SHCUPD_PEERS+1];
static unsigned char shared_secret[SHA_DIGEST_LENGTH];
#endif /*USE_SHARED_CACHE*/


int create_workers;
static struct vpf_fh *pfh = NULL;

static char tcp_proxy_line[128] = "";

/* What agent/state requests the shutdown--for proper half-closed
 * handling */
typedef enum _SHUTDOWN_REQUESTOR {
	SHUTDOWN_HARD,
	SHUTDOWN_CLEAR,
	SHUTDOWN_SSL
} SHUTDOWN_REQUESTOR;

static const char *SHUTDOWN_STR[] = {
	[SHUTDOWN_HARD] = "SHUTDOWN_HARD",
	[SHUTDOWN_CLEAR] = "SHUTDOWN_CLEAR",
	[SHUTDOWN_SSL] = "SHUTDOWN_SSL",
};

#ifndef OPENSSL_NO_TLSEXT

sni_name *sni_names;
static sslctx *ssl_ctxs;
static sslctx *default_ctx;

static void insert_sni_names(sslctx *sc, sni_name **sn_tab);
static int load_cert_ctx(sslctx *so);
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
	} local;
};

struct ha_proxy_v2_hdr {
	uint8_t			sig[12];
	uint8_t			ver_cmd;
	uint8_t			fam;
	uint16_t		len;	/* number of following bytes
					 * part of the header */
	union ha_proxy_v2_addr	addr;
};


/* set a file descriptor (socket) to non-blocking mode */
static int
setnonblocking(int fd)
{
	int flag = 1;

	if (ioctl(fd, FIONBIO, &flag) < 0) {
		assert (errno == ECONNRESET || errno == ENOTCONN);
		return (-1);
	}

	return (0);
}


/* set a tcp socket to use TCP Keepalive */
static void
settcpkeepalive(int fd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

	if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
		SOCKERR("Error activating SO_KEEPALIVE on client socket");
	}

#ifdef TCP_KEEPIDLE
	optval = CONFIG->TCP_KEEPALIVE_TIME;
	optlen = sizeof(optval);
	if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
		SOCKERR("Error setting TCP_KEEPIDLE on client socket");
	}
#endif
}


#ifndef OPENSSL_NO_DH
static int
init_dh(SSL_CTX *ctx, const char *cert)
{
	DH *dh;
	BIO *bio;

	AN(cert);

	bio = BIO_new_file(cert, "r");
	if (!bio) {
		log_ssl_error(NULL, "{core} BIO_new_file");
		return (-1);
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!dh) {
		LOG("{core} Note: no DH parameters found in %s\n", cert);
		return (-1);
	}

	LOG("{core} Using DH parameters from %s\n", cert);
	if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
		log_ssl_error(NULL, "{core} Error setting temp DH params");
		return (-1);
	}
	LOG("{core} DH initialized with %d bit key\n", 8*DH_size(dh));
	DH_free(dh);
	return (0);
}

static int init_ecdh(SSL_CTX *ctx) {
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
static void
info_callback(const SSL *ssl, int where, int ret)
{
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

#ifdef OPENSSL_WITH_NPN
static int npn_select_cb(SSL *ssl, const unsigned char **out,
    unsigned *outlen, void *arg) {
	proxystate *ps;
	(void)arg;
	CAST_OBJ_NOTNULL(ps, SSL_get_app_data(ssl), PROXYSTATE_MAGIC);
	ps->npn_alpn_tried = 1;

	LOG("{npn} Got NPN callback\n");
	*out = (unsigned char *) CONFIG->ALPN_PROTOS_LV;
	*outlen = CONFIG->ALPN_PROTOS_LV_LEN;

	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef OPENSSL_WITH_ALPN
static int alpn_select_cb(SSL *ssl,
    const unsigned char **out,
    unsigned char *outlen,
    const unsigned char *in,
    unsigned int inlen,
    void *arg)
{
	int selected;
	proxystate *ps;
	(void)arg;

	CAST_OBJ_NOTNULL(ps, SSL_get_app_data(ssl), PROXYSTATE_MAGIC);
	ps->npn_alpn_tried = 1;

	selected = SSL_select_next_proto((unsigned char **)out, outlen,
	    CONFIG->ALPN_PROTOS_LV, CONFIG->ALPN_PROTOS_LV_LEN, in, inlen);
	if (selected == OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_OK;
	else {
		assert(selected == OPENSSL_NPN_NO_OVERLAP);
		LOGPROXY(ps, "ALPN: no overlap in protocols.\n");
		/* Here it is possible to add logging of which protocols
		   the client wanted */
		return SSL_TLSEXT_ERR_NOACK;
	}
	return SSL_TLSEXT_ERR_NOACK;
}
#endif

#ifdef USE_SHARED_CACHE

/* Handle incoming message updates */
static void
handle_shcupd(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	unsigned char msg[SHSESS_MAX_ENCODED_LEN], hash[EVP_MAX_MD_SIZE];
	ssize_t r;
	unsigned int hash_len;
	uint32_t encdate;
	long now = (time_t)ev_now(loop);

	while ((r = recv(w->fd, msg, sizeof(msg), 0)) > 0) {
		/* msg len must be greater than 1 Byte of data + sig length */
		if (r < (int)(1+sizeof(shared_secret)))
			continue;

		/* compute sig */
		r -= sizeof(shared_secret);
		HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret), msg,
		    r, hash, &hash_len);

		if (hash_len != sizeof(shared_secret)) /* should never happen */
		   continue;

		/* check sign */
		if (memcmp(msg+r, hash, hash_len))
			continue;

		/* msg len must be greater than 1 Byte of data +
		 * encdate length */
		if (r < (int)(1+sizeof(uint32_t)))
			continue;

		/* drop too unsync updates */
		r -= sizeof(uint32_t);
		encdate = *((uint32_t *)&msg[r]);
		if (!(abs((int)(int32_t)now - ntohl(encdate))
			< SSL_CTX_get_timeout(default_ctx->ctx)))
			continue;

		shctx_sess_add(msg, r, now);
	}
}

/* Send remote updates messages callback */
void
shcupd_session_new(unsigned char *msg, unsigned int len, long cdate)
{
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
		sendto(shcupd_socket, msg, len, 0, (*pai)->ai_addr,
		    (*pai)->ai_addrlen);
		pai++;
	}
}

/* Compute a sha1 secret from an ASN1 rsa private key */
static int
compute_secret(RSA *rsa, unsigned char *secret)
{
	unsigned char *buf, *p;
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
static int
create_shcupd_socket()
{
	struct addrinfo *ai, hints;
	struct addrinfo **pai = shcupd_peers;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	const int gai_err = getaddrinfo(CONFIG->SHCUPD_IP,
	    CONFIG->SHCUPD_PORT, &hints, &ai);
	if (gai_err != 0) {
		ERR("{getaddrinfo}: %s\n", gai_strerror(gai_err));
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
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT_WORKS
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif

	if (setnonblocking(s) < 0)
		fail("{shared cache: setnonblocking}");

	if (ai->ai_addr->sa_family == AF_INET) {
		struct ip_mreqn mreqn;

		memset(&mreqn, 0, sizeof(mreqn));
		mreqn.imr_multiaddr.s_addr =
		    ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

		if (CONFIG->SHCUPD_MCASTIF) {
			if (isalpha(*CONFIG->SHCUPD_MCASTIF)) {
				/* appears to be an iface name */
				struct ifreq ifr;
				memset(&ifr, 0, sizeof(ifr));
				if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
					ERR("Error iface name is too "
					    "long [%s]\n",
					    CONFIG->SHCUPD_MCASTIF);
					exit(1);
				}

				memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF,
				    strlen(CONFIG->SHCUPD_MCASTIF));
				if (ioctl(s, SIOCGIFINDEX, &ifr)) {
					fail("{ioctl: SIOCGIFINDEX}");
				}

				mreqn.imr_ifindex = ifr.ifr_ifindex;
			} else if (strchr(CONFIG->SHCUPD_MCASTIF,'.')) {
				/* appears to be an ipv4 address */
				mreqn.imr_address.s_addr =
				    inet_addr(CONFIG->SHCUPD_MCASTIF);
			} else {
				/* appears to be an iface index */
				mreqn.imr_ifindex =
				    atoi(CONFIG->SHCUPD_MCASTIF);
			}
		}

		if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    &mreqn, sizeof(mreqn)) < 0) {
			if (errno != EINVAL) {
				/* EINVAL if it is not a multicast address,
				 * not an error we consider unicast */
				fail("{setsockopt: IP_ADD_MEMBERSIP}");
			}
		} else { /* this is a multicast address */
			unsigned char loop = 0;
			if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
				&loop, sizeof(loop)) < 0) {
				fail("{setsockopt: IP_MULTICAST_LOOP}");
			}
		}

		/* optional set sockopts for sending to multicast msg */
		if (CONFIG->SHCUPD_MCASTIF &&
		    setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
		    &mreqn, sizeof(mreqn)) < 0) {
			fail("{setsockopt: IP_MULTICAST_IF}");
		}

		if (CONFIG->SHCUPD_MCASTTTL) {
			unsigned char ttl;

			ttl = (unsigned char)atoi(CONFIG->SHCUPD_MCASTTTL);
			if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
			    &ttl, sizeof(ttl)) < 0) {
				fail("{setsockopt: IP_MULTICAST_TTL}");
			}
		}
	 }
#ifdef IPV6_ADD_MEMBERSHIP
	 else if (ai->ai_addr->sa_family == AF_INET6) {
		struct ipv6_mreq mreq;

		memset(&mreq, 0, sizeof(mreq));
		memcpy(&mreq.ipv6mr_multiaddr,
		    &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		    sizeof(mreq.ipv6mr_multiaddr));

		if (CONFIG->SHCUPD_MCASTIF) {
			if (isalpha(*CONFIG->SHCUPD_MCASTIF)) {
				/* appears to be an iface name */
				struct ifreq ifr;

				memset(&ifr, 0, sizeof(ifr));
				if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
					ERR("Error iface name is too "
					    "long [%s]\n",
					    CONFIG->SHCUPD_MCASTIF);
					exit(1);
				}

				memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF,
				    strlen(CONFIG->SHCUPD_MCASTIF));

				if (ioctl(s, SIOCGIFINDEX, &ifr))
					fail("{ioctl: SIOCGIFINDEX}");

				mreq.ipv6mr_interface = ifr.ifr_ifindex;
			} else { /* option appears to be an iface index */
				mreq.ipv6mr_interface =
				    atoi(CONFIG->SHCUPD_MCASTIF);
			}
		}

		if (setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
		    &mreq, sizeof(mreq)) < 0) {
			if (errno != EINVAL) {
				/* EINVAL if it is not a multicast address,
				 * not an error we consider unicast */
				fail("{setsockopt: IPV6_ADD_MEMBERSIP}");
			}
		} else { /* this is a multicast address */
			unsigned int loop = 0;
			if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			    &loop, sizeof(loop)) < 0) {
				fail("{setsockopt: IPV6_MULTICAST_LOOP}");
			}
		}
		/* optional set sockopts for sending to multicast msg */
		if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		    &mreq.ipv6mr_interface,
		    sizeof(mreq.ipv6mr_interface)) < 0) {
			fail("{setsockopt: IPV6_MULTICAST_IF}");
		}

		if (CONFIG->SHCUPD_MCASTTTL) {
			int hops;

			hops = atoi(CONFIG->SHCUPD_MCASTTTL);
			if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			    &hops, sizeof(hops)) < 0) {
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

EVP_PKEY *
load_privatekey(SSL_CTX *ctx, const char *file)
{
	BIO *bio;
	EVP_PKEY *pkey;

	bio = BIO_new_file(file, "r");
	if (!bio) {
		log_ssl_error(NULL, "{core} BIO_new_file");
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define SSL_CTX_get_default_passwd_cb(ctx) (ctx->default_passwd_callback)
#define SSL_CTX_get_default_passwd_cb_userdata(ctx) (ctx->default_passwd_callback_userdata)
#endif
	pkey = PEM_read_bio_PrivateKey(bio, NULL,
	    SSL_CTX_get_default_passwd_cb(ctx),
	    SSL_CTX_get_default_passwd_cb_userdata(ctx));
	BIO_free(bio);

	return (pkey);
}

#ifndef OPENSSL_NO_TLSEXT
static int
sni_match(const sni_name *sn, const char *srvname)
{
	if (!sn->is_wildcard)
		return (strcasecmp(srvname, sn->servername) == 0);
	else {
		char *s = strchr(srvname, '.');
		if (s == NULL)
			return (0);
		return (strcasecmp(s, sn->servername + 1) == 0);
	}
}

static sslctx *
sni_lookup(const char *servername, const sni_name *sn_tab)
{
	const sni_name *sn;

	HASH_FIND_STR(sn_tab, servername, sn);
	if (sn == NULL) {
		char *s;
		/* attempt another lookup for wildcard matches */
		s = strchr(servername, '.');
		if (s != NULL) {
			HASH_FIND_STR(sn_tab, s, sn);
		}
	}

	if (sn != NULL) {
		CHECK_OBJ_NOTNULL(sn, SNI_NAME_MAGIC);
		if (sni_match(sn, servername))
			return (sn->sctx);
	}

	return (NULL);
}

/*
 * Switch the context of the current SSL object to the most appropriate one
 * based on the SNI header
 */
static int
sni_switch_ctx(SSL *ssl, int *al, void *data)
{
	const char *servername;
	sslctx *sc;
	const struct frontend *fr = NULL;
	int lookup_global = 1;
	int sni_nomatch_abort = CONFIG->SNI_NOMATCH_ABORT;

	(void)al;
	if (data != NULL)
		CAST_OBJ_NOTNULL(fr, data, FRONTEND_MAGIC);

	servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return (SSL_TLSEXT_ERR_NOACK);

#define TRY_SNI_MATCH(sn_tab)					\
	do {							\
		sc = sni_lookup(servername, (sn_tab));		\
		if (sc != NULL) {				\
			CHECK_OBJ_NOTNULL(sc, SSLCTX_MAGIC);	\
			SSL_set_SSL_CTX(ssl, sc->ctx);		\
			return (SSL_TLSEXT_ERR_OK);		\
		}						\
	} while (0)

	if (fr != NULL) {
		TRY_SNI_MATCH(fr->sni_names);
		lookup_global = fr->match_global_certs;
		if (fr->sni_nomatch_abort != -1)
			sni_nomatch_abort = fr->sni_nomatch_abort;
	}

	if (lookup_global)
		TRY_SNI_MATCH(sni_names);

	/* No matching certs */
	if (sni_nomatch_abort)
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	else
		return (SSL_TLSEXT_ERR_NOACK);
}
#endif /* OPENSSL_NO_TLSEXT */

static void
sctx_free(sslctx *sc, sni_name **sn_tab)
{
	sni_name *sn, *sntmp;

	if (sc == NULL)
		return;

	HOCSP_free(&sc->staple);

	if (sn_tab != NULL)
		CHECK_OBJ_NOTNULL(*sn_tab, SNI_NAME_MAGIC);

	CHECK_OBJ_NOTNULL(sc, SSLCTX_MAGIC);
	VTAILQ_FOREACH_SAFE(sn, &sc->sni_list, list, sntmp) {
		CHECK_OBJ_NOTNULL(sn, SNI_NAME_MAGIC);
		VTAILQ_REMOVE(&sc->sni_list, sn, list);
		if (sn_tab != NULL)
			HASH_DEL(*sn_tab, sn);
		free(sn->servername);
		FREE_OBJ(sn);
	}

	free(sc->filename);
	SSL_CTX_free(sc->ctx);
	FREE_OBJ(sc);
}

X509 *
Find_issuer(X509 *subj, STACK_OF(X509) *chain)
{
       int i;
       X509 *x;

       AN(subj);

       for (i = 0; i < sk_X509_num(chain); i++) {
               x = sk_X509_value(chain, i);
               if (X509_check_issued(x, subj) == X509_V_OK)
                       return (x);
       }

       /* todo: look in cert store?  */

       return (NULL);
}



/* Initialize an SSL context */
static sslctx *
make_ctx_fr(const struct cfg_cert_file *cf, const struct frontend *fr,
    const struct front_arg *fa)
{
	SSL_CTX *ctx;
	sslctx *sc;
	EVP_PKEY *pkey;
	int selected_protos = CONFIG->SELECTED_TLS_PROTOS;
	char *ciphers = CONFIG->CIPHER_SUITE;
	int pref_srv_ciphers = CONFIG->PREFER_SERVER_CIPHERS;

	if (fa != NULL) {
		CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);
		if (fa->selected_protos != 0)
			selected_protos = fa->selected_protos;
		if (fa->ciphers != NULL)
			ciphers = fa->ciphers;
		if (fa->prefer_server_ciphers != -1)
			pref_srv_ciphers = fa->prefer_server_ciphers;
	}

	long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL |
	    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

#ifdef SSL_OP_NO_COMPRESSION
	ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
#ifdef SSL_OP_SINGLE_DH_USE
	ssloptions |= SSL_OP_SINGLE_DH_USE;
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
	ssloptions |= SSL_OP_SINGLE_ECDH_USE;
#endif
	if (!(selected_protos & SSLv3_PROTO))
		ssloptions |= SSL_OP_NO_SSLv3;
	if (!(selected_protos & TLSv1_0_PROTO))
		ssloptions |= SSL_OP_NO_TLSv1;
	if (!(selected_protos & TLSv1_1_PROTO))
		ssloptions |= SSL_OP_NO_TLSv1_1;
	if (!(selected_protos & TLSv1_2_PROTO))
		ssloptions |= SSL_OP_NO_TLSv1_2;
	ctx = SSL_CTX_new((CONFIG->PMODE == SSL_CLIENT) ?
	    SSLv23_client_method() : SSLv23_server_method());

	SSL_CTX_set_options(ctx, ssloptions);
	SSL_CTX_set_info_callback(ctx, info_callback);
#ifdef OPENSSL_WITH_ALPN
	if (CONFIG->ALPN_PROTOS != NULL)
		SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
#endif
#ifdef OPENSSL_WITH_NPN
	if (CONFIG->ALPN_PROTOS != NULL)
		SSL_CTX_set_next_protos_advertised_cb(ctx, npn_select_cb, NULL);
#endif
	AN(SSL_CTX_set_default_verify_paths(ctx));

	if (ciphers != NULL) {
		if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1) {
			log_ssl_error(NULL, "{core} SSL_CTX_set_cipher_list");
			return (NULL);
		}
	}

	if (pref_srv_ciphers)
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

	ALLOC_OBJ(sc, SSLCTX_MAGIC);
	AN(sc);
	sc->filename = strdup(cf->filename);
	sc->mtim = cf->mtim;
	sc->ctx = ctx;
	sc->staple_vfy = cf->ocsp_vfy;
	VTAILQ_INIT(&sc->sni_list);

	if (CONFIG->PMODE == SSL_CLIENT)
		return (sc);

	/* SSL_SERVER Mode stuff */
	if (SSL_CTX_use_certificate_chain_file(ctx, cf->filename) <= 0) {
		log_ssl_error(NULL,
		    "Error loading certificate file %s\n", cf->filename);
		sctx_free(sc, NULL);
		return (NULL);
	}

	pkey = load_privatekey(ctx, cf->filename);
	if (!pkey) {
		ERR("Error loading private key (%s)\n", cf->filename);
		sctx_free(sc, NULL);
		return (NULL);
	}

	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
		log_ssl_error(NULL, "SSL_CTX_use_PrivateKey: %s",
		    cf->filename);
		EVP_PKEY_free(pkey);
		sctx_free(sc, NULL);
		return (NULL);
	}

#ifndef OPENSSL_NO_DH
	init_dh(ctx, cf->filename);
	init_ecdh(ctx);
#endif /* OPENSSL_NO_DH */

#ifndef OPENSSL_NO_TLSEXT
	if (!SSL_CTX_set_tlsext_servername_callback(ctx, sni_switch_ctx)) {
		ERR("Error setting up SNI support.\n");
	}
	CHECK_OBJ_ORNULL(fr, FRONTEND_MAGIC);
	if (!SSL_CTX_set_tlsext_servername_arg(ctx, fr)) {
		ERR("Error setting SNI servername arg.\n");
	}

	if (load_cert_ctx(sc) != 0) {
		EVP_PKEY_free(pkey);
		sctx_free(sc, NULL);
		return (NULL);
	}

	if (CONFIG->OCSP_DIR) {
		char *fn = HOCSP_fn(sc->filename);
		/* attempt loading of cached ocsp staple */
		if (fn != NULL && HOCSP_init_file(fn, sc, 1) == 0) {
			LOG("{core} Loaded cached OCSP staple for cert '%s'\n",
			    sc->filename);
			sc->staple_fn = fn;
		}
	}

	if (sc->staple == NULL && cf->ocspfn != NULL) {
		if (HOCSP_init_file(cf->ocspfn, sc, 0) != 0) {
			ERR("Error loading OCSP response %s for stapling.\n",
			    cf->ocspfn);
			EVP_PKEY_free(pkey);
			sctx_free(sc, NULL);
			return (NULL);
		} else {
			LOG("{core} Loaded OCSP staple '%s'\n", cf->ocspfn);
			sc->staple_fn = strdup(cf->ocspfn);
			sc->staple->mtim = cf->ocsp_mtim;
		}
	}

	if (CONFIG->OCSP_DIR != NULL)
		HOCSP_ev_stat(sc);

#endif /* OPENSSL_NO_TLSEXT */

#ifdef USE_SHARED_CACHE
	if (CONFIG->SHARED_CACHE) {
		if (shared_context_init(ctx, CONFIG->SHARED_CACHE) < 0) {
			ERR("Unable to alloc memory for shared cache.\n");
			EVP_PKEY_free(pkey);
			sctx_free(sc, NULL);
			return (NULL);
		}
		if (CONFIG->SHCUPD_PORT) {
			RSA *rsa;
			rsa = EVP_PKEY_get1_RSA(pkey);
			if (rsa != NULL &&
			    compute_secret(rsa, shared_secret) < 0) {
				ERR("Unable to compute shared secret.\n");
				EVP_PKEY_free(pkey);
				sctx_free(sc, NULL);
				return (NULL);
			}

			/* Force TLS tickets because keys differs. */
			SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

			if (*shcupd_peers) {
				shsess_set_new_cbk(shcupd_session_new);
			}
		}
	}
#endif
	EVP_PKEY_free(pkey);
	return (sc);
}

static void
insert_sni_names(sslctx *sc, sni_name **sn_tab)
{
	sni_name *sn, *sn2;
	char *key;
	CHECK_OBJ_NOTNULL(sc, SSLCTX_MAGIC);

	VTAILQ_FOREACH(sn, &sc->sni_list, list) {
		CHECK_OBJ_NOTNULL(sn, SNI_NAME_MAGIC);
		key = sn->servername;
		if (sn->is_wildcard)
			key = sn->servername + 1;
		HASH_FIND_STR(*sn_tab, key, sn2);
		if (sn2 != NULL) {
			ERR("Warning: SNI name '%s' from '%s' overridden"
			    " by '%s'\n",
			    key, sn2->sctx->filename, sn->sctx->filename);
		}
		HASH_ADD_KEYPTR(hh, *sn_tab, key, strlen(key), sn);
	}
}

static sslctx *
make_ctx(const struct cfg_cert_file *cf)
{
	return (make_ctx_fr(cf, NULL, NULL));
}
#ifndef OPENSSL_NO_TLSEXT
static int
load_cert_ctx(sslctx *so)
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
		sni_name *sn;						\
		ALLOC_OBJ(sn, SNI_NAME_MAGIC);				\
		ASN1_STRING_to_UTF8(					\
			(unsigned char **)&sn->servername, asn1_str);	\
		sn->is_wildcard =					\
		    (strstr(sn->servername, "*.") == sn->servername);	\
		sn->sctx = so;						\
		VTAILQ_INSERT_TAIL(&so->sni_list, sn, list);		\
	} while (0)

	f = BIO_new(BIO_s_file());
	// TODO: error checking

	if (!BIO_read_filename(f, so->filename)) {
		ERR("Could not read certificate '%s'\n", so->filename);
		return (1);
	}
	x509 = PEM_read_bio_X509_AUX(f, NULL, NULL, NULL);
	BIO_free(f);

	so->x509 = x509;

	/* First, look for Subject Alternative Names. */
	names = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
		name = sk_GENERAL_NAME_value(names, i);
		if (name->type == GEN_DNS) {
			PUSH_CTX(name->d.dNSName, ctx);
		}
	}
	if (sk_GENERAL_NAME_num(names) > 0) {
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		/* If we found some, don't bother looking any further. */
		return (0);
	} else if (names != NULL) {
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
	}

	/* Now we're left looking at the CN on the cert. */
	x509_name = X509_get_subject_name(x509);
	i = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1);
	if (i < 0) {
		ERR("Could not find Subject Alternative Names"
		    " or a CN on cert %s\n", so->filename);
		return (1);
	}
	x509_entry = X509_NAME_get_entry(x509_name, i);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_NAME_ENTRY_get_data(e) (e->value)
#endif
	AN(x509_entry);
	PUSH_CTX(X509_NAME_ENTRY_get_data(x509_entry), ctx);

	return (0);
}
#endif /* OPENSSL_NO_TLSEXT */

/* Check that we don't needlessly load a cert that's already loaded. */
static sslctx *
find_ctx(const char *file)
{
	sslctx *so;
	HASH_FIND_STR(ssl_ctxs, file, so);
	return (so);
}

/* Init library and load specified certificate.
 * Establishes a SSL_ctx, to act as a template for
 * each connection */
void
init_openssl(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_digests();

	if (CONFIG->ENGINE) {
		ENGINE *e = NULL;
		ENGINE_load_builtin_engines();
		HSSL_Locks_Init();
		if (!strcmp(CONFIG->ENGINE, "auto"))
			ENGINE_register_all_complete();
		else {
			if ((e = ENGINE_by_id(CONFIG->ENGINE)) == NULL ||
			    !ENGINE_init(e) ||
			    !ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
				log_ssl_error(NULL,
				    "{core} ENGINE initialization failed");
				exit(1);
			}
			LOG("{core} will use OpenSSL engine %s.\n",
			    ENGINE_get_id(e));
			ENGINE_finish(e);
			ENGINE_free(e);
		}
	}
}

static void
init_certs(void) {
	struct cfg_cert_file *cf, *cftmp;
	sslctx *so;

	if (CONFIG->CERT_DEFAULT != NULL) {
		AN(CONFIG->CERT_DEFAULT);
		default_ctx = make_ctx(CONFIG->CERT_DEFAULT);
		if (default_ctx == NULL)
			exit(1);
#ifndef OPENSSL_NO_TLSEXT
		insert_sni_names(default_ctx, &sni_names);
#endif
	}

	// Go through the list of PEMs and make some SSL contexts for
	// them. We also keep track of the names associated with each
	// cert so we can do SNI on them later
	HASH_ITER(hh, CONFIG->CERT_FILES, cf, cftmp) {
		if (find_ctx(cf->filename) == NULL) {
			so = make_ctx(cf);
			if (so == NULL)
				exit(1);
			HASH_ADD_KEYPTR(hh, ssl_ctxs, cf->filename,
			    strlen(cf->filename), so);
#ifndef OPENSSL_NO_TLSEXT
			insert_sni_names(so, &sni_names);
#endif
		}
	}
}

static void
destroy_lsock(struct listen_sock *ls)
{
	CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
	if (ls->sock > 0)
		(void) close(ls->sock);
	free(ls->name);
	FREE_OBJ(ls);
}

static void
destroy_frontend(struct frontend *fr)
{
	struct listen_sock *ls, *lstmp;
	sslctx *sc, *sctmp;

	CHECK_OBJ_NOTNULL(fr, FRONTEND_MAGIC);

	VTAILQ_FOREACH_SAFE(ls, &fr->socks, list, lstmp) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		VTAILQ_REMOVE(&fr->socks, ls, list);
		destroy_lsock(ls);
	}

	HASH_ITER(hh, fr->ssl_ctxs, sc, sctmp) {
		HASH_DEL(fr->ssl_ctxs, sc);
		sctx_free(sc, &fr->sni_names);
	}

	AZ(HASH_COUNT(fr->sni_names));
	free(fr->pspec);
	FREE_OBJ(fr);
}

/* Create the bound socket in the parent process */
static int
frontend_listen(const struct front_arg *fa, struct listen_sock_head *slist)
{
	struct addrinfo *ai, hints, *it;
	struct listen_sock *ls, *lstmp;
	char buf[INET6_ADDRSTRLEN+20];
	char abuf[INET6_ADDRSTRLEN];
	char pbuf[8];
	int r, count = 0;

	CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	r = getaddrinfo(fa->ip, fa->port,
	    &hints, &ai);
	if (r != 0) {
		ERR("{getaddrinfo-listen}: %s: %s\n", fa->pspec,
		    gai_strerror(r));
		return (-1);
	}

	for (it = ai; it != NULL; it = it->ai_next) {
		ALLOC_OBJ(ls, LISTEN_SOCK_MAGIC);
		VTAILQ_INSERT_TAIL(slist, ls, list);
		count++;

		ls->sock = socket(it->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (ls->sock == -1) {
			ERR("{socket: main}: %s: %s\n", strerror(errno),
			    fa->pspec);
			goto creat_frontend_err;
		}

		int t = 1;
		if (setsockopt(ls->sock, SOL_SOCKET, SO_REUSEADDR,
			&t, sizeof(int))
		    < 0) {
			ERR("{setsockopt-reuseaddr}: %s: %s\n", strerror(errno),
			    fa->pspec);
			goto creat_frontend_err;
		}
#ifdef SO_REUSEPORT_WORKS
		if (setsockopt(ls->sock, SOL_SOCKET, SO_REUSEPORT,
			&t, sizeof(int))
		    < 0) {
			ERR("{setsockopt-reuseport}: %s: %s\n", strerror(errno),
			    fa->pspec);
			goto creat_frontend_err;
		}
#endif
		if(setnonblocking(ls->sock) < 0) {
			ERR("{listen sock: setnonblocking}: %s: %s\n",
			    strerror(errno), fa->pspec);
			goto creat_frontend_err;
		}
#ifdef IPV6_V6ONLY
		t = 1;
		if (it->ai_family == AF_INET6 &&
		    setsockopt(ls->sock, IPPROTO_IPV6, IPV6_V6ONLY, &t,
			sizeof (t)) != 0) {
			ERR("{setsockopt-ipv6only}: %s: %s\n", strerror(errno),
			    fa->pspec);
			goto creat_frontend_err;
		}
#endif
		if (CONFIG->RECV_BUFSIZE > 0) {
			r = setsockopt(ls->sock, SOL_SOCKET, SO_RCVBUF,
			    &CONFIG->RECV_BUFSIZE,
			    sizeof(CONFIG->RECV_BUFSIZE));
			if (r < 0) {
				ERR("{setsockopt-rcvbuf}: %s: %s\n",
				    strerror(errno), fa->pspec);
				goto creat_frontend_err;
			}
		}
		if (CONFIG->SEND_BUFSIZE > 0) {
			r = setsockopt(ls->sock, SOL_SOCKET, SO_SNDBUF,
			    &CONFIG->SEND_BUFSIZE,
			    sizeof(CONFIG->SEND_BUFSIZE));
			if (r < 0) {
				ERR("{setsockopt-sndbuf}: %s: %s\n",
				    strerror(errno), fa->pspec);
				goto creat_frontend_err;
			}
		}

		if (bind(ls->sock, it->ai_addr, it->ai_addrlen)) {
			ERR("{bind-socket}: %s: %s\n", strerror(errno),
			    fa->pspec);
			goto creat_frontend_err;
		}

#ifndef NO_DEFER_ACCEPT
#if TCP_DEFER_ACCEPT
		int timeout = 1;
		if (setsockopt(ls->sock, IPPROTO_TCP, TCP_DEFER_ACCEPT,
			&timeout, sizeof(int)) < 0) {
			ERR("{setsockopt-defer_accept}: %s: %s\n",
			    strerror(errno), fa->pspec);
			goto creat_frontend_err;
		}
#endif /* TCP_DEFER_ACCEPT */
#endif
		if (listen(ls->sock, CONFIG->BACKLOG) != 0) {
			ERR("{listen-socket}: %s: %s\n", strerror(errno),
			    fa->pspec);
			goto creat_frontend_err;
		}

		memcpy(&ls->addr, it->ai_addr, it->ai_addrlen);

		r = getnameinfo(it->ai_addr, it->ai_addrlen, abuf,
		    sizeof abuf, pbuf, sizeof pbuf,
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (r != 0) {
			ERR("{getnameinfo}: %s\n", fa->pspec);
			goto creat_frontend_err;
		}

		if (it->ai_addr->sa_family == AF_INET6) {
			sprintf(buf, "[%s]:%s", abuf, pbuf);
		} else {
			sprintf(buf, "%s:%s", abuf, pbuf);
		}
		ls->name = strdup(buf);
		AN(ls->name);
		LOG("{core} Listening on %s\n", ls->name);
	}

	freeaddrinfo(ai);
	return (count);

creat_frontend_err:
	freeaddrinfo(ai);
	VTAILQ_FOREACH_SAFE(ls, slist, list, lstmp) {
		VTAILQ_REMOVE(slist, ls, list);
		free(ls->name);
		if (ls->sock > 0)
			(void) close(ls->sock);
		FREE_OBJ(ls);
	}

	return (-1);
}

static struct frontend *
create_frontend(const struct front_arg *fa)
{
	struct frontend *fr;
	sslctx *so;
	int count = 0;
	struct frontend_head tmp_list;
	struct cfg_cert_file *cf, *cftmp;

	CHECK_OBJ_NOTNULL(fa, FRONT_ARG_MAGIC);
	ALLOC_OBJ(fr, FRONTEND_MAGIC);
	VTAILQ_INIT(&fr->socks);
	AN(fr);

	fr->pspec = strdup(fa->pspec);
	fr->match_global_certs = fa->match_global_certs;
	fr->sni_nomatch_abort = fa->sni_nomatch_abort;

	VTAILQ_INIT(&tmp_list);
	count = frontend_listen(fa, &fr->socks);
	if (count < 0) {
		destroy_frontend(fr);
		return (NULL);
	}

	HASH_ITER(hh, fa->certs, cf, cftmp) {
		so = make_ctx_fr(cf, fr, fa);
		if (so == NULL) {
			destroy_frontend(fr);
			return (NULL);
		}
		HASH_ADD_KEYPTR(hh, fr->ssl_ctxs,
		    cf->filename, strlen(cf->filename), so);
#ifndef OPENSSL_NO_TLSEXT
		insert_sni_names(so, &fr->sni_names);
#endif
	}

	return (fr);
}

/* Initiate a clear-text nonblocking connect() to the backend IP on behalf
 * of a newly connected upstream (encrypted) client */
static int
create_back_socket()
{
	int s = socket(backaddr->ai_family, SOCK_STREAM, IPPROTO_TCP);

	if (s == -1)
		return -1;

	int flag = 1;
	int ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
	    (char *)&flag, sizeof(flag));
	if (ret == -1)
		ERR("Couldn't setsockopt to backend (TCP_NODELAY): %s\n",
		    strerror(errno));
	if (setnonblocking(s) < 0) {
		(void)close(s);
		return (-1);
	}
	return (s);
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void
safe_enable_io(proxystate *ps, ev_io *w)
{
	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	if (!ps->want_shutdown)
		ev_io_start(loop, w);
}

static void
check_exit_state(void)
{
	if (worker_state == WORKER_EXITING && n_conns == 0) {
		LOGL("Worker %d (gen: %d) in state EXITING "
		    "is now exiting.\n", core_id, worker_gen);
		_exit(0);
	}
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void
shutdown_proxy(proxystate *ps, SHUTDOWN_REQUESTOR req)
{
	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	LOGPROXY(ps, "proxy shutdown req=%s\n", SHUTDOWN_STR[req]);
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

		(void)SSL_shutdown(ps->ssl);

		ERR_clear_error();
		SSL_free(ps->ssl);

		close(ps->fd_up);
		close(ps->fd_down);

		ringbuffer_cleanup(&ps->ring_clear2ssl);
		ringbuffer_cleanup(&ps->ring_ssl2clear);
		free(ps);

		n_conns--;
		check_exit_state();
	}
	else {
		ps->want_shutdown = 1;
		if (req == SHUTDOWN_CLEAR &&
		    ringbuffer_is_empty(&ps->ring_clear2ssl))
			shutdown_proxy(ps, SHUTDOWN_HARD);
		else if (req == SHUTDOWN_SSL &&
		    ringbuffer_is_empty(&ps->ring_ssl2clear))
			shutdown_proxy(ps, SHUTDOWN_HARD);
	}
}

/* Handle various socket errors */
static void
handle_socket_errno(proxystate *ps, int backend)
{
	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
		return;

	if (backend)
		ERR("{backend} Socket error: %s\n", strerror(errno));
	else
		LOG("{client} Socket error: %s\n", strerror(errno));
	shutdown_proxy(ps, SHUTDOWN_CLEAR);
}

/* Start connect to backend */
static int
start_connect(proxystate *ps)
{
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
static void
clear_read(struct ev_loop *loop, ev_io *w, int revents)
{
	(void) revents;
	int t;
	proxystate *ps;
	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
	if (ps->want_shutdown) {
		ev_io_stop(loop, &ps->ev_r_clear);
		return;
	}
	int fd = w->fd;
	char *buf = ringbuffer_write_ptr(&ps->ring_clear2ssl);
	t = recv(fd, buf, ps->ring_clear2ssl.data_len, 0);

	if (t > 0) {
		ringbuffer_write_append(&ps->ring_clear2ssl, t);
		if (ringbuffer_is_full(&ps->ring_clear2ssl))
			ev_io_stop(loop, &ps->ev_r_clear);
		if (ps->handshaked)
			safe_enable_io(ps, &ps->ev_w_ssl);
	}
	else if (t == 0) {
		LOGPROXY(ps,"Connection closed by %s\n",
		    fd == ps->fd_down ? "backend" : "client");
		shutdown_proxy(ps, SHUTDOWN_CLEAR);
	}
	else {
		assert(t == -1);
		handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
	}
}


/* Write some data, previously received on the secure upstream socket,
 * out of the downstream buffer and onto the backend socket */
static void
clear_write(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
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
		} else {
			ringbuffer_read_skip(&ps->ring_ssl2clear, t);
		}
	} else {
		assert(t == -1);
		handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
	}
}

static void start_handshake(proxystate *ps, int err);

/* Continue/complete the asynchronous connect() before starting data
 * transmission between front/backend */
static void
handle_connect(struct ev_loop *loop, ev_io *w, int revents)
{
	int t, r;
	proxystate *ps;

	(void)revents;
	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

	t = connect(ps->fd_down, backaddr->ai_addr, backaddr->ai_addrlen);
	if (!t || errno == EISCONN || !errno) {
		ev_io_stop(loop, &ps->ev_w_connect);
		ev_timer_stop(loop, &ps->ev_t_connect);

		if (!ps->clear_connected) {
			struct sockaddr_storage addr;
			socklen_t sl;

			sl = sizeof(addr);
			r = getsockname(ps->fd_down,
			    (struct sockaddr*) &addr, &sl);
			AZ(r);
			ps->connect_port =
			    ntohs(((struct sockaddr_in*)&addr)->sin_port);
			LOGPROXY(ps, "backend connected\n");

			ps->clear_connected = 1;

			/* if incoming buffer is not full */
			if (!ringbuffer_is_full(&ps->ring_clear2ssl))
				safe_enable_io(ps, &ps->ev_r_clear);

			/* if outgoing buffer is not empty */
			if (!ringbuffer_is_empty(&ps->ring_ssl2clear))
				// not safe.. we want to resume stream
				// even during half-closed
				ev_io_start(loop, &ps->ev_w_clear);
		} else {
			/* Clear side already connected so connect is on
			 * secure side: perform handshake */
			start_handshake(ps, SSL_ERROR_WANT_WRITE);
		}
	}
	else if (errno == EINPROGRESS || errno == EINTR || errno == EALREADY) {
		/* do nothing, we'll get phoned home again... */
	} else {
		ERR("{backend-connect}: %s\n", strerror(errno));
		shutdown_proxy(ps, SHUTDOWN_HARD);
	}
}

static void
connect_timeout(EV_P_ ev_timer *w, int revents)
{
	(void)loop;
	(void)revents;
	proxystate *ps;
	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
	ERRPROXY(ps,"backend connect timeout\n");
	//shutdown_proxy(ps, SHUTDOWN_HARD);
}

/* Upon receiving a signal from OpenSSL that a handshake is required, re-wire
 * the read/write events to hook up to the handshake handlers */
static void
start_handshake(proxystate *ps, int err)
{
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
get_proto_selected(proxystate *ps, const unsigned char **selected, unsigned *len) {
	*selected = NULL;
	*len = 0;
#ifdef OPENSSL_WITH_ALPN
	SSL_get0_alpn_selected(ps->ssl, selected, len);
#endif
#ifdef OPENSSL_WITH_NPN
	if (*len == 0)
		SSL_get0_next_proto_negotiated(ps->ssl, selected, len);
#endif
}

static void
write_proxy_v2(proxystate *ps, const struct sockaddr *local)
{
	char *base;
#if defined(OPENSSL_WITH_ALPN) || defined(OPENSSL_WITH_NPN)
	const unsigned char *selected = NULL;
	unsigned selected_len = 0;
	char *alpn_base;

	get_proto_selected(ps, &selected, &selected_len);
#endif
	struct ha_proxy_v2_hdr *p;
	union addr {
		struct sockaddr		sa;
		struct sockaddr_in	sa4;
		struct sockaddr_in6	sa6;
	} *l, *r;

	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	base = ringbuffer_write_ptr(&ps->ring_ssl2clear);
	p = (struct ha_proxy_v2_hdr *)base;
	size_t len = 16;
	l = (union addr *) local;
	r = (union addr *) &ps->remote_ip;

	memcpy(&p->sig,"\r\n\r\n\0\r\nQUIT\n", 12);
	p->ver_cmd = 0x21; 	/* v2|PROXY */
	p->fam = l->sa.sa_family == AF_INET ? 0x11 : 0x21;
	size_t payload_len = l->sa.sa_family == AF_INET ? 12 : 36;
#if defined(OPENSSL_WITH_ALPN) || defined(OPENSSL_WITH_NPN)
	if (selected_len > 0)
		payload_len += selected_len + 3;
#endif
	p->len = htons(payload_len);

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

	/* This is where we add something related to NPN or ALPN*/
#if defined(OPENSSL_WITH_ALPN) || defined(OPENSSL_WITH_NPN)
	if (selected_len > 0) {
		/* let the server know that a protocol was selected. */
		alpn_base = base + len;
		alpn_base[0] = 1 /* PP2_TYPE_ALPN */;
		alpn_base[1] = (selected_len >> 8) & 0xff;
		alpn_base[2] = selected_len & 0xff;
		memcpy(alpn_base + 3, selected, selected_len);
		len += selected_len + 3;
	}
#endif
	assert(len == payload_len + 16);
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
	AZ(n);

	n = getnameinfo((struct sockaddr *) &ps->remote_ip, slen, src_addr,
	    sizeof src_addr, src_port, sizeof src_port,
	    NI_NUMERICHOST | NI_NUMERICSERV);
	AZ(n);

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

#if defined(OPENSSL_WITH_NPN) || defined(OPENSSL_WITH_ALPN)
static int is_protocol_matching(const unsigned char *selected, unsigned len) {
	int unsigned i = 0;
	if (CONFIG->ALPN_PROTOS_LV != NULL) {
		while (i < CONFIG->ALPN_PROTOS_LV_LEN) {
			if(CONFIG->ALPN_PROTOS_LV[i] == len &&
			    0 == memcmp(selected,
				CONFIG->ALPN_PROTOS_LV + i + 1,
				len))
				return 1;
			i+= CONFIG->ALPN_PROTOS_LV[i] + 1;
		}
	}
	return 0;
}

static int is_alpn_shutdown_needed(proxystate *ps) {
	const unsigned char *selected;
	unsigned selected_len;

	if (CONFIG->ALPN_PROTOS_LV == NULL)
		return 0;

	get_proto_selected(ps, &selected, &selected_len);
	if (selected_len == 0) {
		/* If alpn / npn was tried, shut down */
		if(ps->npn_alpn_tried) {
			LOGPROXY(ps, "Unsuccessful NPN/ALPN negotiation\n");
			return 1;
		} else
			LOGPROXY(ps, "No NPN/ALPN negotiation happened.\n");
	} else if (!is_protocol_matching(selected, selected_len)) {
		LOGPROXY(ps, "NPN: Unknown protocol selected\n");
		return 1;
	} else
		LOGPROXY(ps, "NPN/ALPN protocol: %.*s\n",
		    selected_len, selected);
	return 0;
}
#endif

/* After OpenSSL is done with a handshake, re-wire standard read/write handlers
 * for data transmission */
static void end_handshake(proxystate *ps) {
	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);
	ev_io_stop(loop, &ps->ev_r_handshake);
	ev_io_stop(loop, &ps->ev_w_handshake);
	ev_timer_stop(loop, &ps->ev_t_handshake);

#if defined(OPENSSL_WITH_NPN) || defined(OPENSSL_WITH_ALPN)
	if (is_alpn_shutdown_needed(ps)) {
		shutdown_proxy(ps, SHUTDOWN_HARD);
		return;
	}
#endif
	LOGPROXY(ps,"ssl end handshake\n");
	/* Disable renegotiation (CVE-2009-3555) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* For OpenSSL 1.1, setting the following flag does not seem
	 * to be possible. This is OK, since SSLv3 negotiation will
	 * not happen in OpenSSL 0.9.8m or later unless
	 * SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION is set. */
	if (ps->ssl->s3) {
		ps->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
	}
#endif
	ps->handshaked = 1;

	/* Check if clear side is connected */
	if (!ps->clear_connected) {
		if (CONFIG->WRITE_PROXY_LINE_V1 ||
		    CONFIG->WRITE_PROXY_LINE_V2) {
			struct sockaddr_storage local;
			socklen_t slen = sizeof local;
			AZ(getsockname(ps->fd_up, (struct sockaddr *) &local,
				&slen));
			if (CONFIG->WRITE_PROXY_LINE_V1)
				write_proxy_v1(ps, (struct sockaddr *) &local,
				    slen);
			else
				write_proxy_v2(ps, (struct sockaddr *) &local);
		} else if (CONFIG->WRITE_IP_OCTET) {
			write_ip_octet(ps);
		}
		/* start connect now */
		if (0 != start_connect(ps))
			return;
	} else {
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

static void
client_proxy_proxy(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	int t;
	char *proxy = tcp_proxy_line;
	char *end = tcp_proxy_line + sizeof(tcp_proxy_line);
	proxystate *ps;
	BIO *b;

	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
	b = SSL_get_rbio(ps->ssl);

	// Copy characters one-by-one until we hit a \n or an error
	while (proxy != end && (t = BIO_read(b, proxy, 1)) == 1) {
		if (*proxy++ == '\n')
			break;
	}

	if (proxy == end) {
		LOG("{client} Unexpectedly long PROXY line. Malformed req?");
		shutdown_proxy(ps, SHUTDOWN_SSL);
	} else if (t == 1) {
		if (ringbuffer_is_full(&ps->ring_ssl2clear)) {
			LOG("{client} Error writing PROXY line");
			shutdown_proxy(ps, SHUTDOWN_SSL);
			return;
		}

		char *ring = ringbuffer_write_ptr(&ps->ring_ssl2clear);
		memcpy(ring, tcp_proxy_line, proxy - tcp_proxy_line);
		ringbuffer_write_append(&ps->ring_ssl2clear,
		    proxy - tcp_proxy_line);

		// Finished reading the PROXY header
		if (*(proxy - 1) == '\n') {
			ev_io_stop(loop, &ps->ev_proxy);

			// Start the real handshake
			start_handshake(ps, SSL_ERROR_WANT_READ);
		}
	} else if (!BIO_should_retry(b)) {
		LOG("{client} Unexpected error reading PROXY line");
		shutdown_proxy(ps, SHUTDOWN_SSL);
	}
}

/* The libev I/O handler during the OpenSSL handshake phase.  Basically, just
 * let OpenSSL do what it likes with the socket and obey its requests for reads
 * or writes */
static void
client_handshake(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	int t;
	const char *errtok;
	proxystate *ps;
	int errno_val;


	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

	LOGPROXY(ps,"ssl client handshake revents=%x\n",revents);
	t = SSL_do_handshake(ps->ssl);
	if (t == 1) {
		end_handshake(ps);
	} else {
		errno_val = errno;
		int err = SSL_get_error(ps->ssl, t);
		switch (err) {
#define SSL_ERR(a)				\
			case a: errtok = #a; break;
#include "ssl_err.h"
#undef SSL_ERR
		default:
			errtok = "<undefined>";
		}

		LOGPROXY(ps,"ssl client handshake err=%s\n",errtok);
		if (err == SSL_ERROR_WANT_READ) {
			ev_io_stop(loop, &ps->ev_w_handshake);
			ev_io_start(loop, &ps->ev_r_handshake);
		} else if (err == SSL_ERROR_WANT_WRITE) {
			ev_io_stop(loop, &ps->ev_r_handshake);
			ev_io_start(loop, &ps->ev_w_handshake);
		} else if (err == SSL_ERROR_ZERO_RETURN) {
			LOG("{%s} Connection closed (in handshake)\n",
			    w->fd == ps->fd_up ? "client" : "backend");
			shutdown_proxy(ps, SHUTDOWN_SSL);
		} else if (err == SSL_ERROR_SYSCALL) {
			LOG("{%s} SSL socket error in handshake: %s\n",
			    w->fd == ps->fd_up ? "client" : "backend",
			    strerror(errno_val));
			shutdown_proxy(ps, SHUTDOWN_SSL);
		} else {
			if (err == SSL_ERROR_SSL) {
				log_ssl_error(ps, "Handshake failure");
			} else {
				LOG("{%s} Unexpected SSL error "
				    "(in handshake): %d\n",
				    w->fd == ps->fd_up ? "client" : "backend",
				    err);
			}
			shutdown_proxy(ps, SHUTDOWN_SSL);
		}
	}
}

static void
handshake_timeout(EV_P_ ev_timer *w, int revents)
{
	(void)loop;
	(void)revents;
	proxystate *ps;
	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);
	LOGPROXY(ps,"SSL handshake timeout\n");
	shutdown_proxy(ps, SHUTDOWN_HARD);
}

#define SSLERR(ps, which, log)						\
	switch (err) {							\
	case SSL_ERROR_ZERO_RETURN:					\
		log(ps,"Connection closed by " which "\n");		\
		break;							\
	case SSL_ERROR_SYSCALL:						\
		if (errno == 0) {					\
			log(ps,"Connection closed by " which "\n");	\
		} else {						\
			log(ps,"SSL socket error (" which "): %s\n",	\
			    strerror(errno));				\
		}							\
		break;							\
	default:							\
		log(ps,"{" which "} Unexpected SSL_read error ("	\
		    which "): %d\n", err);				\
	}

/* Handle a socket error condition passed to us from OpenSSL */
static void
handle_fatal_ssl_error(proxystate *ps, int err, int backend)
{
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
static void
ssl_read(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
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

	char *buf = ringbuffer_write_ptr(&ps->ring_ssl2clear);
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
	} else {
		int err = SSL_get_error(ps->ssl, t);
		if (err == SSL_ERROR_WANT_WRITE) {
			start_handshake(ps, err);
		} else if (err == SSL_ERROR_WANT_READ) {
			/* NOOP. Incomplete SSL data */
		} else {
			if (err == SSL_ERROR_SSL) {
				log_ssl_error(ps, "SSL_read error");
			}
			handle_fatal_ssl_error(ps, err,
			    w->fd == ps->fd_up ? 0 : 1);
		}
	}
}

/* Write some previously-buffered backend data upstream on the
 * secure socket using OpenSSL */
static void
ssl_write(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	int t;
	int sz;
	proxystate *ps;

	CAST_OBJ_NOTNULL(ps, w->data, PROXYSTATE_MAGIC);

	assert(!ringbuffer_is_empty(&ps->ring_clear2ssl));
	char *next = ringbuffer_read_next(&ps->ring_clear2ssl, &sz);
	t = SSL_write(ps->ssl, next, sz);
	if (t > 0) {
		if (t == sz) {
			ringbuffer_read_pop(&ps->ring_clear2ssl);
			if (ps->clear_connected)
				// can be re-enabled b/c we've popped
				safe_enable_io(ps, &ps->ev_r_clear);
			if (ringbuffer_is_empty(&ps->ring_clear2ssl)) {
				if (ps->want_shutdown) {
					shutdown_proxy(ps, SHUTDOWN_HARD);
					return;
				}
				ev_io_stop(loop, &ps->ev_w_ssl);
			}
		} else {
			ringbuffer_read_skip(&ps->ring_clear2ssl, t);
		}
	} else {
		int err = SSL_get_error(ps->ssl, t);
		if (err == SSL_ERROR_WANT_READ) {
			start_handshake(ps, err);
		} else if (err == SSL_ERROR_WANT_WRITE) {
			/* NOOP. Incomplete SSL data */
		} else {
			if (err == SSL_ERROR_SSL) {
				log_ssl_error(ps, "SSL_write error");
			} else {
				LOG("{%s} SSL_write error: %d\n",
				    w->fd == ps->fd_up ? "client" : "backend",
				    err);
			}
			handle_fatal_ssl_error(ps, err,
			    w->fd == ps->fd_up ? 0 : 1);
		}
	}
}


/* libev read handler for the bound sockets.  Socket is accepted,
 * the proxystate is allocated and initalized, and we're off the races
 * connecting to the backend */
static void
handle_accept(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	(void)loop;
	struct sockaddr_storage addr;
	sslctx *so;
	struct frontend *fr;
	proxystate *ps;
	socklen_t sl = sizeof(addr);

#if HAVE_ACCEPT4==1
	int client = accept4(w->fd, (struct sockaddr *) &addr, &sl,
	    SOCK_NONBLOCK);
#else
	int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
#endif
	if (client == -1) {
		switch (errno) {
		case EMFILE:
			ERR("{client} accept() failed; "
			    "too many open files for this process\n");
			break;

		case ENFILE:
			ERR("{client} accept() failed; "
			    "too many open files for this system\n");
			break;

		default:
			if (errno != EINTR && errno != EWOULDBLOCK &&
			    errno != EAGAIN && errno != ENOTTY &&
			    errno != ECONNABORTED) {
				SOCKERR("{client} accept() failed");
			}
		}
		return;
	}

	int flag = 1;
	int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
	    (char *)&flag, sizeof(flag) );
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

#if HAVE_ACCEPT4==0
	if (setnonblocking(client) < 0) {
		SOCKERR("{client} setnonblocking failed");
		(void) close(client);
		return;
	}
#endif

	settcpkeepalive(client);

	int back = create_back_socket();
	if (back == -1) {
		(void) close(client);
		ERR("{backend-socket}: %s\n", strerror(errno));
		return;
	}

	CAST_OBJ_NOTNULL(fr, w->data, FRONTEND_MAGIC);
	if (fr->ssl_ctxs != NULL)
		CAST_OBJ_NOTNULL(so, fr->ssl_ctxs, SSLCTX_MAGIC);
	else
		CAST_OBJ_NOTNULL(so, default_ctx, SSLCTX_MAGIC);

	SSL *ssl = SSL_new(so->ctx);
	if (ssl == NULL) {
		(void)close(back);
		(void)close(client);
		ERR("{SSL_new}: %s\n", strerror(errno));
		return;
	}

	ALLOC_OBJ(ps, PROXYSTATE_MAGIC);
	if (ps == NULL) {
		SSL_free(ssl);
		(void)close(back);
		(void)close(client);
		ERR("{malloc-err}: %s\n", strerror(errno));
		return;
	}

	long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#ifdef SSL_MODE_RELEASE_BUFFERS
	mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
	SSL_set_mode(ssl, mode);
	SSL_set_accept_state(ssl);
	SSL_set_fd(ssl, client);

	ps->fd_up = client;
	ps->fd_down = back;
	ps->ssl = ssl;
	ps->want_shutdown = 0;
	ps->clear_connected = 0;
	ps->handshaked = 0;
	ps->renegotiation = 0;
	ps->remote_ip = addr;
	ps->connect_port = 0;

	ringbuffer_init(&ps->ring_clear2ssl, CONFIG->RING_SLOTS,
	    CONFIG->RING_DATA_LEN);
	ringbuffer_init(&ps->ring_ssl2clear, CONFIG->RING_SLOTS,
	    CONFIG->RING_DATA_LEN);

	/* set up events */
	ev_io_init(&ps->ev_r_ssl, ssl_read, client, EV_READ);
	ev_io_init(&ps->ev_w_ssl, ssl_write, client, EV_WRITE);

	ev_io_init(&ps->ev_r_handshake, client_handshake, client, EV_READ);
	ev_io_init(&ps->ev_w_handshake, client_handshake, client, EV_WRITE);
	ev_timer_init(&ps->ev_t_handshake, handshake_timeout,
	    CONFIG->SSL_HANDSHAKE_TIMEOUT, 0.);

	ev_io_init(&ps->ev_proxy, client_proxy_proxy, client, EV_READ);

	ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);
	ev_timer_init(&ps->ev_t_connect, connect_timeout,
	    CONFIG->BACKEND_CONNECT_TIMEOUT, 0.);

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

	n_conns++;

	LOGPROXY(ps, "proxy connect\n");
	if (CONFIG->PROXY_PROXY_LINE) {
		ev_io_start(loop, &ps->ev_proxy);
	} else {
		/* for client-first handshake */
		start_handshake(ps, SSL_ERROR_WANT_READ);
	}
}


static void
check_ppid(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct frontend *fr;
	struct listen_sock *ls;
	(void)revents;
	pid_t ppid = getppid();
	if (ppid != master_pid) {
		ERR("{core} Process %d detected parent death, "
		    "closing listener sockets.\n", core_id);
		ev_timer_stop(loop, w);
		VTAILQ_FOREACH(fr, &frontends, list) {
			CHECK_OBJ_NOTNULL(fr, FRONTEND_MAGIC);
			VTAILQ_FOREACH(ls, &fr->socks, list) {
				CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
				ev_io_stop(loop, &ls->listener);
				close(ls->sock);
			}
		}
	}
}

static void
handle_mgt_rd(struct ev_loop *loop, ev_io *w, int revents)
{
	unsigned cg;
	ssize_t r;
	struct frontend *fr;
	struct listen_sock *ls;

	(void) revents;
	r = read(w->fd, &cg, sizeof(cg));
	if (r  == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return;
		SOCKERR("Error in mgt->worker read operation. "
		    "Restarting process.");
		/* If something went wrong here, the process will be
		 * left in utter limbo as to whether it should keep
		 * running or not. Kill the process and let the mgt
		 * process start it back up. */
		_exit(1);
	} else if (r == 0) {
		/* Parent died .. */
		_exit(1);
	}

	if (cg != worker_gen) {
		/* This means this process has reached its retirement age. */
		worker_state = WORKER_EXITING;

		/* Stop accepting new connections. */
		VTAILQ_FOREACH(fr, &frontends, list) {
			CHECK_OBJ_NOTNULL(fr, FRONTEND_MAGIC);
			VTAILQ_FOREACH(ls, &fr->socks, list) {
				CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
				ev_io_stop(loop, &ls->listener);
				close(ls->sock);
			}
		}

		check_exit_state();
	}

	LOGL("Worker %d (gen: %d): State %s\n", core_id, worker_gen,
	    (worker_state == WORKER_EXITING) ? "EXITING" : "ACTIVE");
}

static void
handle_clear_accept(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	(void)loop;
	struct sockaddr_storage addr;
	struct frontend *fr;
	sslctx *so;
	proxystate *ps;
	socklen_t sl = sizeof(addr);
	int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
	if (client == -1) {
		switch (errno) {
		case EMFILE:
			ERR("{client} accept() failed; "
			    "too many open files for this process\n");
			break;

		case ENFILE:
			ERR("{client} accept() failed; "
			    "too many open files for this system\n");
			break;

		default:
			if (errno != EINTR && errno != EWOULDBLOCK &&
			    errno != EAGAIN && errno != ECONNABORTED) {
				SOCKERR("{client} accept() failed");
			}
			break;
		}
		return;
	}

	int flag = 1;
	int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
	    (char *)&flag, sizeof(flag) );
	if (ret == -1) {
		ERR("Couldn't setsockopt on client (TCP_NODELAY): %s\n",
		    strerror(errno));
	}
#ifdef TCP_CWND
	int cwnd = 10;
	ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
	if (ret == -1) {
		ERR("Couldn't setsockopt on client (TCP_CWND): %s\n",
		    strerror(errno));
	}
#endif

	if (setnonblocking(client)) {
		SOCKERR("{client} setnonblocking failed");
		(void) close(client);
		return;
	}

	settcpkeepalive(client);

	int back = create_back_socket();
	if (back == -1) {
		close(client);
		ERR("{backend-socket}: %s\n", strerror(errno));
		return;
	}

	CAST_OBJ_NOTNULL(fr, w->data, FRONTEND_MAGIC);
	if (fr->ssl_ctxs != NULL)
		CAST_OBJ_NOTNULL(so, fr->ssl_ctxs, SSLCTX_MAGIC);
	else
		CAST_OBJ_NOTNULL(so, default_ctx, SSLCTX_MAGIC);
	SSL *ssl = SSL_new(so->ctx);
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
	ringbuffer_init(&ps->ring_clear2ssl, CONFIG->RING_SLOTS,
	    CONFIG->RING_DATA_LEN);
	ringbuffer_init(&ps->ring_ssl2clear, CONFIG->RING_SLOTS,
	    CONFIG->RING_DATA_LEN);

	/* set up events */
	ev_io_init(&ps->ev_r_clear, clear_read, client, EV_READ);
	ev_io_init(&ps->ev_w_clear, clear_write, client, EV_WRITE);

	ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);
	ev_timer_init(&ps->ev_t_connect, connect_timeout,
	    CONFIG->BACKEND_CONNECT_TIMEOUT, 0.);

	ev_io_init(&ps->ev_r_handshake, client_handshake, back, EV_READ);
	ev_io_init(&ps->ev_w_handshake, client_handshake, back, EV_WRITE);
	ev_timer_init(&ps->ev_t_handshake, handshake_timeout,
	    CONFIG->SSL_HANDSHAKE_TIMEOUT, 0.);

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

	n_conns++;

	ev_io_start(loop, &ps->ev_r_clear);
	start_connect(ps); /* start connect */
}

/* Set up the child (worker) process including libev event loop, read event
 * on the bound sockets, etc */
static void
handle_connections(int mgt_fd)
{
	struct frontend *fr;
	sslctx *sc, *sctmp;
	struct listen_sock *ls;
	struct sigaction sa;

	worker_state = WORKER_ACTIVE;
	LOGL("{core} Process %d online\n", core_id);

	/* child cannot create new children... */
	create_workers = 0;

	/* nor can they handle SIGHUP */
	sa.sa_flags = 0;
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	AZ(sigaction(SIGHUP, &sa, NULL));

#if defined(CPU_ZERO) && defined(CPU_SET)
	cpu_set_t cpus;

	CPU_ZERO(&cpus);
	CPU_SET(core_id, &cpus);

	int res = sched_setaffinity(0, sizeof(cpus), &cpus);
	if (!res)
		LOG("{core} Successfully attached to CPU #%d\n", core_id);
	else
		ERR("{core-warning} Unable to attach to CPU #%d; "
		    "do you have that many cores?\n", core_id);
#endif

	loop = ev_default_loop(EVFLAG_AUTO);

	ev_timer timer_ppid_check;
	ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
	ev_timer_start(loop, &timer_ppid_check);

	VTAILQ_FOREACH(fr, &frontends, list) {
		VTAILQ_FOREACH(ls, &fr->socks, list) {
			ev_io_init(&ls->listener,
			    (CONFIG->PMODE == SSL_CLIENT) ?
			    handle_clear_accept : handle_accept,
			    ls->sock, EV_READ);
			ls->listener.data = fr;
			ev_io_start(loop, &ls->listener);
		}
	}

	if (CONFIG->OCSP_DIR != NULL) {
		HASH_ITER(hh, ssl_ctxs, sc, sctmp) {
			if (sc->ev_staple)
				ev_stat_start(loop, sc->ev_staple);
		}

		VTAILQ_FOREACH(fr, &frontends, list) {
			HASH_ITER(hh, fr->ssl_ctxs, sc, sctmp) {
			    if (sc->ev_staple)
				    ev_stat_start(loop, sc->ev_staple);
			}
		}

		if (default_ctx != NULL && default_ctx->ev_staple != NULL)
			ev_stat_start(loop, default_ctx->ev_staple);
	}

	AZ(setnonblocking(mgt_fd));
	ev_io_init(&mgt_rd, handle_mgt_rd, mgt_fd, EV_READ);
	ev_io_start(loop, &mgt_rd);

	ev_loop(loop, 0);
	ERR("Worker %d (gen: %d) exiting.\n", core_id, worker_gen);
	_exit(1);
}


/*
   OCSP requestor process.
*/
static void
handle_ocsp_task(void) {
	struct frontend *fr;
	struct listen_sock *ls;
	sslctx *sc, *sctmp;
	ev_timer timer_ppid_check;

	/* we don't accept incoming connections for this process.  */
	VTAILQ_FOREACH(fr, &frontends, list) {
		CHECK_OBJ_NOTNULL(fr, FRONTEND_MAGIC);
		VTAILQ_FOREACH(ls, &fr->socks, list) {
			CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
			ev_io_stop(loop, &ls->listener);
			close(ls->sock);
		}
	}

	(void) umask(027);
	loop = ev_default_loop(EVFLAG_AUTO);

	/* Create ocspquery work items for any eligible ocsp queries */

	HASH_ITER(hh, ssl_ctxs, sc, sctmp) {
		HOCSP_mktask(sc, NULL, -1.0);
	}

	VTAILQ_FOREACH(fr, &frontends, list) {
		HASH_ITER(hh, fr->ssl_ctxs, sc, sctmp) {
			HOCSP_mktask(sc, NULL, -1.0);
		}
	}

	if (default_ctx != NULL)
		HOCSP_mktask(default_ctx, NULL, -1.0);

	ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
	ev_timer_start(loop, &timer_ppid_check);

	ev_loop(loop, 0);

	_exit(0);
}

void
change_root()
{
	if (chroot(CONFIG->CHROOT) == -1)
		fail("chroot");
	if (chdir("/"))
		fail("chdir");
}

void
drop_privileges(void)
{

	if (geteuid() == 0) {
		if (CONFIG->UID >= 0)
			AZ(setgroups(0, NULL));
		if (CONFIG->GID >= 0)
			AZ(setgid(CONFIG->GID));
		if (CONFIG->UID >= 0)
			AZ(setuid(CONFIG->UID));
	} else {
		LOG("{core} Not running as root, no priv-sep\n");
	}

	/* On Linux >= 2.4, you need to set the dumpable flag
	   to get core dumps after you have done a setuid. */

#ifdef __linux__
	if (prctl(PR_SET_DUMPABLE, 1) != 0)
		LOG("Could not set dumpable bit.  Core dumps turned off\n");
#endif
}

void
init_globals(void)
{
	/* backaddr */
	struct addrinfo hints;

	VTAILQ_INIT(&frontends);
	VTAILQ_INIT(&worker_procs);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	const int gai_err = getaddrinfo(CONFIG->BACK_IP, CONFIG->BACK_PORT,
	    &hints, &backaddr);
	if (gai_err != 0) {
		ERR("{getaddrinfo-backend}: %s\n", gai_strerror(gai_err));
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
			    spo->port ? spo->port : CONFIG->SHCUPD_PORT,
			    &hints, pai);
			if (gai_err != 0) {
				ERR("{getaddrinfo}: %s\n",
				    gai_strerror(gai_err));
				exit(1);
			}
			spo++;
			pai++;
		}
	}
#endif
	if (CONFIG->SYSLOG)
		openlog("hitch", LOG_CONS | LOG_PID | LOG_NDELAY,
		    CONFIG->SYSLOG_FACILITY);
}

/* Forks COUNT children starting with START_INDEX.  We keep a struct
 * child_proc per child so the parent can manage it later. */
void
start_workers(int start_index, int count)
{
	struct worker_proc *c;
	int pfd[2];

	/* don't do anything if we're not allowed to create new workers */
	if (!create_workers)
		return;

	for (core_id = start_index;
	    core_id < start_index + count; core_id++) {
		ALLOC_OBJ(c, WORKER_PROC_MAGIC);
		AZ(pipe(pfd));
		c->pfd = pfd[1];
		c->gen = worker_gen;
		c->pid = fork();
		c->core_id = core_id;
		if (c->pid == -1) {
			ERR("{core} fork() failed: %s; Goodbye cruel world!\n",
			    strerror(errno));
			exit(1);
		} else if (c->pid == 0) { /* child */
			close(pfd[1]);
			FREE_OBJ(c);
			if (CONFIG->CHROOT && CONFIG->CHROOT[0])
				change_root();
			if (CONFIG->UID >= 0 || CONFIG->GID >= 0)
				drop_privileges();
			if (geteuid() == 0) {
				ERR("{core} ERROR: "
				    "Refusing to run workers as root.\n");
				_exit(1);
			}
			handle_connections(pfd[0]);
			exit(0);
		} else { /* parent. Track new child. */
			close(pfd[0]);
			VTAILQ_INSERT_TAIL(&worker_procs, c, list);
		}
	}
}

void
start_ocsp_proc(void)
{
	ocsp_proc_pid = fork();

	if (ocsp_proc_pid == -1) {
		ERR("{core}: fork() failed: %s: Exiting.\n", strerror(errno));
		exit(1);
	} else if (ocsp_proc_pid == 0) {
		if (CONFIG->UID >= 0 || CONFIG->GID >= 0)
			drop_privileges();
		if (geteuid() == 0) {
			ERR("{core} ERROR: "
			    "Refusing to run workers as root.\n");
			_exit(1);
		}
		handle_ocsp_task();
	}

	/* child proc should never return. */
	AN(ocsp_proc_pid);
}


/* Forks a new child to replace the old, dead, one with the given PID.*/
void
replace_child_with_pid(pid_t pid)
{
	struct worker_proc *c, *cp;

	/* find old child's slot and put a new child there */
	VTAILQ_FOREACH_SAFE(c, &worker_procs, list, cp) {
		if (c->pid == pid) {
			VTAILQ_REMOVE(&worker_procs, c, list);
			/* Only replace if it matches current generation. */
			if (c->gen == worker_gen)
				start_workers(c->core_id, 1);
			FREE_OBJ(c);
			return;
		}
	}

	ERR("Cannot find index for child pid %d", pid);
}

/* Manage status changes in child processes */
static void
do_wait(void)
{
	struct worker_proc *c, *ctmp;
	int status;
	int pid;

#define WAIT_PID(p, action) do {					\
	pid = waitpid(p, &status, WNOHANG);				\
	if (pid == 0) {							\
		/* child has not exited */				\
		break;							\
	}								\
	else if (pid == -1) {						\
		if (errno == EINTR)					\
			ERR("{core} Interrupted waitpid\n");		\
		else							\
			fail("waitpid");				\
	} else {							\
		if (WIFEXITED(status)) {				\
			ERR("{core} Child %d exited with status %d.\n",	\
			    pid, WEXITSTATUS(status));			\
			action;						\
		} else if (WIFSIGNALED(status)) {			\
			ERR("{core} Child %d was terminated by "	\
			    "signal %d.\n", pid, WTERMSIG(status));	\
			action;						\
		}							\
	}								\
	} while (0)

	VTAILQ_FOREACH_SAFE(c, &worker_procs, list, ctmp) {
		WAIT_PID(c->pid, replace_child_with_pid(pid));
	}

	/* also check if the ocsp worker killed itself */
	if (CONFIG->OCSP_DIR != NULL)
		WAIT_PID(ocsp_proc_pid, start_ocsp_proc());
}

static void
sigchld_handler(int signum)
{
	assert(signum == SIGCHLD);
	n_sigchld++;
}


static void
sigh_terminate (int __attribute__ ((unused)) signo)
{
	struct worker_proc *c;
	/* don't create any more children */
	create_workers = 0;

	/* are we the master? */
	if (getpid() == master_pid) {
		LOGL("{core} Received signal %d, shutting down.\n", signo);

		/* kill all children */
		VTAILQ_FOREACH(c, &worker_procs, list) {
			/* LOG("Stopping worker pid %d.\n", c->pid); */
			if (c->pid > 1 &&
			    kill(c->pid, SIGTERM) != 0) {
				ERR("{core} Unable to send SIGTERM to worker "
				    "pid %d: %s\n", c->pid,
				    strerror(errno));
			}
		}

		if (ocsp_proc_pid != 0)
			kill(ocsp_proc_pid, SIGTERM);
	}

	/* this is it, we're done... */
	exit(0);
}

static void
sighup_handler(int signum)
{
	assert(signum == SIGHUP);
	n_sighup++;
}

static void
init_signals()
{
	struct sigaction act;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;

	/* Avoid getting PIPE signal when writing to a closed file descriptor */
	if (sigaction(SIGPIPE, &act, NULL) < 0)
		fail("sigaction - sigpipe");

	/* We don't care if someone stops and starts a child process
	 * with kill (1) */
	act.sa_flags = SA_NOCLDSTOP;
	act.sa_handler = sigchld_handler;

	/* We do care when child processes change status */
	if (sigaction(SIGCHLD, &act, NULL) < 0)
		fail("sigaction - sigchld");

	/* catch INT and TERM signals */
	act.sa_flags = 0;
	act.sa_handler = sigh_terminate;
	if (sigaction(SIGINT, &act, NULL) < 0) {
		ERR("Unable to register SIGINT signal handler: %s\n",
		    strerror(errno));
		exit(1);
	}
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		ERR("Unable to register SIGTERM signal handler: %s\n",
		    strerror(errno));
		exit(1);
	}

	act.sa_handler = sighup_handler;
	if (sigaction(SIGHUP, &act, NULL) != 0) {
		ERR("Unable to register SIGHUP signal handler: %s\n",
		    strerror(errno));
		exit(1);
	}

}

#define NULL_DEV "/dev/null"
static void
daemonize()
{
	/* logging.c */
	if (logfile == stdout || logfile == stderr) {
		logfile = NULL;
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
		LOGL("{core} Daemonized as pid %d.\n", pid);
		exit(0);
	}

	/* reopen standard streams to null device */
	if (freopen(NULL_DEV, "r", stdin) == NULL) {
		ERR("Unable to reopen stdin to %s: %s\n",
		    NULL_DEV, strerror(errno));
		exit(1);
	}
	if (freopen(NULL_DEV, "w", stdout) == NULL) {
		ERR("Unable to reopen stdout to %s: %s\n",
		    NULL_DEV, strerror(errno));
		exit(1);
	}
	if (freopen(NULL_DEV, "w", stderr) == NULL) {
		ERR("Unable to reopen stderr to %s: %s\n",
		    NULL_DEV, strerror(errno));
		exit(1);
	}

	/* this is child, the new master */
	pid_t s = setsid();
	if (s < 0) {
		ERR("Unable to create new session, setsid(2) failed: "
		    "%s :: %d\n", strerror(errno), s);
		exit(1);
	}

	LOG("Successfully daemonized as pid %d.\n", getpid());
}

static void
openssl_check_version()
{
	/* detect OpenSSL version in runtime */
	long openssl_version = SSLeay();

	/* check if we're running the same openssl that we were */
	/* compiled with */
	if ((openssl_version ^ OPENSSL_VERSION_NUMBER) & ~0xff0L) {
		ERR(
			"WARNING: {core} OpenSSL version mismatch; "
			    "hitch was compiled with %lx, now using %lx.\n",
			(unsigned long int)OPENSSL_VERSION_NUMBER,
			(unsigned long int)openssl_version
		);
		/* now what? exit now? */
		/* exit(1); */
	}

	LOG("{core} Using OpenSSL version %lx.\n",
	    (unsigned long int)openssl_version);
}


static void
remove_pfh(void)
{
	if (pfh && master_pid == getpid()) {
		VPF_Remove(pfh);
	}
}

struct cfg_tpc_obj;

enum cfg_tpc_type {
	CFG_FRONTEND,
	CFG_CERT

	/* ... */
};

/* Commit/rollback handling:
   - KEEP:
	- commit: reuse
	- rollback: do nothing
   - NEW:
	- commit: use as new
	- rollback: drop

   - DROP:
	- commit: drop
	- rollback: do nothing
 */
enum cfg_tpc_handling {
	CFG_TPC_KEEP,
	CFG_TPC_NEW,
	CFG_TPC_DROP
};

typedef void cfg_tpc_rollback_f(struct cfg_tpc_obj *o);
typedef void cfg_tpc_commit_f(struct cfg_tpc_obj *o);

struct cfg_tpc_obj {
	unsigned		magic;
#define CFG_TPC_OBJ_MAGIC	0xd6953e5f
	enum cfg_tpc_type	type;
	enum cfg_tpc_handling	handling;
	void			*p[2];
	cfg_tpc_rollback_f	*rollback;
	cfg_tpc_commit_f	*commit;
	VTAILQ_ENTRY(cfg_tpc_obj) list;
};

VTAILQ_HEAD(cfg_tpc_obj_head, cfg_tpc_obj);

static struct cfg_tpc_obj *
make_cfg_obj(enum cfg_tpc_type type, enum cfg_tpc_handling handling,
    void *priv0, void *priv1, cfg_tpc_rollback_f *rollback,
    cfg_tpc_commit_f *commit)
{
	struct cfg_tpc_obj *o;

	ALLOC_OBJ(o, CFG_TPC_OBJ_MAGIC);
	AN(o);
	o->type = type;
	o->handling = handling;
	o->p[0] = priv0;
	o->p[1] = priv1;
	o->rollback = rollback;
	o->commit = commit;

	return (o);
}

static void
frontend_rollback(struct cfg_tpc_obj *o)
{
	struct frontend *fr;

	if (o->handling == CFG_TPC_NEW) {
		CAST_OBJ_NOTNULL(fr, o->p[0], FRONTEND_MAGIC);
		destroy_frontend(fr);
	}

	/* KEEP/DROP: ignore */
}

static void
frontend_commit(struct cfg_tpc_obj *o)
{
	struct frontend *fr;
	sslctx *sc;
	CAST_OBJ_NOTNULL(fr, o->p[0], FRONTEND_MAGIC);

	switch (o->handling) {
	case CFG_TPC_NEW:
		VTAILQ_INSERT_TAIL(&frontends, fr, list);
		/* FALL-THROUGH */
	case CFG_TPC_KEEP:
		if (o->p[1]) {
			CAST_OBJ_NOTNULL(sc, o->p[1], SSLCTX_MAGIC);
			/* fr->sctx = sc; */
		}
		break;
	case CFG_TPC_DROP:
		VTAILQ_REMOVE(&frontends, fr, list);
		destroy_frontend(fr);
		break;
	}
}

static void cert_rollback(struct cfg_tpc_obj *o);
static void cert_commit(struct cfg_tpc_obj *o);

// Is this incorrectly named?
static int
ocsp_cfg_changed(const struct cfg_cert_file *cf, const sslctx *sc)
{
	if (sc->staple != NULL && cf->ocspfn == NULL)
		return (1); 	/* Dropped OCSP definition */

	if (sc->staple == NULL && cf->ocspfn != NULL)
		return (1); 	/* Added OCSP definition */

	if (sc->staple != NULL && cf->ocspfn != NULL) {
		if (strcmp(sc->staple_fn, cf->ocspfn) != 0
		    || sc->staple->mtim < cf->ocsp_mtim)
			return (1); /* Updated */
	}

	return (0);
}

/* Query frontend-specific certificates.  */
static int
cert_fr_query(struct frontend *fr, struct front_arg *fa,
    struct cfg_tpc_obj_head *cfg_objs)
{
	struct cfg_cert_file *cf, *cftmp;
	sslctx *sc, *sctmp;
	struct cfg_tpc_obj *o;

	HASH_ITER(hh, fr->ssl_ctxs, sc, sctmp) {
		HASH_FIND_STR(fa->certs, sc->filename, cf);
		if (cf != NULL && cf->mtim <= sc->mtim
			&& !ocsp_cfg_changed(cf, sc)) {
			cf->mark = 1;
		} else {
			o = make_cfg_obj(CFG_CERT, CFG_TPC_DROP,
			    sc, fr, cert_rollback, cert_commit);
			VTAILQ_INSERT_TAIL(cfg_objs, o, list);
		}
	}

	HASH_ITER(hh, fa->certs, cf, cftmp) {
		if (cf->mark)
			continue;
		sc = make_ctx_fr(cf, fr, fa);
		if (sc == NULL)
			return (-1);
		o = make_cfg_obj(CFG_CERT, CFG_TPC_NEW,
		    sc, fr, cert_rollback, cert_commit);
		VTAILQ_INSERT_TAIL(cfg_objs, o, list);
	}

	return (0);
}

/* Query reload of listen sockets.
   Returns -1 on failure.
   Failure: Caller calls .rollback() on the objects added in cfg_objs.
   Success: Caller calls .commit()
*/
static int
frontend_query(struct front_arg *new_set, struct cfg_tpc_obj_head *cfg_objs)
{
	struct frontend *fr;
	struct front_arg *fa, *ftmp;
	struct cfg_tpc_obj *o;

	VTAILQ_FOREACH(fr, &frontends, list) {
		HASH_FIND_STR(new_set, fr->pspec, fa);
		if (fa != NULL) {
			fa->mark = 1;
			o = make_cfg_obj(CFG_FRONTEND, CFG_TPC_KEEP, fr, NULL,
			    frontend_rollback, frontend_commit);
			if(cert_fr_query(fr, fa, cfg_objs) < 0) {
				FREE_OBJ(o);
				return (-1);
			}

		} else
			o = make_cfg_obj(CFG_FRONTEND, CFG_TPC_DROP, fr, NULL,
			    frontend_rollback, frontend_commit);
		VTAILQ_INSERT_TAIL(cfg_objs, o, list);
	}

	HASH_ITER(hh, new_set, fa, ftmp) {
		if (!fa->mark) {
			fr = create_frontend(fa);
			if (fr == NULL)
				return (-1);
			o = make_cfg_obj(CFG_FRONTEND, CFG_TPC_NEW,
			    fr, NULL, frontend_rollback, frontend_commit);
			VTAILQ_INSERT_TAIL(cfg_objs, o, list);
		}
	}

	return (0);
}

static void
cert_rollback(struct cfg_tpc_obj *o)
{
	sslctx *sc;

	if (o->handling != CFG_TPC_NEW)
		return;

	CAST_OBJ_NOTNULL(sc, o->p[0], SSLCTX_MAGIC);
	sctx_free(sc, NULL);
}

static void
cert_commit(struct cfg_tpc_obj *o)
{
	sslctx *sc;
	sni_name **sn_tab;
	sslctx **ctxs;
	struct frontend *fr;

	sn_tab = &sni_names;
	ctxs = &ssl_ctxs;

	CAST_OBJ_NOTNULL(sc, o->p[0], SSLCTX_MAGIC);
	if (o->p[1] != NULL) {
		CAST_OBJ_NOTNULL(fr, o->p[1], FRONTEND_MAGIC);
		sn_tab = &fr->sni_names;
		ctxs = &fr->ssl_ctxs;
	}

	switch (o->handling) {
	case CFG_TPC_NEW:
		HASH_ADD_KEYPTR(hh, *ctxs, sc->filename,
		    strlen(sc->filename), sc);
		insert_sni_names(sc, sn_tab);
		break;
	case CFG_TPC_KEEP:
		WRONG("unreachable");
		break;
	case CFG_TPC_DROP:
		HASH_DEL(*ctxs, sc);
		sctx_free(sc, sn_tab);
		break;
	}
}

static void
dcert_rollback(struct cfg_tpc_obj *o)
{
	cert_rollback(o);
}

static void
dcert_commit(struct cfg_tpc_obj *o)
{
	sslctx *sc;

	CAST_OBJ_NOTNULL(sc, o->p[0], SSLCTX_MAGIC);
	CHECK_OBJ_NOTNULL(sni_names, SNI_NAME_MAGIC);

	switch (o->handling) {
	case CFG_TPC_NEW:
		sctx_free(default_ctx, &sni_names);
		default_ctx = sc;
		insert_sni_names(sc, &sni_names);
		break;
	case CFG_TPC_KEEP:
		/* FALL-THROUGH */
	case CFG_TPC_DROP:
		/* We always have a default cert. This should not
		 * happen. */
		WRONG("unreachable");
		break;
	}
}

/* Query reload of certificate files */
static int
cert_query(hitch_config *cfg, struct cfg_tpc_obj_head *cfg_objs)
{
	struct cfg_cert_file *cf, *cftmp;
	sslctx *sc, *sctmp;
	struct cfg_tpc_obj *o;

	/* NB: The ordering here is significant. It is imperative that
	 * all DROP objects are inserted before any NEW objects, in
	 * order to not wreak havoc in cert_commit().  */
	HASH_ITER(hh, ssl_ctxs, sc, sctmp) {
		HASH_FIND_STR(cfg->CERT_FILES, sc->filename, cf);
		if (cf != NULL && cf->mtim <= sc->mtim
		    && !ocsp_cfg_changed(cf, sc)) {
			cf->mark = 1;
		} else {
			o = make_cfg_obj(CFG_CERT, CFG_TPC_DROP,
			    sc, NULL, cert_rollback, cert_commit);
			VTAILQ_INSERT_TAIL(cfg_objs, o, list);
		}
	}

	/* handle default cert. Default cert has its own
	 * rollback/commit functions. */
	if (cfg->CERT_DEFAULT != NULL) {
		cf = cfg->CERT_DEFAULT;
		CHECK_OBJ_NOTNULL(default_ctx, SSLCTX_MAGIC);
		if (strcmp(default_ctx->filename, cf->filename) != 0
		    || cf->mtim > default_ctx->mtim
		    || ocsp_cfg_changed(cf, default_ctx)) {
			sc = make_ctx(cf);
			if (sc == NULL)
				return (-1);
			o = make_cfg_obj(CFG_CERT, CFG_TPC_NEW,
			    sc, NULL, dcert_rollback, dcert_commit);
			VTAILQ_INSERT_TAIL(cfg_objs, o, list);
		}
	}

	HASH_ITER(hh, cfg->CERT_FILES, cf, cftmp) {
		if (cf->mark)
			continue;
		sc = make_ctx(cf);
		if (sc == NULL)
			return (-1);
		o = make_cfg_obj(CFG_CERT, CFG_TPC_NEW,
		    sc, NULL, cert_rollback, cert_commit);
		VTAILQ_INSERT_TAIL(cfg_objs, o, list);
	}

	return (0);
}

static void
reconfigure(int argc, char **argv)
{
	struct worker_proc *c;
	hitch_config *cfg_new;
	int i, rv;
	struct cfg_tpc_obj_head cfg_objs;
	struct cfg_tpc_obj *cto, *cto_tmp;
	struct timeval tv;
	double t0, t1;

	LOGL("Received SIGHUP: Initiating configuration reload.\n");
	AZ(gettimeofday(&tv, NULL));
	t0 = tv.tv_sec + 1e-6 * tv.tv_usec;

	VTAILQ_INIT(&cfg_objs);
	cfg_new = config_new();
	AN(cfg_new);
	if (config_parse_cli(argc, argv, cfg_new, &rv) != 0) {
		ERR("Config reload failed: %s\n", config_error_get());
		config_destroy(cfg_new);
		return;
	}

	/* NB: the ordering of the foo_query() calls here is
	 * significant. */
	if (frontend_query(cfg_new->LISTEN_ARGS, &cfg_objs) < 0
	    || cert_query(cfg_new, &cfg_objs) < 0) {
		VTAILQ_FOREACH_SAFE(cto, &cfg_objs, list, cto_tmp) {
			VTAILQ_REMOVE(&cfg_objs, cto, list);
			AN(cto->rollback);
			cto->rollback(cto);
			FREE_OBJ(cto);
		}
		ERR("{core} Config reload failed.\n");
		return;
	} else {
		VTAILQ_FOREACH_SAFE(cto, &cfg_objs, list, cto_tmp) {
			VTAILQ_REMOVE(&cfg_objs, cto, list);
			AN(cto->commit);
			cto->commit(cto);
			FREE_OBJ(cto);
		}
	}

	AZ(gettimeofday(&tv, NULL));
	t1 = tv.tv_sec + 1e-6 * tv.tv_usec;

	LOGL("{core} Config reloaded in %.2lf seconds. "
	    "Starting new child processes.\n", t1 - t0);

	worker_gen++;
	start_workers(0, CONFIG->NCORES);
	VTAILQ_FOREACH(c, &worker_procs, list) {
		if (c->gen != worker_gen) {
			errno = 0;
			do {
				i = write(c->pfd, &worker_gen,
				    sizeof(worker_gen));
				if (i == -1 && errno != EINTR) {
					ERR("WARNING: {core} Unable to "
					    "gracefully reload worker %d"
					    " (%s).\n",
					    c->pid, strerror(errno));
					(void)kill(c->pid, SIGTERM);
					break;
				}
			} while (i == -1 && errno == EINTR);
		}
	}

	if (CONFIG->OCSP_DIR != NULL) {
		(void) kill(ocsp_proc_pid, SIGTERM);
		/*
		 * Restarting the OCSP process is taken
		 * care of in do_wait
		 */
	}

	config_destroy(CONFIG);
	CONFIG = cfg_new;
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and respawn if any die */
int
main(int argc, char **argv)
{
	// initialize configuration
	struct front_arg *fa, *ftmp;
	int rv;

	CONFIG = config_new();

	// parse command line
	if (config_parse_cli(argc, argv, CONFIG, &rv) != 0) {
		fprintf(stderr, "%s\n", config_error_get());
		return (rv);
	}

	if (CONFIG->TEST) {
		fprintf(stderr, "Trying to initialize SSL contexts with your"
		    " certificates\n");
		init_globals();
		init_openssl();
		init_certs();
		fprintf(stderr, "%s configuration looks ok.\n",
		    basename(argv[0]));
		return (0);
	}

	if (CONFIG->LOG_FILENAME) {
		FILE* f;
		if ((f = fopen(CONFIG->LOG_FILENAME, "a")) == NULL) {
			/* logging.c */
			logfile = stderr;
			ERR("FATAL: Unable to open log file: %s: %s\n",
			    CONFIG->LOG_FILENAME, strerror(errno));
			exit(2);
		}
		logfile = f;
		if (CONFIG->UID >=0 || CONFIG->GID >= 0) {
			AZ(fchown(fileno(logfile), CONFIG->UID, CONFIG->GID));
		}
		AZ(fstat(fileno(logfile), &logf_st));
		logf_check_t = time(NULL);
	} else {
		logfile = CONFIG->QUIET ? stderr : stdout;
	}
	AZ(setvbuf(logfile, NULL, _IONBF, BUFSIZ));

	if (CONFIG->DAEMONIZE && (logfile == stdout || logfile == stderr))
		logfile = NULL;

	LOGL("{core} %s starting\n", PACKAGE_STRING);
	create_workers = 1;

	openssl_check_version();

	init_signals();
	init_globals();
	init_openssl();

	HASH_ITER(hh, CONFIG->LISTEN_ARGS, fa, ftmp) {
		struct frontend *fr = create_frontend(fa);
		if (fr == NULL)
			exit(1);
		VTAILQ_INSERT_TAIL(&frontends, fr, list);
	}

	/* load certificates, pass to handle_connections */
	LOGL("{core} Loading certificate pem files (%d)\n",
	    HASH_COUNT(CONFIG->CERT_FILES) + 1); /* XXX: TODO */
	init_certs();

#ifdef USE_SHARED_CACHE
	if (CONFIG->SHCUPD_PORT) {
		/* create socket to send(children) and
		   receive(parent) cache updates */
		shcupd_socket = create_shcupd_socket();
	}
#endif /* USE_SHARED_CACHE */

	if (CONFIG->CHROOT && CONFIG->CHROOT[0] && geteuid() != 0) {
		ERR("{core} ERROR: chroot requires hitch to be"
		    " started as root.\n");
		exit(1);
	}

	if (geteuid() == 0 && CONFIG->UID < 0) {
		ERR("{core} ERROR: Refusing to run workers as root.\n");
		exit(1);
	}

	if (CONFIG->DAEMONIZE)
		daemonize();

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

	start_workers(0, CONFIG->NCORES);

	if (CONFIG->OCSP_DIR != NULL)
		start_ocsp_proc();

#ifdef USE_SHARED_CACHE
	if (CONFIG->SHCUPD_PORT) {
		/* start event loop to receive cache updates */
		loop = ev_default_loop(EVFLAG_AUTO);
		ev_io_init(&shcupd_listener, handle_shcupd, shcupd_socket,
		    EV_READ);
		ev_io_start(loop, &shcupd_listener);
	}
#endif /* USE_SHARED_CACHE */

	LOGL("{core} %s initialization complete\n", PACKAGE_STRING);
	for (;;) {
#ifdef USE_SHARED_CACHE
		if (CONFIG->SHCUPD_PORT) {
			while (n_sighup == 0 && n_sigchld == 0) {
				/* event loop to receive cache updates */
				ev_loop(loop, EVRUN_ONCE);
			}
		} else
			pause();
#else
		pause();
		/* Sleep and let the children work.
		 * Parent will be woken up if a signal arrives */
#endif /* USE_SHARED_CACHE */

		while (n_sighup != 0) {
			n_sighup = 0;
			reconfigure(argc, argv);
		}

		while (n_sigchld != 0) {
			n_sigchld = 0;
			do_wait();
		}
	}

	exit(0); /* just a formality; we never get here */
}
