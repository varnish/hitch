/**
  * Copyright 2016 Varnish Software
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
  */

#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logging.h"
#include "hitch.h"
#include "ocsp.h"
#include "configuration.h"

/* hitch.c */
extern hitch_config *CONFIG;
extern struct ev_loop *loop;

void
HOCSP_free(sslstaple **staple)
{
	if (*staple == NULL)
		return;
	free((*staple)->staple);
	FREE_OBJ(*staple);
	*staple = NULL;
}


int
HOCSP_verify(sslctx *sc, OCSP_RESPONSE *resp, double *nextupd)
{
	OCSP_BASICRESP *br = NULL;
	X509_STORE *store;
	STACK_OF(X509) *chain = NULL;
	OCSP_CERTID *cid = NULL;
	int status = -1, reason;
	ASN1_GENERALIZEDTIME *asn_nextupd = NULL;
	X509 *issuer;
	int i;
	int do_verify = sc->staple_vfy;
	int verify_flags = OCSP_TRUSTOTHER;

	if (sc->staple_vfy < 0)
		do_verify = CONFIG->OCSP_VFY;

	if (!do_verify)
		verify_flags |= OCSP_NOVERIFY;

	store = SSL_CTX_get_cert_store(sc->ctx);
	AN(store);

#ifdef SSL_CTRL_GET_CHAIN_CERTS
	AN(SSL_CTX_get0_chain_certs(sc->ctx, &chain));
#else
	chain = sc->ctx->extra_certs;
#endif
	br = OCSP_response_get1_basic(resp);
	if (br == NULL) {
		ERR("{core} OCSP_response_get1_basic failed (cert: %s)\n",
		    sc->filename);
		goto err;
	}
	i = OCSP_basic_verify(br, chain, store, verify_flags);
	if (i <= 0) {
		log_ssl_error(NULL, "{core} Staple verification failed "
		    "for cert %s\n", sc->filename);
		goto err;
	}

	issuer = Find_issuer(sc->x509, chain);
	if (issuer == NULL) {
		ERR("{core} Unable to find issuer for cert %s\n.",
		    sc->filename);
		goto err;
	}

	cid = OCSP_cert_to_id(NULL, sc->x509, issuer);
	if (cid == NULL) {
		ERR("{core} OCSP_cert_to_id failed\n");
		goto err;
	}

	if (OCSP_resp_find_status(br, cid, &status, &reason,
		NULL, NULL, &asn_nextupd) != 1) {
		ERR("{core} OCSP_resp_find_status failed: Unable to "
		    "find OCSP response with a matching certificate id\n");
		goto err;
	}

	if (status != V_OCSP_CERTSTATUS_GOOD) {
		ERR("{core} Certificate %s has status %s\n", sc->filename,
		    OCSP_cert_status_str(status));
		if (status == V_OCSP_CERTSTATUS_REVOKED)
			ERR("{core} Certificate %s revocation reason: %s\n",
			    sc->filename, OCSP_crl_reason_str(reason));
		goto err;
	}

	if (asn_nextupd != NULL)
		*nextupd = asn1_gentime_parse(asn_nextupd);
	else {
		*nextupd = -1.0;
	}

	OCSP_CERTID_free(cid);
	OCSP_BASICRESP_free(br);
	return (0);

err:
	if (cid != NULL)
		OCSP_CERTID_free(cid);
	if (br != NULL)
		OCSP_BASICRESP_free(br);
	return (1);
}

#ifndef OPENSSL_NO_TLSEXT
int
HOCSP_staple_cb(SSL *ssl, void *priv)
{
	sslstaple *staple;
	unsigned char *buf;
	CAST_OBJ_NOTNULL(staple, priv, SSLSTAPLE_MAGIC);

	if (staple->nextupd != -1 &&
	    staple->nextupd < Time_now()) {
		return (SSL_TLSEXT_ERR_NOACK);
	}

	/* SSL_set_tlsext_status_ocsp_resp will issue a free() on the
	 * provided input, so we need to pass a copy. */
	buf = malloc(staple->len);
	AN(buf);
	memcpy(buf, staple->staple, staple->len);

	if (SSL_set_tlsext_status_ocsp_resp(ssl,
		buf, staple->len) == 1)
		return (SSL_TLSEXT_ERR_OK);
	else
		free(buf);

	return (SSL_TLSEXT_ERR_NOACK);
}
#endif


int
HOCSP_init_resp(sslctx *sc, OCSP_RESPONSE *resp)
{
	sslstaple *staple = NULL;
	int len, i;
	unsigned char *tmp, *buf;

	i = OCSP_response_status(resp);
	if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		ERR("{core} Error: OCSP response for cert %s has status %s\n",
		    sc->filename, OCSP_response_status_str(i));
		goto err;
	}

	len = i2d_OCSP_RESPONSE(resp, NULL);
	if (len < 0) {
		log_ssl_error(NULL, "{core} i2d_OCSP_RESPONSE");
		goto err;
	}
	buf = malloc(len);
	AN(buf);
	tmp = buf;
	i = i2d_OCSP_RESPONSE(resp, &tmp);
	assert(i > 0);

	ALLOC_OBJ(staple, SSLSTAPLE_MAGIC);
	AN(staple);
	staple->staple = buf;
	staple->len = len;

	if (HOCSP_verify(sc, resp, &staple->nextupd) != 0) {
		goto err;
	}

	if (!SSL_CTX_set_tlsext_status_cb(sc->ctx, HOCSP_staple_cb)) {
		ERR("Error configuring status callback.\n");
		goto err;
	} else if (!SSL_CTX_set_tlsext_status_arg(sc->ctx, staple)) {
		ERR("Error setting status callback argument.\n");
		goto err;
	}

	if (sc->staple != NULL)
		HOCSP_free(&sc->staple);
	sc->staple = staple;
	return (0);

err:
	if (staple != NULL)
		HOCSP_free(&staple);
	return (1);
}


static void
hocsp_stat_cb(struct ev_loop *loop, ev_stat *w, int revents)
{
	sslctx *sc;
	sslstaple *oldstaple;

	(void) revents;
	(void) loop;
	CAST_OBJ_NOTNULL(sc, w->data, SSLCTX_MAGIC);

	if (w->attr.st_nlink) {
		oldstaple = sc->staple;
		sc->staple = NULL;
		AN(sc->staple_fn);

		if (HOCSP_init_file(sc->staple_fn, sc, 1) != 0) {
			sc->staple = oldstaple;
			return;
		}

		HOCSP_free(&oldstaple);
		LOG("{core} Loaded cached OCSP staple for cert '%s'\n",
		    sc->filename);
	}
}

void
HOCSP_ev_stat(sslctx *sc)
{
	char *fn;
	STACK_OF(OPENSSL_STRING) *sk_uri = NULL;
	AN(sc->x509);
	sk_uri = X509_get1_ocsp(sc->x509);

	if (sk_uri == NULL
	   || sk_OPENSSL_STRING_num(sk_uri) == 0) {
		goto err;
	}

	fn = HOCSP_fn(sc->filename);
	if (fn == NULL)
		goto err;

	free(sc->staple_fn);
	sc->staple_fn = fn;
	sc->ev_staple = malloc(sizeof *sc->ev_staple);
	AN(sc->ev_staple);
	sc->ev_staple->data = sc;
	ev_stat_init(sc->ev_staple, hocsp_stat_cb, fn, 0);

err:
	if (sk_uri != NULL)
		X509_email_free(sk_uri);
}

static OCSP_REQUEST *
hocsp_mkreq(ocspquery *oq)
{
	OCSP_REQUEST *req;
	OCSP_CERTID *cid;
	STACK_OF(X509) *chain = NULL;
	X509 *issuer;

	CHECK_OBJ_NOTNULL(oq, OCSPQUERY_MAGIC);
	CHECK_OBJ_NOTNULL(oq->sctx, SSLCTX_MAGIC);

#ifdef SSL_CTRL_GET_CHAIN_CERTS
	AN(SSL_CTX_get0_chain_certs(oq->sctx->ctx, &chain));
#else
	chain = oq->sctx->ctx->extra_certs;
#endif
	issuer = Find_issuer(oq->sctx->x509, chain);
	if (issuer == NULL) {
		ERR("{ocsp} Unable to find issuer for cert %s\n.",
		    oq->sctx->filename);
		return (NULL);
	}

	cid = OCSP_cert_to_id(NULL, oq->sctx->x509, issuer);
	if (cid == NULL) {
		ERR("{ocsp} OCSP_cert_to_id failed for cert %s\n",
		    oq->sctx->filename);
		return (NULL);
	}

	req = OCSP_REQUEST_new();
	if (req == NULL) {
		ERR("{ocsp} OCSP_REQUEST_new failed\n");
		OCSP_CERTID_free(cid);
		return (NULL);
	}

	if (OCSP_request_add0_id(req, cid) == NULL) {
		ERR("{ocsp} OCSP_request_add0_id failed\n");
		OCSP_CERTID_free(cid);
		OCSP_REQUEST_free(req);
		return (NULL);
	}

	return (req);
}


/* Save a downloaded staple to the file system.
 * Process: OCSP child  */
static int
hocsp_proc_persist(sslctx *sc)
{
	char *dstfile = NULL;
	int fd = -1;
	struct vsb *tmpfn;

	CHECK_OBJ_NOTNULL(sc, SSLCTX_MAGIC);
	CHECK_OBJ_NOTNULL(sc->staple, SSLSTAPLE_MAGIC);
	dstfile = HOCSP_fn(sc->filename);
	if (dstfile == NULL)
		return (1);

	(void)umask(027);

	tmpfn = VSB_new_auto();
	AN(tmpfn);
	VSB_printf(tmpfn, "%s.XXXXXX", dstfile);
	VSB_finish(tmpfn);
	fd = mkstemp(VSB_data(tmpfn));
	if (fd < 0) {
		if (errno == EACCES)
			ERR("{ocsp} Error: ocsp-dir '%s' is not "
			    "writable for the configured user\n",
			    CONFIG->OCSP_DIR);
		else
			ERR("{ocsp} hocsp_proc_persist: mkstemp: %s: %s\n",
			    VSB_data(tmpfn), strerror(errno));
		goto err;
	}

	if (write(fd, sc->staple->staple, sc->staple->len) != sc->staple->len) {
		ERR("{ocsp} hocsp_proc_persist: write: %s\n", strerror(errno));
		(void) close(fd);
		goto err;
	}

	if(close(fd) != 0) {
		ERR("{ocsp} hocsp_proc_persist: close: %s\n", strerror(errno));
		goto err;
	}

	if (rename(VSB_data(tmpfn), dstfile) != 0) {
		ERR("{ocsp} hocsp_proc_persist: rename: %s: %s\n",
		    strerror(errno), dstfile);
		goto err;
	}

	/* worker procs notified via ev_stat (inotify/stat) */

	VSB_delete(tmpfn);
	free(dstfile);
	return (0);

err:
	unlink(VSB_data(tmpfn));
	VSB_delete(tmpfn);
	free(dstfile);
	return (1);
}


int
HOCSP_init_file(const char *ocspfn, sslctx *sc, int is_cached)
{
	BIO *bio;
	OCSP_RESPONSE *resp;

	if (ocspfn == NULL) {
		return (1);
	}

	bio = BIO_new_file(ocspfn, "r");
	if (bio == NULL) {
		if (is_cached)
			return (1);
		ERR("Error loading status file '%s'\n", ocspfn);
		return (1);
	}

	resp = d2i_OCSP_RESPONSE_bio(bio, NULL);
	BIO_free(bio);
	if (resp == NULL) {
		ERR("Error parsing OCSP staple in '%s'\n", ocspfn);
		return (1);
	}

	if (HOCSP_init_resp(sc, resp) != 0)
		goto err;

	CHECK_OBJ_NOTNULL(sc->staple, SSLSTAPLE_MAGIC);
	OCSP_RESPONSE_free(resp);
	return (0);

err:
	if (resp != NULL)
		OCSP_RESPONSE_free(resp);
	return (1);
}


char *
HOCSP_fn(const char *certfn)
{
	EVP_MD_CTX *mdctx = NULL;
	unsigned char md_val[EVP_MAX_MD_SIZE];
	unsigned int i, md_len;
	struct vsb *vsb;
	char *res;

	if (CONFIG->OCSP_DIR == NULL) {
		ERR("{ocsp} Error: OCSP directory not specified.\n");
		return (NULL);
	}

	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL) {
		ERR("{ocsp} EVP_MD_CTX_create failed\n");
		goto err;
	}
	if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
		ERR("{ocsp} EVP_DigestInit_ex in ocsp_fn() failed\n");
		goto err;
	}
	if (EVP_DigestUpdate(mdctx, certfn, strlen(certfn)) != 1) {
		ERR("{ocsp} EVP_DigestUpdate in ocsp_fn() failed\n");
		goto err;
	}
	if (EVP_DigestFinal_ex(mdctx, md_val, &md_len) != 1) {
		ERR("{ocsp} EVP_DigestFinal_ex in ocsp_fn() failed\n");
		goto err;
	}

	EVP_MD_CTX_destroy(mdctx);

	vsb = VSB_new_auto();
	AN(vsb);
	VSB_cat(vsb, CONFIG->OCSP_DIR);
	VSB_putc(vsb, '/');
	for (i = 0; i < md_len; i++)
		VSB_printf(vsb, "%02x", md_val[i]);
	VSB_finish(vsb);
	res = strdup(VSB_data(vsb));
	AN(res);
	VSB_delete(vsb);
	return (res);

err:
	if (mdctx != NULL)
		EVP_MD_CTX_destroy(mdctx);
	return (NULL);
}

static void hocsp_query_responder(struct ev_loop *loop, ev_timer *w, int revents);


/* Start a per-sslctx evloop timer that downloads the OCSP staple.
 * Process: OCSP child  */
void
HOCSP_mktask(sslctx *sc, ocspquery *oq, double refresh_hint)
{
	double refresh = -1.0;
	double tnow;
	STACK_OF(OPENSSL_STRING) *sk_uri;

	tnow = Time_now();

	if (sc->staple != NULL) {
		CHECK_OBJ_NOTNULL(sc->staple, SSLSTAPLE_MAGIC);
		if (sc->staple->nextupd > 0) {
			refresh = sc->staple->nextupd - tnow - 600;
			if (refresh < 0)
				refresh = 0.0;
		} else
			refresh = 1800;
	} else {
		AN(sc->x509);
		sk_uri = X509_get1_ocsp(sc->x509);
		if (sk_uri == NULL || sk_OPENSSL_STRING_num(sk_uri) == 0) {
			LOG("{ocsp} Note: No OCSP responder URI found "
			    "for cert %s\n", sc->filename);
			if (sk_uri != NULL)
				X509_email_free(sk_uri);
			return;
		}
		/* schedule for immediate retrieval */
		X509_email_free(sk_uri);
		refresh = 0.0;
	}

	if (refresh < refresh_hint)
		refresh = refresh_hint;

	if (oq == NULL)
		ALLOC_OBJ(oq, OCSPQUERY_MAGIC);

	CHECK_OBJ_NOTNULL(oq, OCSPQUERY_MAGIC);
	oq->sctx = sc;

	assert(refresh >= 0.0);
	ev_timer_init(&oq->ev_t_refresh,
	    hocsp_query_responder, refresh, 0.);
	oq->ev_t_refresh.data = oq;
	ev_timer_start(loop, &oq->ev_t_refresh);

	LOG("{ocsp} Refresh of OCSP staple for %s scheduled in "
	    "%.0lf seconds\n", sc->filename, refresh);
}



static void
hocsp_query_responder(struct ev_loop *loop, ev_timer *w, int revents)
{
	ocspquery *oq;
	OCSP_REQUEST *req = NULL;
	OCSP_REQ_CTX *rctx = NULL;
	STACK_OF(OPENSSL_STRING) *sk_uri;
	char *host = NULL, *port = NULL, *path = NULL;
	int https = 0;
	BIO *cbio = NULL, *sbio;
	SSL_CTX *ctx = NULL;
	OCSP_RESPONSE *resp = NULL;
	double resp_tmo;
	fd_set fds;
	struct timeval tv;
	int n, fd;
	double refresh_hint = 60;

	(void) loop;
	(void) revents;

	CAST_OBJ_NOTNULL(oq, w->data, OCSPQUERY_MAGIC);

	sk_uri = X509_get1_ocsp(oq->sctx->x509);
	AN(sk_uri);

	AN(OCSP_parse_url(sk_OPENSSL_STRING_value(sk_uri, 0),
		&host, &port, &path, &https));
	X509_email_free(sk_uri);

	req = hocsp_mkreq(oq);
	if (req == NULL) {
		/* If we weren't able to create a request, there is no
		 * use in scheduling a retry. */
		FREE_OBJ(oq);
		goto err;
	}

	/* printf("host: %s port: %s path: %s ssl: %d\n", */
	/*     host, port, path, https); */

	cbio = BIO_new_connect(host);
	if (cbio == NULL) {
		refresh_hint = 60;
		goto retry;
	}

	if (port == NULL) {
		if (https)
			port = "443";
		else
			port = "80";
	}
	AN(BIO_set_conn_port(cbio, port));

	if (https) {
		ctx = SSL_CTX_new(SSLv23_client_method());
		AN(ctx);
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		sbio = BIO_new_ssl(ctx, 1);
		if (sbio == NULL) {
			ERR("{ocsp} BIO_new_ssl failed: %s\n", strerror(errno));
			refresh_hint = 60;
			goto retry;
		}
		cbio = BIO_push(sbio, cbio);
		AN(cbio);
	}

	/* set non-blocking */
	BIO_set_nbio(cbio, 1);
	n = BIO_do_connect(cbio);
	if (n <= 0 && !BIO_should_retry(cbio)) {
		ERR("{ocsp} Error connecting to %s:%s\n", host, port);
		refresh_hint = 300;
		goto retry;
	}

	assert(BIO_get_fd(cbio, &fd) >= 0);

	if (n <= 0) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		tv.tv_sec = CONFIG->OCSP_CONN_TMO;
		tv.tv_usec = (CONFIG->OCSP_CONN_TMO - tv.tv_sec) * 1e6;
		n = select(fd + 1, NULL, (void *) &fds, NULL, &tv);
		if (n == 0) {
			/* connect timeout */
			ERR("{ocsp} Error: Connection to %s:%s timed out. "
			    "Hit parameter 'ocsp-connect-tmo"
			    " [current value: %.3fs]\n",
			    host, port, CONFIG->OCSP_CONN_TMO);
			refresh_hint = 300;
			goto retry;
		} else if (n < 0) {
			ERR("{ocsp} Error: Connecting to %s:%s failed: "
			    "select: %s\n",
			    host, port, strerror(errno));
			refresh_hint = 300;
			goto retry;
		}
	}

	rctx = OCSP_sendreq_new(cbio, path, NULL, 0);
	if (rctx == NULL) {
		ERR("{ocsp} OCSP_sendreq_new failed\n");
		refresh_hint = 60;
		goto retry;
	}
	if (OCSP_REQ_CTX_add1_header(rctx, "Host", host) == 0) {
		ERR("{ocsp} OCSP_REQ_CTX_add1_header failed\n");
		refresh_hint = 60;
		goto retry;
	}
	if (OCSP_REQ_CTX_set1_req(rctx, req) == 0) {
		ERR("{ocsp} OCSP_REQ_CTX_set1_req failed\n");
		refresh_hint = 60;
		goto retry;
	}

	resp_tmo = Time_now() + CONFIG->OCSP_RESP_TMO;
	while (1) {
		double tnow;
		n = OCSP_sendreq_nbio(&resp, rctx);
		if (n == 0) {
			/* this is an error, and we can't continue */
			ERR("{ocsp} OCSP_sendreq_nbio failed for %s:%s.\n",
			    host, port);
			refresh_hint = 300;
			goto retry;
		} else if (n == 1) {
			/* complete */
			break;
		}

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		tnow = Time_now();
		tv.tv_sec = resp_tmo - tnow;
		tv.tv_usec = ((resp_tmo - tnow) - tv.tv_sec) * 1e6;

		if (BIO_should_read(cbio))
			n = select(fd + 1, (void *) &fds, NULL, NULL, &tv);
		else if (BIO_should_write(cbio))
			n = select(fd + 1, NULL, (void *) &fds, NULL, &tv);
		else {
			/* BIO_should_io_special? */
			refresh_hint = 300;
			goto retry;
		}

		if (n == -1) {
			if (errno == EINTR)
				continue;
			ERR("{ocsp} Error: Transmission failed:"
			    " select: %s\n", strerror(errno));
			refresh_hint = 300;
			goto retry;
		}

		if (n == 0) {
			/* timeout */
			ERR("{ocsp} Error: Transmission timeout for %s:%s. "
			    "Consider increasing parameter 'ocsp-resp-tmo'"
			    " [current value: %.3fs]\n",
			    host, port, CONFIG->OCSP_RESP_TMO);
			refresh_hint = 300;
			goto retry;
		}
	}

	if (resp == NULL) {
		/* fetch failed.  Retry later. */
		refresh_hint = 600.0;
	} else {
		if (HOCSP_init_resp(oq->sctx, resp) == 0) {
			LOG("{ocsp} Retrieved new staple for cert %s\n",
			    oq->sctx->filename);
			if (hocsp_proc_persist(oq->sctx) != 0) {
				refresh_hint = 300;
				goto retry;
			}
		} else {
			refresh_hint = 300;
			goto retry;
		}
	}

retry:
	HOCSP_mktask(oq->sctx, oq, refresh_hint);
err:
	if (rctx)
		OCSP_REQ_CTX_free(rctx);
	if (req)
		OCSP_REQUEST_free(req);
	if (resp)
		OCSP_RESPONSE_free(resp);
	if (cbio)
		BIO_free_all(cbio);
	if (ctx)
		SSL_CTX_free(ctx);
}

