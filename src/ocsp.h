/*
 *
 */

#ifndef OCSP_H_INCLUDED
#define OCSP_H_INCLUDED

#include "hitch.h"

typedef struct ocspquery_s {
	unsigned	magic;
#define OCSPQUERY_MAGIC	0xb91c4eb1
	ev_timer	ev_t_refresh;
	sslctx		*sctx;
	/*  */
} ocspquery;

void HOCSP_free(sslstaple **staple);
int HOCSP_init_resp(sslctx *sc, OCSP_RESPONSE *resp);
int HOCSP_verify(sslctx *sc, OCSP_RESPONSE *resp, double *nextupd);

char * HOCSP_fn(const char *certfn);
int HOCSP_init_file(const char *ocspfn, sslctx *sc, int is_cached);
void HOCSP_mktask(sslctx *sc, ocspquery *oq, double refresh_hint);
void HOCSP_ev_stat(sslctx *sc);

#endif   /* OCSP_H_INCLUDED */
