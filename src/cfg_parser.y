%{
#include <stdio.h>
#include <stdlib.h>
#include "configuration.h"
#include "vas.h"
#include "miniobj.h"
#include "uthash.h"

extern int yylex (void);
extern int yyparse(hitch_config *);
extern FILE *yyin;
int yyget_lineno(void);

int config_param_validate(char *k, char *v, hitch_config *cfg,
    char *file, int line);
int front_arg_add(hitch_config *cfg, struct front_arg *fa);
struct front_arg *front_arg_new(void);
struct cfg_cert_file *
cfg_cert_file_new(void);
void cfg_cert_file_free(struct cfg_cert_file **cfptr);
int cfg_cert_vfy(struct cfg_cert_file *cf);
void yyerror(hitch_config *, const char *);
void cfg_cert_add(struct cfg_cert_file *cf, struct cfg_cert_file **dst);

static struct front_arg *cur_fa;
static struct cfg_cert_file *cur_pem;

%}

%union {
	int	i;
	char	*s;
}

%token <i> INT
%token <i> UINT
%token <i> BOOL
%token <s> STRING

%token TOK_CIPHERS TOK_SSL_ENGINE TOK_PREFER_SERVER_CIPHERS TOK_BACKEND
%token TOK_FRONTEND TOK_WORKERS TOK_BACKLOG TOK_KEEPALIVE TOK_CHROOT
%token TOK_USER TOK_GROUP TOK_QUIET TOK_SYSLOG TOK_SYSLOG_FACILITY
%token TOK_PARAM_SYSLOG_FACILITY TOK_DAEMON TOK_WRITE_IP TOK_WRITE_PROXY
%token TOK_WRITE_PROXY_V1 TOK_WRITE_PROXY_V2 TOK_PEM_FILE TOK_PROXY_PROXY
%token TOK_BACKEND_CONNECT_TIMEOUT TOK_SSL_HANDSHAKE_TIMEOUT TOK_RECV_BUFSIZE
%token TOK_SEND_BUFSIZE TOK_LOG_FILENAME TOK_RING_SLOTS TOK_RING_DATA_LEN
%token TOK_PIDFILE TOK_SNI_NOMATCH_ABORT TOK_SSL TOK_TLS TOK_HOST TOK_PORT
%token TOK_MATCH_GLOBAL TOK_PB_CERT TOK_PB_OCSP_FILE
%token TOK_PACE_FRONTEND TOK_PACE_BACKEND

%parse-param { hitch_config *cfg }

%%
CFG
	: CFG_RECORDS
	;

CFG_RECORDS
	: CFG_RECORD
	| CFG_RECORDS CFG_RECORD
	;

CFG_RECORD
	: FRONTEND_REC
	| BACKEND_REC
	| PEM_FILE_REC
	| CIPHERS_REC
	| TLS_REC
	| SSL_REC
	| PREFER_SERVER_CIPHERS_REC
	| SSL_ENGINE_REC
	| WORKERS_REC
	| BACKLOG_REC
	| KEEPALIVE_REC
	| CHROOT_REC
	| USER_REC
	| GROUP_REC
	| QUIET_REC
	| SYSLOG_REC
	| SYSLOG_FACILITY_REC
	| DAEMON_REC
	| WRITE_IP_REC
	| WRITE_PROXY_REC
	| WRITE_PROXY_V1_REC
	| WRITE_PROXY_V2_REC
	| PROXY_PROXY_REC
	| SNI_NOMATCH_ABORT_REC
	| PACE_FRONTEND_REC
	| PACE_BACKEND_REC
	;

FRONTEND_REC
	: TOK_FRONTEND '=' STRING
{
	if ($3 && config_param_validate("frontend", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
}
	| TOK_FRONTEND '=' '{'
{
	/* NB: Mid-rule action */
	AZ(cur_fa);
	cur_fa = front_arg_new();
}
	FRONTEND_BLK '}'
{
	if (front_arg_add(cfg, cur_fa) != 1)
		YYABORT;
	cur_fa = NULL;
};

FRONTEND_BLK: FB_RECS;
FB_RECS
	: FB_REC
	| FB_RECS FB_REC
	;

FB_REC
	: FB_HOST
	| FB_PORT
	| FB_CERT
	| FB_MATCH_GLOBAL
	| FB_SNI_NOMATCH_ABORT
	| FB_TLS
	| FB_SSL
	| FB_CIPHERS
	| FB_PREF_SRV_CIPH
	;

FB_HOST: TOK_HOST '=' STRING { cur_fa->ip = strdup($3); };
FB_PORT: TOK_PORT '=' STRING { cur_fa->port = strdup($3); };

PEM_BLK: PB_RECS;

PB_RECS
	: PB_REC
	| PB_RECS PB_REC
	;

PB_REC
	: PB_CERT
	| PB_OCSP_RESP_FILE;
	;

PB_CERT: TOK_PB_CERT '=' STRING { cur_pem->filename = strdup($3); };

PB_OCSP_RESP_FILE: TOK_PB_OCSP_FILE '=' STRING
{
	cur_pem->ocspfn = strdup($3);
};

FB_CERT: TOK_PEM_FILE '=' STRING
{
	int r;
	struct cfg_cert_file *cert;
	cert = cfg_cert_file_new();
	cert->filename = strdup($3);
	r = cfg_cert_vfy(cert);
	if (r == 0) {
		cfg_cert_file_free(&cert);
		YYABORT;
	}
	cfg_cert_add(cert, &cur_fa->certs);
}
	| TOK_PEM_FILE '=' '{'
{
	/* NB: Mid-rule action */
	AZ(cur_pem);
	cur_pem = cfg_cert_file_new();
}
	PEM_BLK '}'
{
	if (cfg_cert_vfy(cur_pem) != 0)
		cfg_cert_add(cur_pem, &cur_fa->certs);
	else {
		cfg_cert_file_free(&cur_pem);
		YYABORT;
	}
	cur_pem = NULL;
};

FB_MATCH_GLOBAL: TOK_MATCH_GLOBAL '=' BOOL { cur_fa->match_global_certs = $3; };

FB_SNI_NOMATCH_ABORT:TOK_SNI_NOMATCH_ABORT '=' BOOL
{
		cur_fa->sni_nomatch_abort = $3;
};
FB_TLS: TOK_TLS '=' BOOL { if ($3) cur_fa->etype = ENC_TLS; }
FB_SSL: TOK_SSL '=' BOOL { if ($3) cur_fa->etype = ENC_SSL; }
FB_CIPHERS: TOK_CIPHERS '=' STRING { if ($3) cur_fa->ciphers = strdup($3); };
FB_PREF_SRV_CIPH: TOK_PREFER_SERVER_CIPHERS '=' BOOL
{
	cur_fa->prefer_server_ciphers = $3;
};

QUIET_REC: TOK_QUIET '=' BOOL { cfg->QUIET = $3; };

WORKERS_REC: TOK_WORKERS '=' UINT { cfg->NCORES = $3; };

BACKLOG_REC: TOK_BACKLOG '=' UINT { cfg->BACKLOG = $3; };

KEEPALIVE_REC: TOK_KEEPALIVE '=' UINT { cfg->TCP_KEEPALIVE_TIME = $3; };

TLS_REC: TOK_TLS '=' BOOL { if ($3) { cfg->ETYPE = ENC_TLS; } };

SSL_REC: TOK_SSL '=' BOOL { if ($3) { cfg->ETYPE = ENC_SSL; } };

SSL_ENGINE_REC: TOK_SSL_ENGINE '=' STRING { if ($3) cfg->ENGINE = strdup($3); };

PREFER_SERVER_CIPHERS_REC: TOK_PREFER_SERVER_CIPHERS '=' BOOL
{
	cfg->PREFER_SERVER_CIPHERS = $3;
};

CHROOT_REC: TOK_CHROOT '=' STRING
{
	if ($3 && config_param_validate("chroot", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
};

BACKEND_REC: TOK_BACKEND '=' STRING
{
	if ($3 && config_param_validate("backend", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
};

PEM_FILE_REC: TOK_PEM_FILE '=' STRING
{
	if ($3 && config_param_validate("pem-file", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
}
	| TOK_PEM_FILE '=' '{'
{
	/* NB: Mid-rule action */
	AZ(cur_pem);
	cur_pem = cfg_cert_file_new();
}
	PEM_BLK '}'
{
	if (cfg_cert_vfy(cur_pem) != 0) {
		if (cfg->CERT_DEFAULT != NULL) {
			struct cfg_cert_file *tmp = cfg->CERT_DEFAULT;
			cfg_cert_add(tmp, &cfg->CERT_FILES);
		}
		cfg->CERT_DEFAULT = cur_pem;
	} else {
		cfg_cert_file_free(&cur_pem);
		YYABORT;
	}
	cur_pem = NULL;
};


SYSLOG_REC: TOK_SYSLOG '=' BOOL { cfg->SYSLOG = $3; };
DAEMON_REC: TOK_DAEMON '=' BOOL { cfg->DAEMONIZE = $3; };
SNI_NOMATCH_ABORT_REC
	: TOK_SNI_NOMATCH_ABORT '=' BOOL
{
	cfg->SNI_NOMATCH_ABORT = $3;
};

CIPHERS_REC: TOK_CIPHERS '=' STRING { if ($3) cfg->CIPHER_SUITE = strdup($3); };

USER_REC: TOK_USER '=' STRING
{
	if ($3 && config_param_validate("user", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
};

GROUP_REC: TOK_GROUP '=' STRING
{
	if ($3 && config_param_validate("group", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
};

WRITE_IP_REC: TOK_WRITE_IP '=' BOOL { cfg->WRITE_IP_OCTET = $3; };

WRITE_PROXY_REC: TOK_WRITE_PROXY '=' BOOL { cfg->WRITE_PROXY_LINE_V2 = $3; };

WRITE_PROXY_V1_REC: TOK_WRITE_PROXY_V1 '=' BOOL
{
	cfg->WRITE_PROXY_LINE_V1 = $3;
};

WRITE_PROXY_V2_REC: TOK_WRITE_PROXY_V2 '=' BOOL
{
	cfg->WRITE_PROXY_LINE_V2 = $3;
};

PROXY_PROXY_REC: TOK_PROXY_PROXY '=' BOOL { cfg->PROXY_PROXY_LINE = $3; };

SYSLOG_FACILITY_REC: TOK_SYSLOG_FACILITY '=' STRING
{
	if ($3 &&
	    config_param_validate("syslog-facility", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
};

PACE_FRONTEND_REC: TOK_PACE_FRONTEND '=' INT { abort(); };
PACE_BACKEND_REC: TOK_PACE_BACKEND '=' INT { abort(); };

%%

void
yyerror(hitch_config *cfg, const char *s)
{
	(void) cfg;

	/* Clean up if FRONTEND_BLK parsing failed */
	if (cur_fa != NULL)
		FREE_OBJ(cur_fa);

	fprintf(stderr, "parsing error: line: %d: %s\n", yyget_lineno(), s);
}
