%{
#include <stdio.h>
#include <stdlib.h>
#include "configuration.h"
#include "vas.h"

extern int yylex (hitch_config *);
extern int yyparse(hitch_config *);
extern FILE *yyin;
int yyget_lineno(void);

int
config_param_validate(char *k, char *v, hitch_config *cfg,
    char *file, int line);

void yyerror(hitch_config *, const char *);
%}

%union {
	int	i;
	char	*s;
}

%debug
%verbose

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
%token TOK_PIDFILE TOK_SNI_NOMATCH_ABORT TOK_SSL TOK_TLS


%param {hitch_config *cfg}
%define parse.error verbose

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
	;

FRONTEND_REC: TOK_FRONTEND '=' STRING
{
	if ($3 && config_param_validate("frontend", $3, cfg, /* XXX: */ "",
	    yyget_lineno()) != 0)
		YYABORT;
}
/* 	| FRONTEND '=' '{' STRING '}' */
/* { */
/* 	printf("frontblk = %s\n", $4); */
/* } */

;
QUIET_REC: TOK_QUIET '=' BOOL { cfg->QUIET = $3; };

WORKERS_REC: TOK_WORKERS '=' UINT { cfg->NCORES = $3; };

BACKLOG_REC: TOK_BACKLOG '=' UINT { cfg->BACKLOG = $3; };

KEEPALIVE_REC: TOK_KEEPALIVE '=' UINT { cfg->TCP_KEEPALIVE_TIME = $3; };

TLS_REC: TOK_TLS '=' BOOL { if ($3) { cfg->ETYPE = ENC_TLS; } };

SSL_REC: TOK_SSL '=' BOOL { if ($3) { cfg->ETYPE = ENC_SSL; } };

SSL_ENGINE_REC: TOK_SSL_ENGINE '=' STRING { if ($3) cfg->ENGINE = $3; };

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
};

SYSLOG_REC: TOK_SYSLOG '=' BOOL { cfg->SYSLOG = $3; };
DAEMON_REC: TOK_DAEMON '=' BOOL { cfg->DAEMONIZE = $3; };
SNI_NOMATCH_ABORT_REC
	: TOK_SNI_NOMATCH_ABORT '=' BOOL
{
	cfg->SNI_NOMATCH_ABORT = $3;
};

CIPHERS_REC: TOK_CIPHERS '=' STRING { if ($3) cfg->CIPHER_SUITE = $3; };

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

%%

void
yyerror(hitch_config *cfg, const char *s)
{
	(void) cfg;
	fprintf(stderr, "parsing error: %s\n", s);
}
