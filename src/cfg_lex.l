%{
#include <stdio.h>
#include <assert.h>

#include "configuration.h"
#include "cfg_parser.h"

char input_line[512];

%}

%option nounput noinput
%option yylineno
%option noyywrap
%%
\n.* {
	strncpy(input_line, yytext + 1, sizeof (input_line));
	yyless(1);
}
[ \t\n\r]         ;
#.*$            ;
"{"             { return ('{'); }
"}"             { return ('}'); }
"="             { return ('='); }

[0-9]+          {
	yylval.i = atoi(yytext);
	return (UINT);
}

\-?[0-9]+ {
	yylval.i = atoi(yytext);
	return (INT);
}

"frontend"	{ return (TOK_FRONTEND); }
"backend"	{ return (TOK_BACKEND); }
"quiet"		{ return (TOK_QUIET); }
"ssl"		{ return (TOK_SSL); }
"tls"		{ return (TOK_TLS); }
"tls-protos"    { return (TOK_TLS_PROTOS); }
"SSLv3"         { return (TOK_SSLv3); }
"TLSv1.0"       { return (TOK_TLSv1_0); }
"TLSv1.1"       { return (TOK_TLSv1_1); }
"TLSv1.2"       { return (TOK_TLSv1_2); }
"ciphers"		{ return (TOK_CIPHERS); }
"ssl-engine"		{ return (TOK_SSL_ENGINE); }
"prefer-server-ciphers"	{ return (TOK_PREFER_SERVER_CIPHERS); }
"workers"		{ return (TOK_WORKERS); }
"backlog"		{ return (TOK_BACKLOG); }
"keepalive"		{ return (TOK_KEEPALIVE); }
"chroot"		{ return (TOK_CHROOT); }
"user"		{ return (TOK_USER); }
"group"		{ return (TOK_GROUP); }
"syslog"		{ return (TOK_SYSLOG); }
"syslog-facility"		{ return (TOK_SYSLOG_FACILITY); }
"daemon"		{ return (TOK_DAEMON); }
"write-ip"		{ return (TOK_WRITE_IP); }
"write-proxy"		{ return (TOK_WRITE_PROXY); }
"write-proxy-v1"		{ return (TOK_WRITE_PROXY_V1); }
"write-proxy-v2"		{ return (TOK_WRITE_PROXY_V2); }
"pem-file"		{ return (TOK_PEM_FILE); }
"proxy-proxy"		{ return (TOK_PROXY_PROXY); }
"alpn-protos"		{ return (TOK_ALPN_PROTOS); }
"backend-connect-timeout"	{ return (TOK_BACKEND_CONNECT_TIMEOUT); }
"ssl-handshake-timeout"		{ return (TOK_SSL_HANDSHAKE_TIMEOUT); }
"recv-bufsize"		{ return (TOK_RECV_BUFSIZE); }
"send-bufsize"		{ return (TOK_SEND_BUFSIZE); }
"log-filename"		{ return (TOK_LOG_FILENAME); }
"ring-slots"		{ return (TOK_RING_SLOTS); }
"ring-data-len"		{ return (TOK_RING_DATA_LEN); }
"pidfile"		{ return (TOK_PIDFILE); }
"sni-nomatch-abort"	{ return (TOK_SNI_NOMATCH_ABORT); }
"host"		{ return (TOK_HOST); }
"port"		{ return (TOK_PORT); }
"match-global-certs"	{ return (TOK_MATCH_GLOBAL); }
"cert"			{ return (TOK_PB_CERT); }
"ocsp-resp-file"	{ return (TOK_PB_OCSP_FILE); }
"ocsp-verify-staple"	{ return (TOK_OCSP_VERIFY); }
"ocsp-resp-tmo"		{ return (TOK_OCSP_RESP_TMO); }
"ocsp-connect-tmo"	{ return (TOK_OCSP_CONN_TMO); }
"ocsp-dir"		{ return (TOK_OCSP_DIR); }

(?i:"yes"|"y"|"on"|"true"|"t"|\"yes\"|\"y\"|\"on\"|\"true\"|\"t\") {
	yylval.i = 1;
	return (BOOL);
}

(?i:"no"|"n"|"off"|"false"|"f"|\"no\"|\"n\"|\"off\"|\"false\"|\"f\") {
	yylval.i = 0;
	return (BOOL);
}

\"(\\.|[^\\"])*\" {
	char *s;
	if (strlen(yytext) == 2) {
		yylval.s = NULL;
		return (STRING);
	}
	s = strchr(yytext + 1, '"');
	*s = '\0';
	yylval.s = yytext + 1;
	return (STRING);
}
[a-zA-Z0-9\-]+    {
	yylval.s = yytext;
	return (STRING);
}

.		;
%%
