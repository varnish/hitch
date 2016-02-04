%{
#include <stdio.h>
#include <assert.h>

#include "configuration.h"
#include "cfg_parser.h"

%}

%option nounput noinput
%option yylineno
%%
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

"on"|"off"|"true"|"false"|\"on\"|\"off\"|\"true\"|\"false\" {
	if (!strcmp(yytext, "on") || !strcmp(yytext, "true"))
		yylval.i = 1;
	else if (!strcmp(yytext, "off") || !strcmp(yytext, "false"))
		yylval.i = 0;
	return (BOOL);

}

"frontend"	{ return (TOK_FRONTEND); }
"backend"	{ return (TOK_BACKEND); }
"quiet"		{ return (TOK_QUIET); }
"ssl"		{ return (TOK_SSL); }
"tls"		{ return (TOK_TLS); }
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
11015		{ return (TOK_PARAM_SYSLOG_FACILITY); }
"daemon"		{ return (TOK_DAEMON); }
"write-ip"		{ return (TOK_WRITE_IP); }
"write-proxy"		{ return (TOK_WRITE_PROXY); }
"write-proxy-v1"		{ return (TOK_WRITE_PROXY_V1); }
"write-proxy-v2"		{ return (TOK_WRITE_PROXY_V2); }
"pem-file"		{ return (TOK_PEM_FILE); }
"proxy-proxy"		{ return (TOK_PROXY_PROXY); }
"backend-connect-timeout"	{ return (TOK_BACKEND_CONNECT_TIMEOUT); }
"ssl-handshake-timeout"		{ return (TOK_SSL_HANDSHAKE_TIMEOUT); }
"recv-bufsize"		{ return (TOK_RECV_BUFSIZE); }
"send-bufsize"		{ return (TOK_SEND_BUFSIZE); }
"log-filename"		{ return (TOK_LOG_FILENAME); }
"ring-slots"		{ return (TOK_RING_SLOTS); }
"ring-data-len"		{ return (TOK_RING_DATA_LEN); }
"pidfile"		{ return (TOK_PIDFILE); }
"sni-nomatch-abort"	{ return (TOK_SNI_NOMATCH_ABORT); }


\"(\\.|[^\\"])*\" {
	char *s;
	if (strlen(yytext) == 2) {
		yylval.s = NULL;
		return (STRING);
	}
	s = strchr(yytext + 1, '"');
	*s = '\0';
	yylval.s = strdup(yytext + 1);
	return (STRING);
}
[a-zA-Z0-9\-]+    {
	yylval.s = strdup(yytext);
	return (STRING);
}

.		;
%%
