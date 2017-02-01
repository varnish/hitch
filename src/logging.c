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
  * THIS SOFTWARE IS PROVIDED BY VARNISH SOFTWARE ``AS IS'' AND
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

#include "config.h"

#include <netdb.h>
#include <netinet/tcp.h>  /* TCP_NODELAY */
#include <net/if.h>

#include <libgen.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
#include <time.h>
#include <unistd.h>

#include "logging.h"
#include "configuration.h"
#include "hitch.h"
#include "hssl_locks.h"
#include "ocsp.h"
#include "shctx.h"
#include "foreign/vpf.h"
#include "foreign/uthash.h"

/* hitch.c */
extern hitch_config *CONFIG;

#define LOG_REOPEN_INTERVAL 60

FILE * logfile;
struct stat logf_st;
time_t logf_check_t;

#define LOGPROXY(...)							\
	do {								\
		if (!CONFIG->QUIET && (logfile || CONFIG->SYSLOG))		\
			logproxy(LOG_INFO, __VA_ARGS__ );		\
	} while(0)

#define ERRPROXY(...)							\
	do {								\
		if (logfile || CONFIG->SYSLOG)				\
			logproxy(LOG_ERR, __VA_ARGS__ );		\
	} while (0)

double
Time_now(void)
{
	struct timespec tv;

	AZ(clock_gettime(CLOCK_REALTIME, &tv));
	return (tv.tv_sec + 1e-9 * tv.tv_nsec);
}

void
VWLOG(int level, const char *fmt, va_list ap)
{
	struct timeval tv;
	struct tm tm;
	char buf[1024];
	int n;
	va_list ap1;

	va_copy(ap1, ap);
	if (CONFIG->SYSLOG) {
		vsyslog(level, fmt, ap);
	}

	if (!logfile) {
		va_end(ap1);
		return;
	}
	AZ(gettimeofday(&tv, NULL));
	if (logfile != stdout && logfile != stderr
	    && tv.tv_sec >= logf_check_t + LOG_REOPEN_INTERVAL) {
		struct stat st;
		if (stat(CONFIG->LOG_FILENAME, &st) < 0
		    || st.st_dev != logf_st.st_dev
		    || st.st_ino != logf_st.st_ino) {
			fclose(logfile);

			logfile = fopen(CONFIG->LOG_FILENAME, "a");
			if (logfile == NULL
			    || fstat(fileno(logfile), &logf_st) < 0)
				memset(&logf_st, 0, sizeof(logf_st));
		}
		logf_check_t = tv.tv_sec;
	}

	AN(localtime_r(&tv.tv_sec, &tm));
	n = strftime(buf, sizeof(buf), "%Y%m%dT%H%M%S", &tm);
	snprintf(buf + n, sizeof(buf) - n, ".%06d [%5d] %s",
	    (int) tv.tv_usec, getpid(), fmt);
	vfprintf(logfile, buf, ap1);
	va_end(ap1);
}

void
WLOG(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	VWLOG(level, fmt, ap);
	va_end(ap);
}

#define LOG(...)							\
	do {								\
		if (!CONFIG->QUIET)					\
			WLOG(LOG_INFO, __VA_ARGS__ );			\
	} while (0)
#define ERR(...)	WLOG(LOG_ERR, __VA_ARGS__ )

#define LOGL(...) WLOG(LOG_INFO, __VA_ARGS__)

#define SOCKERR(msg)						\
	do {							\
		if (errno == ECONNRESET) {			\
			LOG(msg ": %s\n", strerror(errno));	\
		} else {					\
			ERR(msg ": %s\n", strerror(errno));	\
		}						\
	} while (0)


void
logproxy(int level, const proxystate* ps, const char *fmt, ...)
{
	char buf[1024];
	char hbuf[INET6_ADDRSTRLEN+1];
	char sbuf[8];
	int n;
	va_list ap;
	socklen_t salen;

	CHECK_OBJ_NOTNULL(ps, PROXYSTATE_MAGIC);

	salen = (ps->remote_ip.ss_family == AF_INET) ?
	    sizeof(struct sockaddr) : sizeof(struct sockaddr_in6);
	n = getnameinfo((struct sockaddr *) &ps->remote_ip, salen, hbuf,
		sizeof hbuf, sbuf, sizeof sbuf,
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (n != 0) {
		strcpy(hbuf, "n/a");
		strcpy(sbuf, "n/a");
	}

	va_start(ap, fmt);
	if (ps->remote_ip.ss_family == AF_INET)
		snprintf(buf, sizeof(buf), "%s:%s :%d %d:%d %s",
		    hbuf, sbuf, ps->connect_port, ps->fd_up, ps->fd_down, fmt);
	else
		snprintf(buf, sizeof(buf), "[%s]:%s :%d %d:%d %s",
		    hbuf, sbuf, ps->connect_port, ps->fd_up, ps->fd_down, fmt);
	VWLOG(level, buf, ap);
	va_end(ap);
}

// XXX: Rename
void
fail(const char *s)
{
	ERR("%s: %s\n", s, strerror(errno));
	exit(1);
}


void
log_ssl_error(proxystate *ps, const char *what, ...)
{
	va_list ap;
	int e;
	char buf[256];
	char whatbuf[1024];

	CHECK_OBJ_ORNULL(ps, PROXYSTATE_MAGIC);

	va_start(ap, what);
	vsnprintf(whatbuf, sizeof(whatbuf), what, ap);
	va_end(ap);

	while ((e = ERR_get_error())) {
		ERR_error_string_n(e, buf, sizeof(buf));
		if (ps)
			ERRPROXY(ps, "%s: %s\n", whatbuf, buf);
		else
			ERR("%s: %s\n", whatbuf, buf);
	}
}
