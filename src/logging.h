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

#ifndef LOGGING_H_INCLUDED
#define LOGGING_H_INCLUDED

#include "config.h"

#include <arpa/inet.h>

#include <ev.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/ioctl.h>

// #include "asn_gentm.h"
#include "configuration.h"
#include "hitch.h"
// #include "miniobj.h"
// #include "ringbuffer.h"
// #include "vas.h"
// #include "vsb.h"


double Time_now(void);

void WLOG(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void logproxy(int level, const proxystate* ps, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

void VWLOG(int level, const char *fmt, va_list ap);
void WLOG(int level, const char *fmt, ...);

void log_ssl_error(proxystate *ps, const char *what, ...);

void fail(const char *s);

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

#define LOGPROXY(...)							\
	do {								\
		if (!CONFIG->QUIET && (logfile || CONFIG->SYSLOG))	\
			logproxy(LOG_INFO, __VA_ARGS__ );		\
	} while(0)

#define ERRPROXY(...)							\
	do {								\
		if (logfile || CONFIG->SYSLOG)				\
			logproxy(LOG_ERR, __VA_ARGS__ );		\
	} while (0)



#endif  /* LOGGING_H_INCLUDED */
