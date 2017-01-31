/*-
 * Copyright (c) 2015-2016 Varnish Software
 * All rights reserved.
 *
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "foreign/vas.h"
#include "hssl_locks.h"

/*
 * OpenSSL 1.1 has a new threading implementation that no longer
 * requires the application to set its own locking callbacks.
 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static int num_locks = 0;
static pthread_mutex_t *locks = NULL;

static void
hssl_lock_cb(int mode, int type, const char *file, int line)
{

	(void)file;
	(void)line;
	AN(locks);
	assert(type >= 0 && type < num_locks);
	if (mode & CRYPTO_LOCK)
		AZ(pthread_mutex_lock(&locks[type]));
	else
		AZ(pthread_mutex_unlock(&locks[type]));
}

void
HSSL_Locks_Init(void)
{
	int i;

	assert(locks == NULL || CRYPTO_get_locking_callback() == hssl_lock_cb);
	if (locks != NULL)
		return;

	num_locks = CRYPTO_num_locks();
	assert(num_locks > 0);
	locks = malloc(sizeof (pthread_mutex_t) * num_locks);
	AN(locks);
	for (i = 0; i < num_locks; i++)
		AZ(pthread_mutex_init(&locks[i], NULL));

	AZ(CRYPTO_get_locking_callback());
	CRYPTO_set_locking_callback(hssl_lock_cb);
}

#else

void
HSSL_Locks_Init(void)
{
}

#endif
