/*
 * shctx.c
 *
 * Copyright (C) 2011 EXCELIANCE
 *
 * Author: Emeric Brun - emeric@exceliance.fr
 *
 */

#include "config.h"

#include <sys/mman.h>

#ifdef USE_SYSCALL_FUTEX
#  include <unistd.h>
#  include <linux/futex.h>
#  include <sys/syscall.h>
#else
#  include <pthread.h>
#endif

#include "ebtree/ebmbtree.h"
#include "foreign/vas.h"
#include "shctx.h"

struct shared_session {
	struct ebmb_node	key;
	unsigned char		key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
	long			c_date;
	int			data_len;
	unsigned char		data[SHSESS_MAX_DATA_LEN];
	struct shared_session	*p;
	struct shared_session	*n;
};

struct shared_context {
#ifdef USE_SYSCALL_FUTEX
	unsigned		waiters;
#else
	pthread_mutex_t		mutex;
#endif
	struct shared_session	active;
	struct shared_session	free;
};

/* Static shared context */
static struct shared_context *shctx = NULL;

/* Callbacks */
shsess_new_f *shared_session_new_cbk;

/* Lock functions */
#ifdef USE_SYSCALL_FUTEX
static inline unsigned
xchg(unsigned *ptr, unsigned x)
{
	__asm volatile("lock xchgl %0,%1"
		     : "=r" (x), "+m" (*ptr)
		     : "0" (x)
		     : "memory");
	return (x);
}

static inline unsigned
cmpxchg(unsigned *ptr, unsigned old, unsigned new)
{
	unsigned ret;

	__asm volatile("lock cmpxchgl %2,%1"
		     : "=a" (ret), "+m" (*ptr)
		     : "r" (new), "0" (old)
		     : "memory");
	return (ret);
}

static inline unsigned char
atomic_dec(unsigned *ptr)
{
	unsigned char ret;
	__asm volatile("lock decl %0\n"
		     "setne %1\n"
		     : "+m" (*ptr), "=qm" (ret)
		     :
		     : "memory");
	return (ret);
}

static inline void
shared_context_lock(void)
{
	unsigned x;

	x = cmpxchg(&shctx->waiters, 0, 1);
	if (x) {
		if (x != 2)
			x = xchg(&shctx->waiters, 2);

		while (x) {
			syscall(SYS_futex, &shctx->waiters, FUTEX_WAIT, 2, NULL, 0, 0);
			x = xchg(&shctx->waiters, 2);
		}
	}
}

static inline void
shared_context_unlock(void)
{
	if (atomic_dec(&shctx->waiters)) {
		shctx->waiters = 0;
		syscall(SYS_futex, &shctx->waiters, FUTEX_WAKE, 1, NULL, 0, 0);
	}
}

#else /* USE_SYSCALL_FUTEX */
#  define shared_context_lock(v) pthread_mutex_lock(&shctx->mutex)
#  define shared_context_unlock(v) pthread_mutex_unlock(&shctx->mutex)
#endif

/* List Macros */

#define shsess_unset(s)			\
	do {				\
		(s)->n->p = (s)->p;	\
		(s)->p->n = (s)->n;	\
	} while (0)

#define shsess_set_free(s)		\
	do {				\
		shsess_unset(s);	\
		(s)->p = &shctx->free;	\
		(s)->n = shctx->free.n;	\
		shctx->free.n->p = s;	\
		shctx->free.n = s;	\
	} while (0)


#define shsess_set_active(s)			\
	do {					\
		shsess_unset(s);		\
		(s)->p = &shctx->active;	\
		(s)->n = shctx->active.n;	\
		shctx->active.n->p = s;		\
		shctx->active.n = s;		\
	} while (0)


#define shsess_get_next()	\
	(shctx->free.p == shctx->free.n ? shctx->active.p : shctx->free.p)

/* Tree Macros */

#define shsess_tree_delete(s) ebmb_delete(&(s)->key)

#define shsess_tree_insert(s) \
	(struct shared_session *)ebmb_insert(&shctx->active.key.node.branches, \
	    &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define shsess_tree_lookup(k) \
	(struct shared_session *)ebmb_lookup(&shctx->active.key.node.branches, \
	    (k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/* Copy-with-padding Macros */

#define shsess_memcpypad(dst, dlen, src, slen)			\
	do {							\
		assert((slen) <= (dlen));			\
		memcpy((dst), (src), (slen));			\
		if ((slen) < (dlen))				\
			memset((char *)(dst) + (slen), 0,	\
			    (dlen) - (slen));			\
	} while (0)

#define shsess_set_key(s, k, l)					\
	do {							\
		shsess_memcpypad((s)->key_data,			\
		    SSL_MAX_SSL_SESSION_ID_LENGTH, (k), (l));	\
	} while (0)

/* SSL context callbacks */

/* SSL callback used on new session creation */
int
shctx_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct shared_session *shsess;
	unsigned char *data,*p;
	const unsigned char *key;
	unsigned keylen;
	unsigned data_len;
	unsigned char encsess[SHSESS_MAX_ENCODED_LEN];

	AN(ssl);

	data_len = i2d_SSL_SESSION(sess, NULL);
	if (data_len > SHSESS_MAX_DATA_LEN)
		return (1);

	/* process ASN1 session encoding before the lock: lower cost */
	p = data = encsess+SSL_MAX_SSL_SESSION_ID_LENGTH;
	i2d_SSL_SESSION(sess, &p);

	shared_context_lock();

	shsess = shsess_get_next();

	shsess_tree_delete(shsess);

	key = SSL_SESSION_get_id(sess, &keylen);
	shsess_set_key(shsess, key, keylen);

	shsess = shsess_tree_insert(shsess);
	AN(shsess);

	/* store ASN1 encoded session into cache */
	shsess->data_len = data_len;
	memcpy(shsess->data, data, data_len);

	/* store creation date */
	shsess->c_date = SSL_SESSION_get_time(sess);

	shsess_set_active(shsess);

	shared_context_unlock();

	if (shared_session_new_cbk) { /* if user level callback is set */
		shsess_memcpypad(encsess, SSL_MAX_SSL_SESSION_ID_LENGTH,
		    key, keylen);

		shared_session_new_cbk(encsess,
		    SSL_MAX_SSL_SESSION_ID_LENGTH + data_len,
		    SSL_SESSION_get_time(sess));
	}

	return (0); /* do not increment session reference count */
}

/* SSL callback used on lookup an existing session cause none found in internal cache */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static SSL_SESSION *
shctx_get_cb(SSL *ssl, unsigned char *key, int key_len, int *do_copy)
#else
static SSL_SESSION *
shctx_get_cb(SSL *ssl, const unsigned char *key, int key_len, int *do_copy)
#endif
{
	struct shared_session *shsess;
	unsigned char data[SHSESS_MAX_DATA_LEN], *p;
	unsigned char padded_key[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned data_len;
	long cdate;
	SSL_SESSION *sess;

	AN(ssl);

        /* allow the session to be freed automatically by openssl */
	*do_copy = 0;

	shsess_memcpypad(padded_key, sizeof padded_key, key, (size_t)key_len);

	shared_context_lock();

	shsess = shsess_tree_lookup(padded_key);
	if(shsess == NULL) {
		shared_context_unlock();
		return (NULL);
	}

	/* backup creation date to reset in session after ASN1 decode */
	cdate = shsess->c_date;

	/* copy ASN1 session data to decode outside the lock */
	data_len = shsess->data_len;
	memcpy(data, shsess->data, shsess->data_len);

	shsess_set_active(shsess);

	shared_context_unlock();

	/* decode ASN1 session */
        p = data;
	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, data_len);

	/* reset creation date */
	if (sess)
		SSL_SESSION_set_time(sess, cdate);

	return (sess);
}

/* SSL callback used to signal session is no more used in internal cache */
void
shctx_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
	struct shared_session *shsess;
	unsigned char padded_key[SSL_MAX_SSL_SESSION_ID_LENGTH];
	const unsigned char *key;
	unsigned keylen;

	AN(ctx);

	key = SSL_SESSION_get_id(sess, &keylen);
	shsess_memcpypad(padded_key, sizeof padded_key, key, (size_t)keylen);

	shared_context_lock();

	shsess = shsess_tree_lookup(padded_key);
	if (shsess != NULL)
		shsess_set_free(shsess);

	/* unlock cache */
	shared_context_unlock();
}

/* User level function called to add a session to the cache (remote updates) */
void
shctx_sess_add(const unsigned char *encsess, unsigned len, long cdate)
{
	struct shared_session *shsess;

	/* check buffer is at least padded key long + 1 byte
		and data_len not too long */
	if (len <= SSL_MAX_SSL_SESSION_ID_LENGTH ||
	    len > SHSESS_MAX_DATA_LEN + SSL_MAX_SSL_SESSION_ID_LENGTH)
		return;

	shared_context_lock();

	shsess = shsess_get_next();
	shsess_tree_delete(shsess);
	shsess_set_key(shsess, encsess, SSL_MAX_SSL_SESSION_ID_LENGTH);

	shsess = shsess_tree_insert(shsess);
	AN(shsess);

	/* store into cache and update earlier on session get events */
	if (cdate)
		shsess->c_date = (long)cdate;

	/* copy ASN1 session data into cache */
	shsess->data_len = len - SSL_MAX_SSL_SESSION_ID_LENGTH;
	memcpy(shsess->data, encsess+SSL_MAX_SSL_SESSION_ID_LENGTH, shsess->data_len);

	shsess_set_active(shsess);

	shared_context_unlock();
}

/* Function used to set a callback on new session creation */
void
shsess_set_new_cbk(shsess_new_f *func)
{

	AN(func);
	shared_session_new_cbk = func;
}

/* Init shared memory context if not allocated and set SSL context callbacks
 * size is the max number of stored session
 * Returns: -1 on alloc failure, size if performs context alloc, and 0 if just perform
 * callbacks registration */

static int
shared_context_alloc(int size)
{
	struct shared_session *prev,*cur;
#ifndef USE_SYSCALL_FUTEX
	pthread_mutexattr_t attr;
#endif
	int i;

	assert(size > 0);

	shctx = mmap(NULL,
	    sizeof *shctx + (size * sizeof(struct shared_session)),
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (shctx == MAP_FAILED)
		return (-1);

#ifdef USE_SYSCALL_FUTEX
	shctx->waiters = 0;
#else
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&shctx->mutex, &attr);
#endif
	memset(&shctx->active.key, 0, sizeof(struct ebmb_node));
	memset(&shctx->free.key, 0, sizeof(struct ebmb_node));

	/* No duplicate authorized in tree: */
	shctx->active.key.node.branches.b[1] = (void *)1;

	cur = &shctx->active;
	cur->n = cur->p = cur;

	cur = &shctx->free;
	for (i = 0 ; i < size ; i++) {
		prev = cur;
		cur++;
		prev->n = cur;
		cur->p = prev;
	}
	cur->n = &shctx->free;
	shctx->free.p = cur;

	return (size);
}

int
shared_context_init(SSL_CTX *ctx, int size)
{
	int ret = 0;

	AN(ctx);

	if (shctx == NULL)
		ret = shared_context_alloc(size);

	/* set SSL internal cache size to external cache / 8  + 123 */
	SSL_CTX_sess_set_cache_size(ctx, size >> 3 | 0x3ff);

	/* Set callbacks */
	SSL_CTX_sess_set_new_cb(ctx, shctx_new_cb);
	SSL_CTX_sess_set_get_cb(ctx, shctx_get_cb);
	SSL_CTX_sess_set_remove_cb(ctx, shctx_remove_cb);

	return (ret);
}
