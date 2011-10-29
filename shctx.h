/*
 * shctx.h
 *
 * Copyright (C) 2011 EXCELIANCE
 *
 * Author: Emeric Brun - emeric@exceliance.fr
 *
 */

#ifndef SHCTX_H
#define SHCTX_H
#include <openssl/ssl.h>
#include <stdint.h>

#ifndef SHSESS_MAX_FOOTER_LEN
#define SHSESS_MAX_FOOTER_LEN sizeof(uint32_t) \
				+ EVP_MAX_MD_SIZE
#endif 

#ifndef SHSESS_MAX_DATA_LEN
#define SHSESS_MAX_DATA_LEN 512
#endif

#define SHSESS_MAX_ENCODED_LEN SSL_MAX_SSL_SESSION_ID_LENGTH \
				+ SHSESS_MAX_DATA_LEN \
				+ SHSESS_MAX_FOOTER_LEN


/* Callback called on a new session event:
 * session contains the sessionid zeros padded to SSL_MAX_SSL_SESSION_ID_LENGTH
 *                                               followed by ASN1 session encoding.
 * len is set to SSL_MAX_SSL_SESSION_ID_LENGTH + ASN1 session length
 * len is always less than SSL_MAX_SSL_SESSION_ID_LENGTH + SHSESS_MAX_DATA_LEN.
 * Remaining Bytes from len to SHSESS_MAX_ENCODED_LEN can be used to add a footer.
 * cdate is the creation date timestamp.
 */ 
void shsess_set_new_cbk(void (*func)(unsigned char *session, unsigned int len, long cdate));

/* Add a session into the cache, 
 * session contains the sessionid zeros padded to SSL_MAX_SSL_SESSION_ID_LENGTH
 *                                             followed by ASN1 session encoding.
 * len is set to SSL_MAX_SSL_SESSION_ID_LENGTH + ASN1 data length.
 *            if len greater than SHSESS_MAX_ENCODED_LEN, session is not added.
 * if cdate not 0, on get events session creation date will be reset to cdate */
void shctx_sess_add(const unsigned char *session, unsigned int session_len, long cdate);

/* Init shared memory context if not allocated and set SSL context callbacks
 * size is the max number of stored session 
 * Returns: -1 on alloc failure, size if performs context alloc, and 0 if just
 * perform callbacks registration */
int shared_context_init(SSL_CTX *ctx, int size);

#endif /* SHCTX_H */
