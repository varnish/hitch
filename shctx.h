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

/* Init shared memory context if not allocated and set SSL context callbacks
 * size is the max number of stored session 
 * Returns: -1 on alloc failure, size if performs context alloc, and 0 if just
 * perform callbacks registration */
int shared_context_init(SSL_CTX *ctx, int size);

#endif /* SHCTX_H */
