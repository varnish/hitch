/*-
  * Copyright 2011 Bump Technologies, Inc. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *
  *    1. Redistributions of source code must retain the above copyright
  *       notice, this list of conditions and the following disclaimer.
  *
  *    2. Redistributions in binary form must reproduce the above copyright
  *       notice, this list of conditions and the following disclaimer in the
  *       documentation and/or other materials provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY BUMP TECHNOLOGIES, INC. ``AS IS'' AND ANY
  * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL BUMP TECHNOLOGIES, INC. OR CONTRIBUTORS BE
  * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
  * THE POSSIBILITY OF SUCH DAMAGE.
  *
  * The views and conclusions contained in the software and documentation are
  * those of the authors and should not be interpreted as representing
  * official policies, either expressed or implied, of Bump Technologies, Inc.
  *
  **/

#include <stdlib.h>

#include "foreign/vas.h"
#include "ringbuffer.h"

/* Initialize a ringbuffer structure to empty */

void
ringbuffer_init(ringbuffer *rb, int num_slots, int data_len)
{
	rb->num_slots = num_slots ?: DEF_RING_SLOTS;
	rb->data_len = data_len ?: DEF_RING_DATA_LEN;
	rb->slots = malloc(rb->num_slots * sizeof(rb->slots[0]));
	AN(rb->slots);

	rb->head = &rb->slots[0];
	rb->tail = &rb->slots[0];
	int x;
	for (x=0; x < rb->num_slots; x++) {
		rb->slots[x].next = &(rb->slots[(x + 1) % rb->num_slots]);
		rb->slots[x].data = malloc(rb->data_len);
		AN(rb->slots[x].data);
	}
	rb->used = 0;
	rb->bytes_written = 0;
}

void
ringbuffer_cleanup(ringbuffer *rb)
{
	int x;
	for (x=0; x < rb->num_slots; x++) {
		free(rb->slots[x].data);
	}
	free(rb->slots);
}

/** READ FUNCTIONS **/

/* Return a char * that represents the current unconsumed buffer */
char *
ringbuffer_read_next(ringbuffer *rb, int * length)
{
	assert(rb->used);
	*length = rb->head->left;
	return rb->head->ptr;
}

/* Mark consumption of only part of the read head buffer */
void
ringbuffer_read_skip(ringbuffer *rb, int length)
{
	assert(rb->used);
	rb->head->ptr += length;
	rb->head->left -= length;
}

/* Pop a consumed (fully read) head from the buffer */
void
ringbuffer_read_pop(ringbuffer *rb)
{
	assert(rb->used);
	rb->head = rb->head->next;
	rb->used--;
}


/** WRITE FUNCTIONS **/

/* Return the tail ptr (current target of new writes) */
char *
ringbuffer_write_ptr(ringbuffer *rb)
{
	assert(rb->used < rb->num_slots);
	return rb->tail->data;
}

/* Mark the tail appended for `length` bytes, and move the cursor
 * to the next slot */
void
ringbuffer_write_append(ringbuffer *rb, int length)
{
	assert(rb->used < rb->num_slots);

	rb->used++;

	rb->tail->ptr = rb->tail->data;
	rb->tail->left = length;
	rb->tail = rb->tail->next;
}

/** RING STATE FUNCTIONS **/

/* Used size of the ringbuffer */
int
ringbuffer_size(ringbuffer *rb)
{
    return rb->used;
}

/* Used size of the ringbuffer */
int
ringbuffer_capacity(ringbuffer *rb)
{
    return rb->num_slots;
}

/* Is the ringbuffer completely empty (implies: no data to be written) */
int
ringbuffer_is_empty(ringbuffer *rb)
{
    return rb->used == 0;
}

/* Is the ringbuffer completely full (implies: no more data should be read) */
int
ringbuffer_is_full(ringbuffer *rb)
{
    return rb->used == rb->num_slots;
}

