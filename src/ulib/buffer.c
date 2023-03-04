// SPDX-License-Identifier: GPL-3.0-only
/***********************************************************************
*                                                                      *
*                                                                      *
* Copyright 2022, 2023 svijsv                                          *
* This program is free software: you can redistribute it and/or modify *
* it under the terms of the GNU General Public License as published by *
* the Free Software Foundation, version 3.                             *
*                                                                      *
* This program is distributed in the hope that it will be useful, but  *
* WITHOUT ANY WARRANTY; without even the implied warranty of           *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU    *
* General Public License for more details.                             *
*                                                                      *
* You should have received a copy of the GNU General Public License    *
* along with this program. If not, see <http:// www.gnu.org/licenses/>.*
*                                                                      *
*                                                                      *
***********************************************************************/
// buffer.c
// Manage unsigned byte buffers
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "buffer.h"
#if ULIB_ENABLE_BUFFERS

#include "debug.h"
#include "util.h"


#if BUFFERS_USE_MALLOC
# include <stdlib.h>
#endif

#if BUFFER_GROW_FACTOR < 1
# error "BUFFER_GROW_FACTOR < 1"
#endif
#if (BUFFER_GROW_METHOD == BUFFER_GROW_MUL) && (BUFFER_GROW_FACTOR <= 1)
# error "(BUFFER_GROW_METHOD == BUFFER_GROW_MUL) && (BUFFER_GROW_FACTOR <= 1)"
#endif
#if (BUFFER_GROW_METHOD == BUFFER_GROW_FRAC) && ((BUFFER_INITIAL_SIZE / BUFFER_GROW_FACTOR) < 1)
# error "(BUFFER_INITIAL_SIZE / BUFFER_GROW_FACTOR) < 1"
#endif
#if BUFFER_MAX_BYTES < 1
# error "BUFFER_MAX_BYTES < 1"
#endif

#if ULIB_USE_STRUCT_ID
# define IS_BUFFER_ID(s) (s->id.value == ID_BUFFER)
#else
# define IS_BUFFER_ID(s) (true)
#endif
#if BUFFERS_USE_MALLOC
# define ASSERT_BUFFER(b) assert( \
		((b) != NULL) && \
		(IS_BUFFER_ID(b)) && \
		((b)->max_size <= BUFFER_MAX_BYTES) && \
		((b)->allocated <= (b)->max_size) && \
		((b)->bank != NULL) \
		)
#else
# define ASSERT_BUFFER(b) assert( \
		((b) != NULL) && \
		(IS_BUFFER_ID(b)) && \
		((b)->allocated <= BUFFER_MAX_BYTES) \
		)
#endif

buffer_t* buffer_init(buffer_t *b, const buffer_init_t *init) {
	assert(POINTER_IS_VALID(b));

#if DO_BUFFER_SAFETY_CHECKS
	if (b == NULL) {
		return NULL;
	}
#endif

#if ULIB_USE_STRUCT_ID
	b->id.value = ID_BUFFER;
#endif

#if BUFFERS_USE_MALLOC
	b->allocated = 1;
	b->max_size = BUFFER_MAX_BYTES;

	if (init != NULL) {
		if ((init->max_size > 0) && (init->max_size < BUFFER_MAX_BYTES)) {
			b->max_size = init->max_size;
		}
		if (init->initial_size > 0) {
			if (init->initial_size <= b->max_size) {
				b->allocated = init->initial_size;
			} else {
				b->allocated = b->max_size;
			}
		}
	}
	b->bank = malloc(b->allocated);
#else
	UNUSED(init);
	b->allocated = BUFFER_MAX_BYTES;
#endif

	return b;
}
#if BUFFERS_USE_MALLOC
buffer_t* buffer_new(const buffer_init_t *init) {
	buffer_t *b = malloc(sizeof(*b));
	return buffer_init(b, init);
}
buffer_t* _buffer_free(buffer_t *b) {
	// The inline wrapper checks for null to avoid avoid a context switch when
	// true.
	//if (POINTER_IS_VALID(b) && IS_BUFFER_ID(b)) {
	if (IS_BUFFER_ID(b)) {
		if (POINTER_IS_VALID(b->bank) && (b->allocated > 0)) {
			free(b->bank);
		}
		free(b);
	}

	return NULL;
}
#endif

buflen_t buffer_grow(buffer_t *b, buflen_t add) {
	buflen_t old_size, new_size;
	uint8_t *tmp;

	ASSERT_BUFFER(b);

#if DO_BUFFER_SAFETY_CHECKS
	if (b == NULL) {
		return 0;
	}
#endif

	old_size = b->allocated;

#if BUFFERS_USE_MALLOC
	if (add <= 0) {
# if BUFFER_GROW_METHOD == BUFFER_GROW_ADD
		add = BUFFER_GROW_FACTOR;
# elif BUFFER_GROW_METHOD == BUFFER_GROW_MUL
		add = CLIP_UMUL(b->allocated, BUFFER_GROW_FACTOR-1, b->max_size);
# elif BUFFER_GROW_METHOD == BUFFER_GROW_FRAC
		add = (b->allocated / BUFFER_GROW_FACTOR);
# elif BUFFER_GROW_METHOD == BUFFER_GROW_NONE
		add = 0;
# else
#  error "Unsupported BUFFER_GROW_METHOD"
# endif
	}
	new_size = CLIP_UADD(b->allocated, add, b->max_size);
	if (new_size != old_size) {
		tmp = realloc(b->bank, new_size);
		if (tmp != NULL) {
			b->allocated = new_size;
			b->bank = tmp;
		}
	}
#else // !BUFFERS_USE_MALLOC
	UNUSED(add);
	new_size = old_size;
#endif

	return new_size - old_size;
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_BUFFERS
#ifdef __cplusplus
 }
#endif
