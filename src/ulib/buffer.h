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
// buffer.h
// Manage unsigned byte buffers
// NOTES:
//    Unless otherwise noted, functions returning buffer_t* return the same
//    object passed to them.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_BUFFER_H
#define _ULIB_BUFFER_H

#include "configify.h"
#if ULIB_ENABLE_BUFFERS

#include "types.h"
#include "util.h"


// Method of buffer growth. See config_template.h for descriptions.
#define BUFFER_GROW_NONE 1
#define BUFFER_GROW_ADD  2
#define BUFFER_GROW_MUL  3
#define BUFFER_GROW_FRAC 4

// To simplify things, use an int that allows adding 1 to the maximum size
// without overflowing.
#if BUFFER_MAX_BYTES < 0xFFU
 typedef uint8_t buflen_t;
#elif BUFFER_MAX_BYTES < 0xFFFFU
 typedef uint16_t buflen_t;
#elif BUFFER_MAX_BYTES < 0xFFFFFFFFU
 typedef uint32_t buflen_t;
#elif BUFFER_MAX_BYTES < 0xFFFFFFFFFFFFFFFFU
 typedef uint64_t buflen_t;
#else
# error "BUFFER_MAX_BYTES is too big"
#endif

typedef struct {
#if ULIB_USE_STRUCT_ID
	struct_id_t id;
#endif
#if BUFFERS_USE_MALLOC
	// The bank of all bytes in the buffer.
	uint8_t *bank;
	// The maximum size of the buffer. Constrained by BUFFER_MAX_BYTES.
	buflen_t max_size;
#else
	void *bank[BUFFER_MAX_BYTES];
#endif
	// The number of bytes allocated.
	buflen_t allocated;
} buffer_t;
typedef struct {
	// The initial size of the buffer.
	buflen_t initial_size;
	// See buffer_t for details on these fields.
	buflen_t max_size;
} buffer_init_t;

// Initialize a buffer_t structure which is presumed to be filled with junk
// using values from a buffer_init_t.
// If init is NULL, use defaults.
buffer_t* buffer_init(buffer_t *b, const buffer_init_t *init);
//
// Allocate and initialize a new buffer_t structure using values from an
// buffer_init_t.
// If init is NULL, use defaults.
#if BUFFERS_USE_MALLOC
buffer_t* buffer_new(const buffer_init_t *init);
//
// Free a buffer and it's bank.
buffer_t* _buffer_free(buffer_t *b);
INLINE buffer_t* buffer_free(buffer_t *b) {
	if (POINTER_IS_VALID(b)) {
		return _buffer_free(b);
	}
	return NULL;
}
#endif
//
// Grow a buffer.
// If add is >0, try to add that many bytes instead of using the built-in
// algorithm.
// If add is <=0, use BUFFER_GROW_FACTOR to determine the number of new bytes.
// Returns the number of bytes added to the buffer, which is 0 if the buffer
// couldn't grow any more.
buflen_t buffer_grow(buffer_t *b, buflen_t add);


#endif // ULIB_ENABLE_BUFFERS
#endif // _ULIB_BUFFER_H
#ifdef __cplusplus
 }
#endif
