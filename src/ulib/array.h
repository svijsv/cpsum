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
// array.h
// Manage arrays of pointers to objects
//
// NOTES:
//    A stored object may validly be NULL.
//
//    Unless otherwise noted, functions returning array_t* return the same
//    object passed to them.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_ARRAY_H
#define _ULIB_ARRAY_H

#include "configify.h"
#if ULIB_ENABLE_ARRAYS

#include "types.h"
#include "util.h"


// Method of array growth. See config_template.h for descriptions.
#define ARRAY_GROW_NONE 0
#define ARRAY_GROW_ADD  1
#define ARRAY_GROW_MUL  2
#define ARRAY_GROW_FRAC 3

// To simplify things, use an int that allows adding 1 to the maximum size
// without overflowing.
#if ARRAY_MAX_OBJECTS < 0xFFU
 typedef uint8_t arlen_t;
#elif ARRAY_MAX_OBJECTS < 0xFFFFU
 typedef uint16_t arlen_t;
#elif ARRAY_MAX_OBJECTS < 0xFFFFFFFFU
 typedef uint32_t arlen_t;
#elif ARRAY_MAX_OBJECTS < 0xFFFFFFFFFFFFFFFFU
 typedef uint64_t arlen_t;
#else
# error "ARRAY_MAX_OBJECTS is too big"
#endif

typedef struct {
#if ULIB_USE_STRUCT_ID
	struct_id_t id;
#endif
#if ARRAYS_USE_MALLOC
	// The bank of all objects in the array.
	void **bank;
	// The number of bank slots allocated.
	arlen_t allocated;
#else
	void *bank[ARRAY_MAX_OBJECTS];
#endif
	// The number of bank slots used.
	arlen_t used;
	// The function used to free the objects when required. May be NULL.
	void (*free_obj)(void *obj);
	// The function used to compare objects when required. If the search function
	// is given a different comparison function, that takes precedence. If both
	// are NULL, do a simple pointer comparison.
	// obj is the object to find, ent is the current array item being checked
	// against it.
	int (*compare)(const void *obj, const void *ent);
} array_t;

typedef struct {
	// See array_t definition for meanings of these fields.
	void (*free_obj)(void *obj);
	int (*compare)(const void *a, const void *b);
} array_init_t;

// Initialize an array_t structure which is presumed to be filled with junk
// using values from an array_init_t.
// If init is NULL, use defaults.
array_t* array_init(array_t *a, const array_init_t *init);
#if ARRAYS_USE_MALLOC
// Allocate and initialize a new array_t structure using values from an
// array_init_t.
// If init is NULL, use defaults.
array_t* array_new(const array_init_t *init);
// Free an array, calling free_obj() on each object.
array_t* _array_free(array_t *a);
INLINE array_t* array_free(array_t *a) {
	if (POINTER_IS_VALID(a)) {
		return _array_free(a);
	}
	return NULL;
}
#endif
// Empty an array's bank, calling free_obj() on each object.
array_t* array_clear(array_t *a);
// Add an object to the end of the array.
array_t* array_append(array_t *a, void *object);
// Add an object to the end of the array if it's not already stored.
array_t* array_append_checked(array_t *a, void *object, int (*compare)(const void *obj, const void *ent));
// Synonym for array_append().
INLINE array_t* array_push(array_t *a, void *object) {
	return array_append(a, object);
}
// Remove an object from the end of the array. If ret_obj != NULL set it to
// the removed object, otherwise free the object with free_obj().
array_t* array_pop(array_t *a, void **ret_obj);
// Find the index of an object, starting at index 'start'. If the search
// reaches the end of the array, it doesn't wrap around.
// If compare() is NULL, use a->compare() if that's non-NULL. Otherwise check
// if the pointers are the same.
// Returns (arlen_t )-1 if no match is found.
arlen_t array_find_index(const array_t *a, arlen_t start, const void *object, int (*compare)(const void *obj, const void *ent));
// Find object in the array.
// If compare() is NULL, use a->compare() if that's non-NULL. Otherwise check
// if the pointers are the same.
// Returns NULL if no match is found.
void* array_find_object(const array_t *a, const void *object, int (*compare)(const void *obj, const void *ent));


#endif // ULIB_ENABLE_ARRAYS
#endif // _ULIB_ARRAY_H
#ifdef __cplusplus
 }
#endif
