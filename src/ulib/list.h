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
// list.h
// Manage lists of pointers to objects
//
// NOTES:
//    A stored object may validly be NULL.
//
//    Unless otherwise noted, functions returning list_t* return the same
//    object passed to them.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_LIST_H
#define _ULIB_LIST_H

#include "configify.h"
#if ULIB_ENABLE_LISTS

#include "types.h"
#include "util.h"


// To simplify things, use an int that allows adding 1 to the maximum size
// without overflowing.
#if LIST_MAX_OBJECTS < 0xFFU
 typedef uint8_t listlen_t;
#elif LIST_MAX_OBJECTS < 0xFFFFU
 typedef uint16_t listlen_t;
#elif LIST_MAX_OBJECTS < 0xFFFFFFFFU
 typedef uint32_t listlen_t;
#elif LIST_MAX_OBJECTS < 0xFFFFFFFFFFFFFFFFU
 typedef uint64_t listlen_t;
#else
# error "LIST_MAX_OBJECTS is too big"
#endif

typedef struct list_entry_t {
	void *obj;
	struct list_entry_t *prev;
	struct list_entry_t *next;
} list_entry_t;

typedef struct {
#if ULIB_USE_STRUCT_ID
	struct_id_t id;
#endif
	// The function used to free the objects when required. May be NULL.
	void (*free_obj)(void *obj);
#if ! LISTS_USE_MALLOC
	// The function used to free the memory used by a list_entry_t when required.
	// May be NULL.
	void (*free_entry)(void *obj);
#endif
	// The function used to compare objects when required. If the search function
	// is given a different comparison function, that takes precedence. If both
	// are NULL, do a simple pointer comparison.
	// obj is the object to find, ent is the current list item being checked
	// against it.
	int (*compare)(const void *obj, const void *ent);

	// First entry in the list.
	list_entry_t *head;
	// Last entry in the list.
	list_entry_t *tail;
	// Number of entries in the list.
	listlen_t size;
} list_t;

typedef struct {
	// See list_t definition for meanings of these fields.
	void (*free_obj)(void *obj);
#if ! LISTS_USE_MALLOC
	void (*free_entry)(list_entry_t *e);
#endif
	int (*compare)(const void *l, const void *b);
} list_init_t;

// Initialize a list_t structure which is presumed to be filled with junk
// using values from a list_init_t.
// If init is NULL, use defaults.
list_t* list_init(list_t *l, const list_init_t *init);
#if LISTS_USE_MALLOC
//
// Allocate and initialize a new list_t structure using values from a
// list_init_t.
// If init is NULL, use defaults.
list_t* list_new(const list_init_t *init);
// Free a list, calling free_obj() on each object.
list_t* _list_free(list_t *l);
INLINE list_t* list_free(list_t *l) {
	if (POINTER_IS_VALID(l)) {
		return _list_free(l);
	}
	return NULL;
}
#endif
//
// Empty a list, calling free_obj() on each object and free_entry() on each
// list_entry_t. The list_t structure itself remains valid.
list_t* list_clear(list_t *l);
//
// Add an object to the end of the list.
list_t* _list_append(list_t *l, void *object, list_entry_t *emem);
//
// Add an object to the end of the list if it's not already stored.
list_t* _list_append_checked(list_t *l, void *object, int (*compare)(const void *obj, const void *ent), list_entry_t *emem);
//
// Shims for the above.
#if LISTS_USE_MALLOC
INLINE list_t* list_append(list_t *l, void *object) {
	return _list_append(l, object, NULL);
}
INLINE list_t* list_push(list_t *l, void *object) {
	return _list_append(l, object, NULL);
}
INLINE list_t* list_append_checked(list_t *l, void *object, int (*compare)(const void *obj, const void *ent)) {
	return _list_append_checked(l, object, compare, NULL);
}
#else
INLINE list_t* list_append(list_t *l, void *object, list_entry_t *emem) {
	return _list_append(l, object, emem);
}
INLINE list_t* list_push(list_t *l, void *object, list_entry_t *emem) {
	return _list_append(l, object, emem);
}
INLINE list_t* list_append_checked(list_t *l, void *object, int (*compare)(const void *obj, const void *ent), list_entry_t *emem) {
	return _list_append_checked(l, object, compare, emem);
}
#endif
//
// Remove an object from the end of the list. If ret_obj != NULL set it to
// the removed object, otherwise free the object with free_obj().
list_t* list_pop(list_t *l, void **ret_obj);
//
// Find the entry for an object, starting at entry 'start'. If 'start' is NULL,
// start from the beginning of the list. If the search reaches the end of the
// list, it doesn't wrap around.
// If compare() is NULL, use l->compare() if that's non-NULL. Otherwise check
// if the pointers are the same.
// Returns NULL if no match is found.
list_entry_t* list_find_entry(const list_t *l, list_entry_t *start, const void *object, int (*compare)(const void *obj, const void *ent));
//
// Find object in the list.
// If compare() is NULL, use l->compare() if that's non-NULL. Otherwise check
// if the pointers are the same.
// Returns NULL if no match is found.
void* list_find_object(const list_t *l, const void *object, int (*compare)(const void *obj, const void *ent));


#endif // ULIB_ENABLE_LISTS
#endif // _ULIB_LIST_H
#ifdef __cplusplus
 }
#endif
