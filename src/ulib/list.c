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
// list.c
// Manage lists of pointers to objects
//
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "list.h"
#if ULIB_ENABLE_LISTS

#include "debug.h"
#include "util.h"

#if LISTS_USE_MALLOC
# include <stdlib.h>
#endif
// For memset()
#include "string.h"


#if ULIB_USE_STRUCT_ID
# define IS_LIST_ID(s) (s->id.value == ID_LIST)
#else
# define IS_LIST_ID(s) (true)
#endif

#define ASSERT_LIST(l) assert( \
		(POINTER_IS_VALID(l)) && \
		(IS_LIST_ID(l)) && \
		((l)->size <= LIST_MAX_OBJECTS) \
		)

list_t* list_init(list_t *l, const list_init_t *init) {
	assert(POINTER_IS_VALID(l));

#if DO_LIST_SAFETY_CHECKS
	if (!POINTER_IS_VALID(l)) {
		return NULL;
	}
#endif

	memset(l, 0, sizeof(*l));

#if ULIB_USE_STRUCT_ID
	l->id.value = ID_LIST;
#endif
	if (init != NULL) {
		l->free_obj = init->free_obj;
#if !LISTS_USE_MALLOC
		l->free_entry = init->free_entry;
#endif
		l->compare = init->compare;
	}

	ASSERT_LIST(l);

	return l;
}
#if LISTS_USE_MALLOC
list_t* list_new(const list_init_t *init) {
	list_t *l = malloc(sizeof(*l));
	return list_init(l, init);
}
list_t* _list_free(list_t *l) {
	// The inline wrapper checks for null to avoid avoid a function call.
	//if (POINTER_IS_VALID(l) && IS_LIST_ID(l)) {
	if (IS_LIST_ID(l)) {
		list_clear(l);
		free(l);
	}

	return NULL;
}
#endif
list_t* list_clear(list_t *l) {
	ASSERT_LIST(l);

#if DO_LIST_SAFETY_CHECKS
	if (!POINTER_IS_VALID(l)) {
		return NULL;
	}
#endif

	for (list_entry_t *e = l->head; e != NULL;) {
		list_entry_t *t = e;
		e = e->next;

		if (l->free_obj != NULL) {
			l->free_obj(t->obj);
		}
#if LISTS_USE_MALLOC
		free(t);
#else
		if (l->free_entry != NULL) {
			l->free_entry(t);
		}
#endif
	}
	l->head = NULL;
	l->tail = NULL;
	l->size = 0;

	return l;
}

list_t* _list_append(list_t *l, void *object, list_entry_t *emem) {
	list_entry_t *e;

	ASSERT_LIST(l);

#if DO_LIST_SAFETY_CHECKS
	if (!POINTER_IS_VALID(l)) {
		return NULL;
	}
#endif

	if (l->size == LIST_MAX_OBJECTS) {
		return l;
	}

#if LISTS_USE_MALLOC
	UNUSED(emem);
	e = malloc(sizeof(*e));
#else
	assert(POINTER_IS_VALID(emem));
	e = emem;
#endif

	memset(e, 0, sizeof(*e));
	e->obj = object;
	e->prev = l->tail;
	//e->next = NULL;
	if (l->tail != NULL) {
		l->tail->next = e;
	}
	l->tail = e;
	if (l->head == NULL) {
		l->head = e;
	}
	++l->size;

	return l;
}
list_t* _list_append_checked(list_t *l, void *object, int (*compare)(const void *obj, const void *ent), list_entry_t *emem) {
	if (list_find_object(l, object, compare) != NULL) {
		return l;
	}
	return _list_append(l, object, emem);
}

list_t* list_pop(list_t *l, void **ret_obj) {
	ASSERT_LIST(l);

#if DO_LIST_SAFETY_CHECKS
	if (!POINTER_IS_VALID(l)) {
		return NULL;
	}
#endif

	if (l->tail != NULL) {
		list_entry_t *t = l->tail;

		if (l->head == t) {
			l->head = NULL;
		}
		if (t->prev != NULL) {
			t->prev->next = NULL;
		}
		l->tail = t->prev;
		--l->size;

		if (ret_obj != NULL) {
			*ret_obj = t->obj;
		} else if (l->free_obj != NULL) {
			l->free_obj(t->obj);
		}
#if LISTS_USE_MALLOC
		free(t);
#else
		if (l->free_entry != NULL) {
			l->free_entry(t);
		}
#endif
	}

	return l;
}

static int default_compare(const void *ent, const void *obj) {
	return !(ent == obj);
}
list_entry_t* list_find_entry(const list_t *l, list_entry_t *start, const void *object, int (*compare)(const void *obj, const void *ent)) {
	int (*use_compare)(const void *obj, const void *ent);

	ASSERT_LIST(l);

#if DO_LIST_SAFETY_CHECKS
	if (!POINTER_IS_VALID(l)) {
		return NULL;
	}
#endif

	use_compare = (compare != NULL) ? compare : (l->compare != NULL) ? l->compare : default_compare;

	if (start == NULL) {
		start = l->head;
	}
	for (list_entry_t *e = start; e != NULL; e = e->next) {
		if (use_compare(object, e->obj) == 0) {
			return e;
		}
	}

	return NULL;
}
void* list_find_object(const list_t *l, const void *object, int (*compare)(const void *obj, const void *ent)) {
	list_entry_t *e;

	if ((e = list_find_entry(l, l->head, object, compare)) != NULL) {
		return e->obj;
	}
	return NULL;
}

#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_LISTS
#ifdef __cplusplus
 }
#endif
