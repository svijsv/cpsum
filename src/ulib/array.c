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
// array.c
// Manage arrays of pointers to objects
//
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "array.h"
#if ULIB_ENABLE_ARRAYS

#include "debug.h"
#include "util.h"

#if ARRAYS_USE_MALLOC
# include <stdlib.h>
#endif


#if ARRAY_GROW_FACTOR < 1
# error "ARRAY_GROW_FACTOR < 1"
#endif
#if (ARRAY_GROW_METHOD == ARRAY_GROW_MUL) && (ARRAY_GROW_FACTOR <= 1)
# error "(ARRAY_GROW_METHOD == ARRAY_GROW_MUL) && (ARRAY_GROW_FACTOR <= 1)"
#endif
#if (ARRAY_GROW_METHOD == ARRAY_GROW_FRAC) && ((ARRAY_INITIAL_SIZE / ARRAY_GROW_FACTOR) < 1)
# error "(ARRAY_INITIAL_SIZE / ARRAY_GROW_FACTOR) < 1"
#endif
#if ARRAY_MAX_OBJECTS < 1
# error "ARRAY_MAX_OBJECTS < 1"
#endif

#if ULIB_USE_STRUCT_ID
# define IS_ARRAY_ID(s) (s->id.value == ID_ARRAY)
#else
# define IS_ARRAY_ID(s) (true)
#endif
#if ARRAYS_USE_MALLOC
# define ASSERT_ARRAY(a) assert( \
		(POINTER_IS_VALID(a)) && \
		(IS_ARRAY_ID(a)) && \
		((a)->used <= ARRAY_MAX_OBJECTS) && \
		((a)->used <= (a)->allocated) && \
		((a)->bank != NULL) \
		)
#else
# define ASSERT_ARRAY(a) assert( \
		(POINTER_IS_VALID(a)) && \
		(IS_ARRAY_ID(a)) && \
		((a)->used <= ARRAY_MAX_OBJECTS) \
		)
#endif

array_t* array_init(array_t *a, const array_init_t *init) {
	assert(POINTER_IS_VALID(a));

#if DO_ARRAY_SAFETY_CHECKS
	if (!POINTER_IS_VALID(a)) {
		return NULL;
	}
#endif

#if ULIB_USE_STRUCT_ID
	a->id.value = ID_ARRAY;
#endif

#if ARRAYS_USE_MALLOC
	a->bank = malloc(ARRAY_INITIAL_SIZE * sizeof(*a->bank));
	a->allocated = ARRAY_INITIAL_SIZE;
#endif

	a->used = 0;
	a->free_obj = NULL;
	a->compare = NULL;

	if (init != NULL) {
		a->free_obj = init->free_obj;
		a->compare = init->compare;
	}

	ASSERT_ARRAY(a);

	return a;
}
#if ARRAYS_USE_MALLOC
array_t* array_new(const array_init_t *init) {
	array_t *a = malloc(sizeof(*a));
	return array_init(a, init);
}
array_t* _array_free(array_t *a) {
	// The inline wrapper checks for null to avoid avoid a context switch when
	// true.
	//if (POINTER_IS_VALID(a) && IS_ARRAY_ID(a)) {
	if (IS_ARRAY_ID(a)) {
		if (POINTER_IS_VALID(a->bank) && (a->allocated > 0)) {
			array_clear(a);
			free(a->bank);
		}
		free(a);
	}

	return NULL;
}
#endif
array_t* array_clear(array_t *a) {
	ASSERT_ARRAY(a);

#if DO_ARRAY_SAFETY_CHECKS
	if (!POINTER_IS_VALID(a)) {
		return NULL;
	}
#endif

	if (a->free_obj != NULL) {
		for (arlen_t i = 0; i < a->used; ++i) {
			a->free_obj(a->bank[i]);
		}
	}
	a->used = 0;

	return a;
}

array_t* array_append(array_t *a, void *object) {
	ASSERT_ARRAY(a);

#if DO_ARRAY_SAFETY_CHECKS
	if (!POINTER_IS_VALID(a)) {
		return NULL;
	}
#endif

#if ARRAYS_USE_MALLOC
	if (a->used == a->allocated) {
		arlen_t add = 0, new_size;
		void **tmp;

# if ARRAY_GROW_METHOD == ARRAY_GROW_ADD
		add = ARRAY_GROW_FACTOR;
# elif ARRAY_GROW_METHOD == ARRAY_GROW_MUL
		add = CLIP_UMUL(a->allocated, ARRAY_GROW_FACTOR-1, ARRAY_MAX_OBJECTS);
# elif ARRAY_GROW_METHOD == ARRAY_GROW_FRAC
		add = (b->allocated / BUFFER_GROW_FACTOR);
# elif ARRAY_GROW_METHOD == ARRAY_GROW_NONE
		add = 0;
# else
#  error "Unsupported ARRAY_GROW_METHOD"
# endif
		if (add == 0) {
			return a;
		}
		if ((new_size = CLIP_UADD(a->allocated, add, (arlen_t )ARRAY_MAX_OBJECTS)) == a->allocated) {
			return a;
		}
		if ((tmp = realloc(a->bank, new_size * sizeof(*a->bank))) == NULL) {
			return a;
		}
		a->allocated = new_size;
		a->bank = tmp;
	}
#else // !ARRAYS_USE_MALLOC
	if (a->used == ARRAY_MAX_OBJECTS) {
		return a;
	}
#endif

	a->bank[a->used] = object;
	++a->used;

	return a;
}
array_t* array_append_checked(array_t *a, void *object, int (*compare)(const void *obj, const void *ent)) {
	if (array_find_object(a, object, compare) != NULL) {
		return a;
	}
	return array_append(a, object);
}
array_t* array_pop(array_t *a, void **ret_obj) {
	ASSERT_ARRAY(a);

#if DO_ARRAY_SAFETY_CHECKS
	if (!POINTER_IS_VALID(a)) {
		return NULL;
	}
#endif

	if (a->used > 0) {
		--a->used;
		if (ret_obj != NULL) {
			*ret_obj = a->bank[a->used];
		} else if (a->free_obj != NULL) {
			a->free_obj(a->bank[a->used]);
		}
	}

	return a;
}

static int default_compare(const void *ent, const void *obj) {
	return !(ent == obj);
}
arlen_t array_find_index(const array_t *a, arlen_t start, const void *object, int (*compare)(const void *obj, const void *ent)) {
	int (*use_compare)(const void *obj, const void *ent);

	ASSERT_ARRAY(a);

#if DO_ARRAY_SAFETY_CHECKS
	if (!POINTER_IS_VALID(a)) {
		return (arlen_t )-1;
	}
#endif

	use_compare = (compare != NULL) ? compare : (a->compare != NULL) ? a->compare : default_compare;

	for (arlen_t i = start; i < a->used; ++i) {
		if (use_compare(object, a->bank[i]) == 0) {
			return i;
		}
	}

	return (arlen_t )-1;
}
void* array_find_object(const array_t *a, const void *object, int (*compare)(const void *obj, const void *ent)) {
	arlen_t i;

	if ((i = array_find_index(a, 0, object, compare)) != (arlen_t )-1) {
		return a->bank[i];
	}
	return NULL;
}

#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_ARRAYS
#ifdef __cplusplus
 }
#endif
