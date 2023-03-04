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
// strings.c
// Static or dynamic strings
// NOTES:
//   Integer overflows are a real possibility here when strlen_t is 8 bits,
//   so they need to be checked for ALWAYS.
//
//   Iterations should be performed in such a way that reaching STRING_MAX_BYTES
//   won't cause problems when it's the max size of strlen_t.
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "strings.h"
#if ULIB_ENABLE_STRINGS

#include "cstrings.h"
#include "debug.h"
#include "printf.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>


#if ! HAVE_PRINTF_VA
# include <stdio.h>
#endif

// Determine the combined length of two strings taking STRING_MAX_BYTES into account
//#define COMBINED_LENGTH(a, b) (((STRING_MAX_BYTES - (a)) > (b)) ? STRING_MAX_BYTES : ((a) + (b)))
//#define COMBINED_LENGTH(a, b) CLIP_UADD(a, b, STRING_MAX_BYTES)
INLINE strlen_t COMBINED_LENGTH(strlen_t a, strlen_t b) {
	return CLIP_UADD(a, b, (strlen_t )STRING_MAX_BYTES);
}

// Assertions for checking input parameters
#if ULIB_USE_STRUCT_ID
# define IS_STRING_ID(s) (s->id.value == ID_STRING)
#else
# define IS_STRING_ID(s) (true)
#endif
#if STRINGS_USE_MALLOC
# define ASSERT_STRING(s) assert( \
		((s) != NULL) && \
		(IS_STRING_ID(s)) && \
		((s)->length <= STRING_MAX_BYTES) && \
		((s)->length < s->allocated) && \
		((s)->cstring != NULL) && \
		((s)->cstring[(s)->length] == 0) \
		)
#else
# define ASSERT_STRING(s) assert( \
		((s) != NULL) && \
		(IS_STRING_ID(s)) && \
		((s)->length <= STRING_MAX_BYTES) && \
		((s)->cstring[(s)->length] == 0) \
		)
#endif
#define ASSERT_CSTRING(cs) assert(POINTER_IS_VALID(cs))
#define ASSERT_CHAR(c) assert((c) != 0)
// strlen_t is set to unsigned always, so it's guaranteed to be >= 0.
//#define ASSERT_LENGTH(l) assert((l) >= 0)
#define ASSERT_LENGTH(l) assert(true)
#define ASSERT_ARP(a) assert(POINTER_IS_VALID(a))

// A pointer set by string_appendf_va and used by the non-reentrant string_putc()
// function so that it can have the same signature as putc().
#if HAVE_PRINTF_VA
static string_t *S_printf_string;
#endif

// Make sure the value returned by strlen() is <= STRING_MAX_BYTES
INLINE strlen_t strlen_checked(const char *c) {
	size_t n = strlen(c);
	return (strlen_t )MIN(n, STRING_MAX_BYTES);
}


/*
* Initialization functions
*/
string_t* string_init(string_t *s) {
	assert(s != NULL);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
#endif

#if ULIB_USE_STRUCT_ID
	s->id.value = ID_STRING;
#endif
#if STRINGS_USE_MALLOC
	s->allocated = STRING_ALLOC_BLOCK_BYTES;
	s->cstring = malloc(s->allocated);
#endif
	s->cstring[0] = 0;
	s->length = 0;

	return s;
}
string_t* string_clear(string_t *s) {
	ASSERT_STRING(s);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
# if STRINGS_USE_MALLOC
	if (s->cstring == NULL) {
		// We can't trust any of the other data (like s->allocated) in the
		// struct if cstring is NULL, since that's set in string_init().
		return string_init(s);
	}
# endif
#endif

	s->length = 0;
	s->cstring[0] = 0;

	return s;
}
#if STRINGS_USE_MALLOC
string_t* string_new() {
	string_t *s = malloc(sizeof(*s));

	return string_init(s);
}
string_t* string_new_from_string(const string_t *s) {
	string_t *d;

	ASSERT_STRING(s);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return string_new();
	}
#endif

	d = malloc(sizeof(*d));
	//d->allocated = SNAP_TO_NEXT_FACTOR(s->length+1, STRING_ALLOC_BLOCK_BYTES);
	d->allocated = s->length+1;
	d->length = s->length;
	d->cstring = malloc(d->allocated);
	memcpy(d->cstring, s->cstring, s->length);
	d->cstring[s->length] = 0;

	return d;
}
string_t* string_new_from_cstring(const char *c, strlen_t len) {
	string_t *s;

	ASSERT_CSTRING(c);
	ASSERT_LENGTH(len);

#if DO_STRING_SAFETY_CHECKS
	if (c == NULL) {
		return string_new();
	}
#endif

	if (len == 0) {
		len = strlen_checked(c);
	}
	if (len == 0) {
		return string_new();
	}

	s = malloc(sizeof(*s));
	//s->allocated = SNAP_TO_NEXT_FACTOR(len+1, STRING_ALLOC_BLOCK_BYTES);
	s->allocated = len+1;
	s->length = len;
	s->cstring = malloc(s->allocated);
	memcpy(s->cstring, c, len);
	s->cstring[len] = 0;

	return s;
}
#else
/*
string_t* string_new() {
	return NULL;
}
string_t* string_new_from_string(const string_t *s) {
	UNUSED(s);

	return NULL;
}
string_t* string_new_from_cstring(const char *c, strlen_t len) {
	UNUSED(c);
	UNUSED(len);

	return NULL;
}
*/
#endif // STRINGS_USE_MALLOC


/*
* Cleanup functions
*/
#if STRINGS_USE_MALLOC
string_t* _string_free(string_t *s) {
	// The inline wrapper checks for null to avoid avoid a context switch when
	// true.
	//if (POINTER_IS_VALID(s) && IS_STRING_ID(s)) {
	if (IS_STRING_ID(s)) {
		if (POINTER_IS_VALID(s->cstring) && (s->allocated > 0)) {
			free(s->cstring);
		}
		free(s);
	}

	return NULL;
}
void string_free_void(void *ptr) {
	string_free(ptr);
	return;
}
#endif // STRINGS_USE_MALLOC


/*
* Setting functions
*/
string_t* string_set_from_string(string_t *restrict s, const string_t *restrict src) {
	ASSERT_STRING(src);

	return string_append_from_cstring(string_clear(s), src->cstring, src->length);
}
string_t* string_set_from_char(string_t *s, char c) {
	ASSERT_STRING(s);
	ASSERT_CHAR(c);

	s->length = 1;
	s->cstring[0] = c;
	s->cstring[1] = 0;

	return s;
}
string_t* string_set_from_cstring(string_t *restrict s, const char *restrict c, strlen_t len) {
	return string_append_from_cstring(string_clear(s), c, len);
}
string_t* string_printf(string_t *restrict s, const char *restrict format, ...) {
	va_list arp;

	va_start(arp, format);
	string_appendf_va(string_clear(s), format, arp);
	va_end(arp);

	return s;
}

/*
* Appending functions
*/
// Helper function to grow a string correctly.
static void grow_allocated(string_t *s, strlen_t n) {
	//ASSERT_STRING(s);
	//assert(n > 0);

	UNUSED(s);
	UNUSED(n);

#if STRINGS_USE_MALLOC
	if (COMBINED_LENGTH(s->length, n) >= s->allocated) {
		strlen_t new_size, add = STRING_ALLOC_BLOCK_BYTES;
		char *tmp;

		//add = STRING_ALLOC_BLOCK_BYTES * (1 + (n / STRING_ALLOC_BLOCK_BYTES));
		while (add < n) {
			add += STRING_ALLOC_BLOCK_BYTES;
		}

		new_size = COMBINED_LENGTH(s->allocated, add);
		//new_size = SNAP_TO_FACTOR(new_size, STRING_ALLOC_BLOCK_BYTES);
		//new_size = MIN(new_size, STRING_MAX_BYTES);
		if (new_size > s->allocated) {
			tmp = realloc(s->cstring, new_size * sizeof(*s->cstring));
			if (tmp != NULL) {
				s->allocated = new_size;
				s->cstring = tmp;
			}
		}
	}
#endif

	return;
}
string_t* string_append_from_char(string_t *s, char c) {
	ASSERT_STRING(s);
	ASSERT_CHAR(c);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == 0) {
		return s;
	}
#endif

	if (s->length != STRING_MAX_BYTES) {
		grow_allocated(s, 1);

		s->cstring[s->length] = c;
		++s->length;
		s->cstring[s->length] = 0;
	}

	return s;
}
string_t* string_append_from_cstring(string_t *restrict s, const char *restrict c, strlen_t len) {
	ASSERT_STRING(s);
	ASSERT_CSTRING(c);
	ASSERT_LENGTH(len);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == NULL) {
		return s;
	}
#endif

	if ((s->length != STRING_MAX_BYTES) && (c[0] != 0)) {
		if (len == 0) {
			len = strlen_checked(c);
		}
		len = (strlen_t )(COMBINED_LENGTH(s->length, len) - s->length);
		grow_allocated(s, len);

#if DO_STRING_SAFETY_CHECKS
		strlen_t i, j;

		for (i = 0, j = s->length; i < len; ++i, ++j) {
			if UNLIKELY((c[i] == 0)) {
				len = i;
				break;
			} else {
				s->cstring[j] = c[i];
			}
		}
#else
		memcpy(&s->cstring[s->length], c, len);
#endif
		s->length += len;
		s->cstring[s->length] = 0;
	}

	return s;
}
string_t* string_append_from_string(string_t *restrict s, const string_t *restrict src) {
	ASSERT_STRING(src);

	return string_append_from_cstring(s, src->cstring, src->length);
}
string_t* string_appendf(string_t *restrict s, const char *restrict format, ...) {
	va_list arp;

	va_start(arp, format);
	string_appendf_va(s, format, arp);
	va_end(arp);

	return s;
}
#if HAVE_PRINTF_VA
static void string_putc(int c) {
	//assert(S_printf_string != NULL);

	string_append_from_char(S_printf_string, (char )c);

	return;
}
string_t* string_appendf_va(string_t *restrict s, const char *restrict format, va_list arp) {
	string_t *bs;

	ASSERT_STRING(s);
	ASSERT_CSTRING(format);
	ASSERT_ARP(arp);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (format == NULL) {
		return s;
	}
#endif

	bs = S_printf_string;
	S_printf_string = s;
	printf_va(string_putc, format, arp);
	S_printf_string = bs;

	return s;
}
#else // !HAVE_PRINTF_VA
string_t* string_appendf_va(string_t *restrict s, const char *restrict format, va_list arp) {
	strlen_t len;
	strlen_t free_space;

	ASSERT_STRING(s);
	ASSERT_CSTRING(format);
	ASSERT_ARP(arp);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (format == NULL) {
		return s;
	}
	if (arp == NULL) {
		return s;
	}
#endif

#if STRINGS_USE_MALLOC
	free_space = s->allocated - s->length;
	if ((len = (strlen_t )vsnprintf(&s->cstring[s->length], free_space, format, arp)) > free_space) {
		grow_allocated(s, len - free_space);

		free_space = s->allocated - s->length;
		len = (strlen_t )vsnprintf(&s->cstring[s->length], free_space, format, arp);
	}
	s->length = MIN(len, s->allocated)-1;

#else
	free_space = (STRING_MAX_BYTES+1) - s->length;
	len = (strlen_t )(vsnprintf(&s->cstring[s->length], free_space, format, arp) - 1);
	s->length = MIN(len, STRING_MAX_BYTES);
#endif

	return s;
}
#endif // HAVE_PRINTF_VA

string_t* string_append_from_int(string_t *s, int n, uint8_t width, char pad) {
	int m, r;

	assert((pad != 0) || (width == 0));
	ASSERT_STRING(s);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (pad == 0) {
		pad = '0';
	}
#endif

	if (n < 0) {
		string_append_from_char(s, '-');
		n = -n;
	}

	// FIXME: Handle n == INT_MAX
	// Find the maximum number of needed characters
	for (m = 1, r = 0; ((n / m) != 0); m *= 10, ++r) {
		// Nothing to do in here
	}
	if (r == 0) {
		if (width > 0) {
			--width;
			for (; r < width; ++r) {
				string_append_from_char(s, pad);
			}
		}
		return string_append_from_char(s, '0');
	}

	for (; width > r; ++r) {
		string_append_from_char(s, pad);
	}
	// Without this first m /= 10 we'd have a leading 0.
	for (m /= 10; m > 0; m /= 10) {
		string_append_from_char(s, (char )('0' + ((n/m) % 10)));
	}

	return s;
}
string_t* string_append_from_int_div(string_t *s, int n, int d) {
	ASSERT_STRING(s);
	assert(d != 0);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (d == 0) {
		d = 1;
	}
#endif

	string_append_from_int(s, (n/d), 0, 0);
	string_append_from_char(s, '.');
	if (n < 0) {
		n = -n;
	}
	if (d < 0) {
		d = -d;
	}
	string_append_from_int(s, (n%d), 0, 0);

	return s;
}


/*
* Content test functions
*/
bool string_is_empty(const string_t *s) {
	if (s == NULL) {
		return true;
	}

	ASSERT_STRING(s);

	return (s->length == 0);
}
bool string_eq_string(const string_t *l, const string_t *r) {
	ASSERT_STRING(l);
	ASSERT_STRING(r);

#if DO_STRING_SAFETY_CHECKS
	if ((l == NULL) || (r == NULL)) {
		return false;
	}
#endif

	if (l->length == r->length) {
		return (strcmp(l->cstring, r->cstring) == 0);
	}
	return false;
}
bool string_eq_cstring(const string_t *l, const char *r) {
	ASSERT_STRING(l);
	ASSERT_CSTRING(r);

#if DO_STRING_SAFETY_CHECKS
	if ((l == NULL) || (r == NULL)) {
		return false;
	}
#endif

	return (strcmp(l->cstring, r) == 0);
}


/*
* File path functions
*/
// FIXME: Make sure the pushed name doesn't contain more than one meaningful
//        path separator.
string_t* string_push_path_from_cstring(string_t *restrict s, const char *restrict c, strlen_t len) {
	ASSERT_STRING(s);
	ASSERT_CSTRING(c);
	ASSERT_LENGTH(len);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == NULL) {
		return s;
	}
#endif

	if (s->length > 0) {
		return string_append_from_cstring(string_prove_trailing(s, '/'), c, len);
	} else {
		return string_set_from_cstring(s, c, len);
	}
}
string_t* string_pop_path(string_t *s) {
	return string_dirname(s, '/');
}
string_t* string_dirname(string_t *s, char sep) {
	strlen_t i;

	ASSERT_STRING(s);
	ASSERT_CHAR(sep);

#if DO_STRING_SAFETY_CHECKS
	if (sep == 0) {
		sep = '/';
	}
	if (s == NULL) {
		return NULL;
	}
#endif

	if (s->length == 0) {
		return string_set_from_char(s, '.');
	}

	for (i = s->length - 1; ((i > 0) && (s->cstring[i] == sep)); --i) {
		// Nothing to do here
	};
	for (; i > 0; --i) {
		if (s->cstring[i] == sep) {
			for (; s->cstring[i] == sep; --i) {
				// Nothing to do here
			};
			++i;
			s->cstring[i] = 0;
			s->length = i;
			return s;
		}
	}
	if ((i == 0) && (s->cstring[0] == sep)) {
		s->cstring[1] = 0;
		s->length = 1;
	} else {
		s->cstring[0] = '.';
		s->cstring[1] = 0;
		s->length = 1;
	}

	return s;
}
string_t* string_basename(string_t *s, char sep) {
	strlen_t i, start, end;

	ASSERT_STRING(s);
	ASSERT_CHAR(sep);

#if DO_STRING_SAFETY_CHECKS
	if (sep == 0) {
		return s;
	}
	if (s == NULL) {
		return NULL;
	}
#endif

	if (s->length == 0) {
		return string_set_from_char(s, '.');
	}

	for (i = s->length-1; ((i > 0) && (s->cstring[i] == sep)); --i) {
		// Nothing to do here
	}
	// This means the string was just '/' or '////' or something:
	if ((i == 0) && (s->cstring[0] == sep)) {
		s->cstring[1] = 0;
		s->length = 1;
		return s;
	}
	end = i+1;

	start = 0;
	for (i = 0; i < end; ++i) {
		if (s->cstring[i] == sep) {
			start = i+1;
		}
	}
	s->length = end - start;
	if (start > 0) {
		strlen_t j;

		for (i = 0, j = start; i < s->length; ++i, ++j) {
			s->cstring[i] = s->cstring[j];
		}
	}
	s->cstring[s->length] = 0;

	return s;
}


/*
* String modifying functions
*/
string_t* string_truncate(string_t *s, const strlen_t l) {
	ASSERT_STRING(s);
	ASSERT_LENGTH(l);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
#endif

	if ((s->length > l) && (l <= STRING_MAX_BYTES)) {
		s->length = l;
		s->cstring[l] = 0;
	}

	return s;
}
string_t* string_trim_char(string_t *s, char c) {
	ASSERT_STRING(s);
	ASSERT_CHAR(c);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
#endif

	string_strip_trailing(s, c);
	string_strip_leading(s, c);

	return s;
}
string_t* string_strip_trailing(string_t *s, char c) {
	strlen_t i;

	ASSERT_STRING(s);
	ASSERT_CHAR(c);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == 0) {
		return s;
	}
#endif

	if (s->length == 0) {
		return s;
	}
	if (s->cstring[s->length-1] != c) {
		return s;
	}

	for (i = s->length-1; ((s->cstring[i] == c) && (i != 0)); --i) {
		// Nothing to do here
	};
	if ((i == 0) && (s->cstring[0] == c)) {
		s->length = 0;
		s->cstring[0] = 0;
	} else {
		s->length = i+1;
		s->cstring[i+1] = 0;
	}

	return s;
}
string_t* string_strip_leading(string_t *s, char c) {
	strlen_t i, j;

	ASSERT_STRING(s);
	ASSERT_CHAR(c);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == 0) {
		return s;
	}
#endif

	if (s->length == 0) {
		return s;
	}
	if (s->cstring[0] != c) {
		return s;
	}

	for (i = 0; s->cstring[i] == c; ++i) {
		// Nothing to do here
	};
	if (i == 0) {
		return s;
	}
	for (j = 0; i < s->length; ++i, ++j) {
		s->cstring[j] = s->cstring[i];
	}
	s->length = j;
	s->cstring[j] = 0;

	return s;
}
string_t* string_prove_trailing(string_t *s, char c) {
	ASSERT_STRING(s);
	ASSERT_CHAR(c);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == 0) {
		return s;
	}
#endif

	if (s->length == 0) {
		return string_set_from_char(s, c);
	}

	if (s->cstring[s->length-1] != c) {
		return string_append_from_char(s, c);
	}

	return s;
}
string_t* string_pad_from_char(string_t *s, char c, strlen_t len) {
	ASSERT_STRING(s);
	ASSERT_CHAR(c);
	ASSERT_LENGTH(len);

#if DO_STRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
	if (c == 0) {
		return s;
	}
#endif

	len = MIN(len, STRING_MAX_BYTES);
	for (strlen_t i = s->length; i < len; ++i) {
		string_append_from_char(s, c);
	}

	return s;
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_STRINGS
#ifdef __cplusplus
 }
#endif
