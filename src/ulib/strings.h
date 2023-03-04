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
// strings.h
// Static or dynamic strings
// NOTES:
//   Unless otherwise noted, functions returning string_t* return the same
//   object passed to them.
//
//   When a function would overflow a static string or allocation of additional
//   space fails, the string will be truncated silently.
//
//   There is no UTF8 support. The functionality is basic enough that that
//   shouldn't matter.
//
//   strlen_t should be unsigned because that's the assumption made during
//   coding. It would probably work as signed most of the time, but there are
//   no guarantees.
//
//   *_printf()/_appendf() functions aren't thread safe when HAVE_PRINTF_VA
//   is set.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_STRINGS_H
#define _ULIB_STRINGS_H

#include "configify.h"
#if ULIB_ENABLE_STRINGS

#include "types.h"
#include "util.h"


#include <stdarg.h>

#if STRING_MAX_BYTES < 0xFFU
typedef uint8_t strlen_t;
#elif STRING_MAX_BYTES < 0xFFFFU
typedef uint16_t strlen_t;
#elif STRING_MAX_BYTES < 0xFFFFFFFFU
typedef uint32_t strlen_t;
#elif STRING_MAX_BYTES < 0xFFFFFFFFFFFFFFFFU
typedef uint64_t strlen_t;
#else
# error "STRING_MAX_BYTES is too big"
#endif

typedef struct {
#if ULIB_USE_STRUCT_ID
	struct_id_t id;
#endif
	strlen_t length;
#if STRINGS_USE_MALLOC
	strlen_t allocated;
	char *restrict cstring;
#else
	char cstring[STRING_MAX_BYTES+1];
#endif
} string_t;


/*
* Initialization functions
*/
// Initialize a new string. All fields are assumed to contain junk so no
// memory is free()d and new memory is allocated for contents if STRINGS_USE_MALLOC
// is set.
string_t* string_init(string_t *s);
//
// Clear an existing string
string_t* string_clear(string_t *s);
//
// Allocate and initialize a new string_t structure
#if STRINGS_USE_MALLOC
string_t* string_new(void);
string_t* string_new_from_string(const string_t *s);
string_t* string_new_from_cstring(const char *c, strlen_t len);
#endif // STRINGS_USE_MALLOC


/*
* Cleanup functions
*/
// Free a string_t structure. s can be NULL.
#if STRINGS_USE_MALLOC
string_t* _string_free(string_t *s);
INLINE string_t* string_free(string_t *s) {
	if (POINTER_IS_VALID(s)) {
		return _string_free(s);
	}
	return NULL;
}
// Same as string_free(), but with a signature matching free().
void string_free_void(void *ptr);
#endif


/*
* Setting functions
* Setting functions will copy in as much as will fit, and truncate the
* string without notice if they have to.
*/
string_t* string_set_from_char(string_t *s, char c);
string_t* string_set_from_cstring(string_t *restrict s, const char *restrict c, strlen_t len);
string_t* string_set_from_string(string_t *restrict s, const string_t *restrict src);
string_t* string_printf(string_t *restrict s, const char *restrict format, ...)
	__attribute__ ((format(printf, 2, 3)));


/*
* Appending functions
* Appending functions will copy in as much as will fit, and truncate the
* string without notice if they have to.
*/
string_t* string_append_from_char(string_t *s, char c);
string_t* string_append_from_cstring(string_t *restrict s, const char *restrict c, strlen_t len);
string_t* string_append_from_string(string_t *restrict s, const string_t *restrict src);
//
// Append to a string with vsprintf()- or sprintf()-like format strings.
string_t* string_appendf_va(string_t *restrict s, const char *restrict format, va_list arp);
string_t* string_appendf(string_t *restrict s, const char *restrict format, ...)
	__attribute__ ((format(printf, 2, 3)));
//
// n is the number to append
// width is the minimum width to allow excluding '-', 0 to disable
// pad is the char to pad to width with
string_t* string_append_from_int(string_t *s, int n, uint8_t width, char pad);
//
// n is the number to append
// d is the number to divide n by; the remainder is printed after a decimal point
// No fancy padding with this one.
string_t* string_append_from_int_div(string_t *s, int n, int d);
//
// Append c to string until it's size characters long
string_t* string_pad_from_char(string_t *s, char c, strlen_t size);


/*
* Content test functions
*/
// Check whether a string is empty
// Returns true if s->length == 0 or s == NULL
bool string_is_empty(const string_t *s);
//
// Check whether a string is the same a cstring
bool string_eq_cstring(const string_t *l, const char *r);
//
// Check whether a string is the same another string
bool string_eq_string(const string_t *l, const string_t *r);


/*
* File path functions
*/
// Strip a string's basename, leaving just the directory.
// It should be considered a bug where this differs from the behavior of
// dirname().
string_t* string_dirname(string_t *s, char sep);
//
// Strip a string's directory, leaving just the basename.
// sep is the path separator.
// It should be considered a bug where this differs from the behavior of
// basename().
string_t* string_basename(string_t *s, char sep);
//
// Push a path element into the string
string_t* string_push_path_from_cstring(string_t *restrict s, const char *restrict c, strlen_t len);
//
// Pop a path element from the string
string_t* string_pop_path(string_t *s);


/*
* String modifying functions
*/
// Add c to the end of a string if it doesn't already end in it
// Does nothing if the string can't get any bigger
string_t* string_prove_trailing(string_t *s, char c);
//
// Remove all leading and trailing instances of c from string
string_t* string_trim_char(string_t *s, char c);
//
// Remove all trailing instances of c from string
string_t* string_strip_trailing(string_t *s, char c);
//
// Remove all leading instances of c from string
string_t* string_strip_leading(string_t *s, char c);
//
// Truncate a string to l characters
string_t* string_truncate(string_t *s, const strlen_t l);

#endif // ULIB_ENABLE_STRINGS
#endif // _ULIB_STRINGS_H
#ifdef __cplusplus
 }
#endif
