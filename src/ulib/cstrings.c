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
// cstrings.c
// Tools for dealing with C-style strings
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "cstrings.h"
#if ULIB_ENABLE_CSTRINGS

#include "debug.h"

#include <string.h>


bool cstring_eq(const char *s1, const char *s2) {
	assert(s1 != NULL);
	assert(s2 != NULL);

#if DO_CSTRING_SAFETY_CHECKS
	if ((s1 == NULL) || (s2 == NULL)) {
		return false;
	}
#endif
	return (strcmp(s1, s2) == 0);
}
bool cstring_eqn(const char *s1, const char *s2, uint_t n) {
	assert(s1 != NULL);
	assert(s2 != NULL);

#if DO_CSTRING_SAFETY_CHECKS
	if ((s1 == NULL) || (s2 == NULL)) {
		return false;
	}
#endif
	return (strncmp(s1, s2, n) == 0);
}
const char* cstring_eat_whitespace(const char *s) {
	assert(s != NULL);

#if DO_CSTRING_SAFETY_CHECKS
	if (s == NULL) {
		return NULL;
	}
#endif

	for (;;) {
		switch (*s) {
			case '\t':
			case '\r':
			case '\n':
			case ' ':
				++s;
				break;
			default:
				return (char *)s;
		}
	}

	return (char *)s;
}
const char* cstring_next_token(const char *cs, char delim) {
	assert(cs != NULL);
	assert(delim != 0);

#if DO_CSTRING_SAFETY_CHECKS
	if (cs == NULL) {
		return NULL;
	}
#endif

	// Eat current token
	for (; ((*cs != delim) && (*cs != 0)); ++cs) {
		// Nothing to do in here
	}
	// Eat delimiters
	for (; (*cs == delim); ++cs) {
		// Nothing to do in here
	}

	return cs;
}
const char* cstring_basename(const char *s) {
	const char *bn;
	static const char *dot = ".";

	// basename() accepts null pointers, and we're trying to be like basename().
	/*
	assert(s != NULL);

#if DO_CSTRING_SAFETY_CHECKS
	if (s == NULL) {
		return dot;
	}
#endif
	*/

	if ((s == NULL) || (s[0] == 0)) {
		return dot;
	}

	bn = strrchr(s, '/');
	if (bn == NULL) {
		bn = s;
	} else {
		++bn;
	}
	if (bn[0] == 0) {
		bn = dot;
	}

	return bn;
}

#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_CSTRINGS
#ifdef __cplusplus
 }
#endif
