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
// cstrings.h
// Tools for dealing with C-style strings
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_CSTRINGS_H
#define _ULIB_CSTRINGS_H

#include "configify.h"
#if ULIB_ENABLE_CSTRINGS

#include "types.h"


// Check if two cstrings are the same
bool cstring_eq(const char *s1, const char *s2);
// Check if two cstrings are the same up to a given length.
bool cstring_eqn(const char *s1, const char *s2, uint_t n);
// Return a pointer to the first non-whitespace character in s.
const char* cstring_eat_whitespace(const char *s);
// Return a pointer to the first non-delim character after the first delim
// character in s - that is to say, eat one token if present then find the
// next.
// Repeating delimiters are treated as a single one.
const char* cstring_next_token(const char *cs, char delim);
// Like basename(), but accepting a const string.
// This normally returns a pointer inside s, but may return a statically-
// allocated string for ".".
// This differs from basename() in that paths ending in '/' will be returned
// as ".".
const char* cstring_basename(const char *s);

#endif // ULIB_ENABLE_CSTRINGS
#endif // _ULIB_CSTRINGS_H
#ifdef __cplusplus
 }
#endif
