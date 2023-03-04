// SPDX-License-Identifier: GPL-3.0-only
/***********************************************************************
*                                                                      *
*                                                                      *
* Copyright 2021, 2023 svijsv                                          *
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
// types.h
// Common type definitions
// NOTES:
//    Macros are used in place of enums in some cases because enums are
//    int-sized and the macros may be smaller on some systems.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_TYPES_H
#define _ULIB_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

typedef signed   int  int_t;
typedef unsigned int uint_t;

// This needs to be a struct rather than a plain int to avoid breaking strict
// aliasing: https://blog.regehr.org/archives/1307
typedef enum {
	ID_ARRAY  = 1,
	ID_BUFFER = 2,
	ID_STRING = 3,
	ID_LIST   = 4,
} struct_id_value_t;
typedef struct {
	struct_id_value_t value;
} struct_id_t;

// Types used for generic iterators
typedef int_fast8_t   iter_t;
typedef uint_fast8_t uiter_t;


#endif // _LIB_TYPES_H
#ifdef __cplusplus
 }
#endif
