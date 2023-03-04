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
// debug.h
// Tools to aid in debugging
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_DEBUG_H
#define _ULIB_DEBUG_H

#include "configify.h"
#include "fmem.h"
#include "msg.h"
#include "types.h"

#if !ULIB_ENABLE_FMEM
# define F(s) (s)
# define F1(s) (s)
#endif

#if USE_ULIB_ASSERT
# ifndef NDEBUG
// Function called when an assertion fails
// _assert_failed() is project-specific and must be defined somewhere if
// NDEBUG is undefined and USE_ULIB_ASSERT is set.
void _assert_failed(const char *file_path, uint32_t lineno, const char *func_name, const char *expr);

//# define assert(exp) ((exp) ? (void)0 : _assert_failed(__FILE__, __LINE__, __func__, #exp))
// Using F() with only #exp saves more RAM and uses less flash than using it
// only with __FILE__, presumably because the multiple uses of each file name
// are deduplicated in RAM but not flash
#  define assert(exp) ((exp) ? (void)0 : _assert_failed(F1(__FILE__), __LINE__, __func__, F(#exp)))
# else
#  define assert(exp) ((void)0)
# endif
#else
# include <assert.h>
#endif

#define PRINT_HERE() msg_debug("-HERE- %s() %s:%d", __func__, F1(__FILE__), __LINE__)

#endif // _ULIB_DEBUG_H
#ifdef __cplusplus
 }
#endif
