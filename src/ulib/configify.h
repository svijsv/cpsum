// SPDX-License-Identifier: GPL-3.0-only
/***********************************************************************
*                                                                      *
*                                                                      *
* Copyright 2023 svijsv                                                *
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
// configify.h
// Read and verify the user configuration.
//
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_CONFIGIFY_H
#define _ULIB_CONFIGIFY_H

#include "ulibconfig.h"

#if ULIB_ENABLE_GETOPT
# if !ULIB_ENABLE_CSTRINGS
#  undef ULIB_ENABLE_CSTRINGS
#  define ULIB_ENABLE_CSTRINGS 1
#  pragma message "Enabling CSTRINGS module for GETOPT module."
# endif
# if !ULIB_ENABLE_MSG
#  undef ULIB_ENABLE_MSG
#  define ULIB_ENABLE_MSG 1
#  pragma message "Enabling MSG module for GETOPT module."
# endif
#endif

#if ULIB_ENABLE_MSG
# if !ULIB_ENABLE_CSTRINGS
#  undef ULIB_ENABLE_CSTRINGS
#  define ULIB_ENABLE_CSTRINGS 1
#  pragma message "Enabling CSTRINGS module for MSG module."
# endif
# if !ULIB_ENABLE_BUFFERS
#  undef ULIB_ENABLE_BUFFERS
#  define ULIB_ENABLE_BUFFERS 1
#  pragma message "Enabling BUFFERS module for MSG module."
# endif
#endif

#if ULIB_ENABLE_FILES
# if !ULIB_ENABLE_MATH
#  undef ULIB_ENABLE_MATH
#  define ULIB_ENABLE_MATH 1
#  pragma message "Enabling MATH module for FILES module."
# endif
#endif

#if HAVE_XPRINTF && ULIB_ENABLE_PRINTF
# define HAVE_PRINTF_VA 1
#else
# define HAVE_PRINTF_VA 0
#endif

#endif // _ULIB_CONFIGIFY_H
#ifdef __cplusplus
 }
#endif
