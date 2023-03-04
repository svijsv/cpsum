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
// printf.h
// Formatted printing support
//
// NOTES:
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_PRINTF_H
#define _ULIB_PRINTF_H

#include "configify.h"
#if ULIB_ENABLE_PRINTF

#include "types.h"

#include <stdarg.h>


// Print printf-formatted strings one character at a time using pputc().
// printf_vv() is comparable to printf() and printf_va() to vprintf().
void printf_vv(void (*pputc)(int c), const char *restrict fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
void printf_va(void (*pputc)(int c), const char *restrict fmt, va_list arp);

#endif // ULIB_ENABLE_PRINTF
#endif // _ULIB_PRINTF_H
#ifdef __cplusplus
 }
#endif
