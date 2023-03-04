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
// printf.c
// Formatted printing support
//
// NOTES:
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "printf.h"
#if ULIB_ENABLE_PRINTF

#include "debug.h"


void printf_vv(void (*pputc)(int c), const char *restrict fmt, ...) {
	va_list arp;

	va_start(arp, fmt);
	printf_va(pputc, fmt, arp);
	va_end(arp);

	return;
}

#if HAVE_XPRINTF
// xv[f]printf() is normally declared static; that needs to be changed in
// xfprintf.c
// void xvprintf (const char* fmt, va_list arp);
void xvfprintf (void(*func)(int), const char* fmt, va_list arp);

void printf_va(void (*pputc)(int c), const char *restrict fmt, va_list arp) {
	assert(pputc != NULL);
	assert(fmt   != NULL);
	assert(arp   != NULL);

#if DO_PRINTF_SAFETY_CHECKS
	if (pputc == NULL) {
		return;
	}
	if ((fmt == NULL) || (arp == NULL)) {
		return;
	}
#endif

	xvfprintf(pputc, fmt, arp);

	return;
}
#endif // HAVE_XPRINTF

#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_PRINTF
#ifdef __cplusplus
 }
#endif
