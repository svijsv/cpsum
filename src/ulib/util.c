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
// util.c
// Utility functions
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "util.h"
#if ULIB_ENABLE_UTIL

#include "debug.h"

#include <string.h>

void mem_init(void *mem, uint8_t value, uint32_t size) {
#if DO_UTIL_SAFETY_CHECKS
	if (mem == NULL) {
		return;
	}
#endif

	memset(mem, value, size);
	return;
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_UTIL
#ifdef __cplusplus
 }
#endif
