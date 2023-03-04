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
// fmem.c
// Helpers for working with data in a separate address space
// NOTES:
//    These functions are only used for MCUs with separate flash and RAM
//    address spaces
//
//    Hopefully your compiler is smart enough to remove any unused FROM_FSTR()
//    variants
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "fmem.h"
#if ULIB_ENABLE_FMEM

#include "debug.h"

#if HAVE_FMEM_NAMESPACE

#define FS_NULL (FMEM_STR_T *)0U
#define ASSERT_FS(fs) ((fs) != FS_NULL)
#define ASSERT_BUF(b) ((b) != NULL)

# if FMEM_STR_BYTES <= 0xFFU
typedef uint8_t fsi_t;
# elif FMEM_STR_BYTES <= 0xFFFFU
typedef uint16_t fsi_t;
# elif FMEM_STR_BYTES <= 0xFFFFFFFFU
typedef uint32_t fsi_t;
# elif FMEM_STR_BYTES <= 0xFFFFFFFFFFFFFFFFU
typedef uint64_t fsi_t;
# else
#  error "FMEM_STR_BYTES is too big"
# endif

char* FROM_FSTR_TO_BUF(FMEM_STR_T *fs, char *buf) {
	fsi_t i;

	ASSERT_FS(fs);
	ASSERT_BUF(buf);

#if DO_FMEM_SAFETY_CHECKS
	if (buf == NULL) {
		return NULL;
	}
	if (fs == FS_NULL) {
		buf[0] = 0;
		return buf;
	}
#endif

	// No point checking for overruns here because we don't know the size of
	// the destination buffer.
	for (i = 0; (buf[i] = fs[i]) != 0; ++i) {
		// Nothing to do here
	}

	return buf;
}

static char* from_fstr(FMEM_STR_T *fs, char *buf) {
	fsi_t i;

	ASSERT_FS(fs);

#if DO_FMEM_SAFETY_CHECKS
	if (buf == NULL) {
		return NULL;
	}
	if (fs == FS_NULL) {
		buf[0] = 0;
		return buf;
	}

	for (i = 0; ((i < FMEM_STR_BYTES) && ((buf[i] = fs[i]) != 0)); ++i) {
		// Nothing to do here
	}
	buf[FMEM_STR_BYTES-1] = 0;
#else
	for (i = 0; (buf[i] = fs[i]) != 0; ++i) {
		// Nothing to do here
	}
#endif

	return buf;
}
char* FROM_FSTR(FMEM_STR_T *fs) {
	static char buf[FMEM_STR_BYTES];

	return from_fstr(fs, buf);
}
char* FROM_FSTR1(FMEM_STR_T *fs) {
	static char buf[FMEM_STR_BYTES];

	return from_fstr(fs, buf);
}
char* FROM_FSTR2(FMEM_STR_T *fs) {
	static char buf[FMEM_STR_BYTES];

	return from_fstr(fs, buf);
}
char* FROM_FSTR3(FMEM_STR_T *fs) {
	static char buf[FMEM_STR_BYTES];

	return from_fstr(fs, buf);
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy1;
#endif // HAVE_FMEM_NAMESPACE
#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy2;
#endif // ULIB_ENABLE_FMEM
#ifdef __cplusplus
 }
#endif
