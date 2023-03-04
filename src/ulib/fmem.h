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
// fmem.h
// Helpers for working with data in a separate address space
// NOTES:
//    AVR MCUs use separate address spaces for PROGMEM and RAM and in order to
//    store constant data in PROGMEM, these macros must be used - FMEM_STORAGE
//    as part of a static declaration for any data and F() for raw strings.
//    Because the pointers don't store information about which address space
//    they belong to, a pointer to data declared with FMEM_STORAGE and one
//    that wasn't can't be interchanged; in particular, passing such a pointer
//    to a function that doesn't expect it will produce garbage on the other
//    side.
//
//    Unfortunately there's no real way to do typechecking between PROGMEM and
//    RAM strings (or other data for that matter) except for using dummy
//    container structs, and those aren't always practical in the current
//    use case.
//
//    Strings passed to F() aren't deduplicated so anything that's used
//    repeatedly should be put in a variable declared as:
//        'FMEM_STORAGE const char n[] = "..."'
//    rather than with #define.
//
//    These helpers depend on named address spaces - a GNU extension based on
//    a proposal for the C11 standard - and won't work with C++ code or code
//    compiled without gnu extension support (such as with -std=c99).
//
//    The F() macro increases PROGMEM usage by more than it saves in RAM, so
//    may not always be worth using in spite of it's ease.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_FMEM_H
#define _ULIB_FMEM_H

#include "configify.h"
#if ULIB_ENABLE_FMEM

#include "types.h"


/*
// Dummy struct used to wrap PROGMEM strings to provide stronger type-checking
typedef struct {
	char *contents;
} fstring_t;
*/
//#define FMEM_STR_T FMEM_STORAGE const fstring_t
#define FMEM_STR_T FMEM_STORAGE const char


#if HAVE_FMEM_NAMESPACE
# define FMEM_STORAGE __flash
// Copy a string from PROGMEM memory to a RAM buffer so it can be passed to a
// function or pointer that doesn't know about program memory.
//
// Macro and inline versions of FROM_FSTR() are possible but take a LOT more
// program space per invocation.
//
// Multiple versions are defined because they use internal static arrays and
// so can't be used more than once in a single statement.
//
// Unused FROM_FSTR() functions (and their static arrays) should be dropped
// by the compiler or linker, so the smallest subset of these possible should
// be used.
char* FROM_FSTR(FMEM_STR_T *fs);
char* FROM_FSTR1(FMEM_STR_T *fs);
char* FROM_FSTR2(FMEM_STR_T *fs);
char* FROM_FSTR3(FMEM_STR_T *fs);
char* FROM_FSTR_TO_BUF(FMEM_STR_T *fs, char *buf);

// Store a static string in program memory.
# define FSTR(s) ((FMEM_STR_T *)({static FMEM_STORAGE const char __c[] = s; &__c[0];}))

// Store a string in program memory, but copy it to a ram buffer before use so
// that it can be passed to a function expecting normal strings.
//
// Use the name 'F()' (borrowed from Arduino) rather than PSTR() (used by
// avr-gcc) because we're building with the latter and want to avoid clashes.
# define F(s) FROM_FSTR(FSTR(s))
# define F1(s) FROM_FSTR1(FSTR(s))
# define F2(s) FROM_FSTR2(FSTR(s))
# define F3(s) FROM_FSTR3(FSTR(s))


#else // !HAVE_FMEM_NAMESPACE
# define FMEM_STORAGE
# define FSTR(s) (s)
# define FROM_FSTR(s) (s)
# define FROM_FSTR1(s) (s)
# define FROM_FSTR2(s) (s)
# define FROM_FSTR3(s) (s)
# define FROM_FSTR_TO_BUF(s, b) ({ for (uint_t i = 0; (b[i] = s[i]) != 0; ++i); b; })
# define F(s) (s)
# define F1(s) (s)
# define F2(s) (s)
# define F3(s) (s)
#endif // HAVE_FMEM_NAMESPACE

#endif // ULIB_ENABLE_FMEM
#endif // _ULIB_FMEM_H
#ifdef __cplusplus
 }
#endif
