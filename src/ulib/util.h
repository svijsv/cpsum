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
// util.h
// Utility functions
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_UTIL_H
#define _ULIB_UTIL_H

#include "configify.h"
#if ULIB_ENABLE_UTIL

#include "types.h"


//
// Initialize a block of memory
void mem_init(void *mem, uint8_t value, uint32_t size);

//
// Determine 
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN)
# define HAVE_BIG_ENDIAN 1
# define HAVE_LITTLE_ENDIAN 0
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN)
# define HAVE_BIG_ENDIAN 0
# define HAVE_LITTLE_ENDIAN 1
#endif

//
// Use these to show the value of a macro at compile-time
// https://stackoverflow.com/questions/1562074/how-do-i-show-the-value-of-a-define-at-compile-time
#define XTRINGIZE(x) STRINGIZE(x)
#define STRINGIZE(x) #x
//#pragma message "The value of ABC: " XTRINGIZE(ABC)

//
// Check if a value is between two others.
#define IS_BETWEEN_INCLUSIVE(x, min, max) ((x >= (min)) && (x <= (max)))
#define IS_BETWEEN_EXCLUSIVE(x, min, max) ((x >  (min)) && (x <  (max)))
//#define IS_BETWEEN(x, min, max) IS_BETWEEN_INCLUSIVE(x, min, max)
//
// Find the smaller of two values.
#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif
//
// Find the larger of two values.
#ifndef MAX
# define MAX(x, y) (((x) < (y)) ? (y) : (x))
#endif
//
// Find the nearest multiple of some factor which isn't larger than some value
#define SNAP_TO_FACTOR(max, factor) (((factor) != 0) ? ((max) - ((max) % (factor))) : 0)
//
// Add two unsigned numbers without going over some value, which may be the
// maximum the type can hold.
#define CLIP_UADD(a, b, max) ((((max) - (a)) > (b)) ? ((a) + (b)) : (max))
//
// Multiply two unsigned numbers without going over some value, which may be
// the maximum the type can hold.
//#define CLIP_UMUL(a, b, max) ((((a) == 0 || (b) == 0) || ((a) < ((max) / (b)))) ? ((a) * (b)) : (max))
#define CLIP_UMUL(a, b, max) (((a) == 0 || (b) == 0) ? 0 : ((a) < (max) / (b)) ? ((a) * (b)) : (max))

//
// Copy an integer composed of smaller integers
#define READ_SPLIT_U16(combined, high, low) \
	do { \
		((combined) = (uint16_t )((((uint16_t )(high)) << 8) | (((uint16_t )(low)) & 0xFF))); \
	} while (0);
#define READ_SPLIT_S16(combined, high, low) \
	do { \
		((combined) = (int16_t )((((int16_t )(high)) << 8) | (((int16_t )(low)) & 0xFF))); \
	} while (0);
//
// Copy a split register while making sure the low half doesn't overflow into
// high in the process
#define READ_SPLITREG32(combined, high, low) \
	do { \
		((combined) = (((uint32_t )(high)) << 16) | (((uint32_t )(low)) & 0xFFFF)); \
	} while ((((combined) >> 16) & 0xFFFF) != (high));
#define READ_SPLITREG16(combined, high, low) \
	do { \
		((combined) = (((uint16_t )(high)) << 8) | (((uint16_t )(low)) & 0xFF)); \
	} while ((((combined) >> 8) & 0xFF) != (high));
//
// Write to a split register
// Certain registers (like the RTC counter on the STM32) aren't updated
// immediately and so trying to check the writes on those will cause an
// infinite loop; there aren't really any places where overflow during write
// is possible, so just skip the check
#define WRITE_SPLITREG32(combined, high, low) \
	do { \
		(high) = (uint16_t )((combined) >> 16); \
		(low)  = (uint16_t )((combined) & 0xFFFF); \
	} while (0);
	//} while ((((combined) >> 16) & 0xFFFF) != (high));
#define WRITE_SPLITREG16(combined, high, low) \
	do { \
		(high) = (uint8_t )((combined) >> 8); \
		(low)  = (uint8_t )((combined) & 0xFF); \
	} while (0);
	//} while ((((combined) >> 8) & 0xFF) != (high));
//
// Write a volatile variable without atomic access; this doesn't protect
// anything trying to read it during the write
#define WRITE_VOLATILE(set, get) \
	do { \
		(set) = (get); \
	} while ((set) != (get));
//
// Read a volatile variable without atomic access
// For now it's identical to WRITE_VOLATILE() except the volatile variable
// is 'get' instead of 'set'.
#define READ_VOLATILE(set, get) \
	do { \
		(set) = (get); \
	} while ((set) != (get));

//
// Optimize a specific function independent of compiler flags.
#if !DEBUG
# define OPTIMIZE_FUNCTION __attribute__((optimize("O2")))
#else
# define OPTIMIZE_FUNCTION
#endif
#define DONT_OPTIMIZE_FUNCTION __attribute__((optimize("O0")))

//
// Strongly suggest that the compiler inline a function.
#define INLINE static inline
#define ALWAYS_INLINE static inline __attribute__((always_inline))

//
// Inform the compiler that some code path is likely or unlikely.
#define LIKELY(x)    (__builtin_expect((x),1))
#define UNLIKELY(x)  (__builtin_expect((x),0))

//
// Tell the compiler to not emit warnings for an unused value.
#define UNUSED(x) ((void )(x))

//
// Calculate the number of entities in an array (as opposed to the number of
// bytes used by it).
#define SIZEOF_ARRAY(a) (sizeof((a)) / sizeof((a)[0]))

//
// Determine if a pointer is valid. This may include additional checks in
// the future.
#define POINTER_IS_VALID(x) ((x) != NULL)


#endif // ULIB_ENABLE_UTIL
#endif // _ULIB_UTIL_H
#ifdef __cplusplus
 }
#endif
