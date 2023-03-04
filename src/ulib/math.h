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
// math.h
// Math functions for use when libc isn't worth it
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_MATH_H
#define _ULIB_MATH_H

#include "configify.h"
#if ULIB_ENABLE_MATH

#include "types.h"
#include "util.h"


/*
* Integer operations
*/
// Absolute value of an integer, naive-but-simple approach.
#ifndef ABS
# define ABS(x) (((x) > 0) ? (x) : -(x))
#endif
//
// Like ABS(), but negative.
#ifndef NABS
# define NABS(x) (((x) > 0) ? -(x) : (x))
#endif
//
// Round a division instead of truncating.
#define DIV_ROUNDED(n, d) (((n) + ((d)/2)) / (d))
//
// Test for truncation in a division.
#define DIV_IS_TRUNCATED(n, d) ((((n) / (d)) * (d)) != (n))


/*
* Power-of-two operations
*/
// Shifts needed to adjust a value by a given power of 2
#define POW2_2_SHIFTS    (1U)
#define POW2_4_SHIFTS    (2U)
#define POW2_8_SHIFTS    (3U)
#define POW2_16_SHIFTS   (4U)
#define POW2_32_SHIFTS   (5U)
#define POW2_64_SHIFTS   (6U)
#define POW2_128_SHIFTS  (7U)
#define POW2_256_SHIFTS  (8U)
#define POW2_512_SHIFTS  (9U)
#define POW2_1024_SHIFTS (10U)
//
// Quick power-of-2 division for unsigned ints
#define SHIFT_DIV_2(x)    ((x) >>  1U)
#define SHIFT_DIV_4(x)    ((x) >>  2U)
#define SHIFT_DIV_8(x)    ((x) >>  3U)
#define SHIFT_DIV_16(x)   ((x) >>  4U)
#define SHIFT_DIV_32(x)   ((x) >>  5U)
#define SHIFT_DIV_64(x)   ((x) >>  6U)
#define SHIFT_DIV_128(x)  ((x) >>  7U)
#define SHIFT_DIV_256(x)  ((x) >>  8U)
#define SHIFT_DIV_512(x)  ((x) >>  9U)
#define SHIFT_DIV_1024(x) ((x) >> 10U)
//
// Quick power-of-2 multiplication for unsigned ints
#define SHIFT_MUL_2(x)    ((x) <<  1U)
#define SHIFT_MUL_4(x)    ((x) <<  2U)
#define SHIFT_MUL_8(x)    ((x) <<  3U)
#define SHIFT_MUL_16(x)   ((x) <<  4U)
#define SHIFT_MUL_32(x)   ((x) <<  5U)
#define SHIFT_MUL_64(x)   ((x) <<  6U)
#define SHIFT_MUL_128(x)  ((x) <<  7U)
#define SHIFT_MUL_256(x)  ((x) <<  8U)
#define SHIFT_MUL_512(x)  ((x) <<  9U)
#define SHIFT_MUL_1024(x) ((x) << 10U)


/*
* Software 64-bit math operations
*/
// Divide n by d
uint64_t div_u64_u16(uint64_t n, uint16_t d);
uint64_t div_u64_u32(uint64_t n, uint32_t d);
uint64_t div_u64_u64(uint64_t n, uint64_t d);
int64_t  div_s64_s64( int64_t n,  int64_t d);

/*
* Fixed-point math operations
*/
// fixed_pnt_t is the type used to store representations.
// fixed_pnt_math_t is the type used for operations that may overflow fixed_pnt_t.
#if FIXED_PNT_BITS > 64
# error "FIXED_PNT_BITS is too big"
#elif FIXED_PNT_BITS == 64
# define FIXED_PNT_MIN INT64_MIN
# define FIXED_PNT_MAX INT64_MAX
  typedef int64_t fixed_pnt_t;
  // Maybe some day I'll be able to count on int128_t...
  //typedef __int128 fixed_pnt_math_t;
  typedef int64_t fixed_pnt_math_t;
#elif FIXED_PNT_BITS == 32
# define FIXED_PNT_MIN INT32_MIN
# define FIXED_PNT_MAX INT32_MAX
  typedef int32_t fixed_pnt_t;
  typedef int64_t fixed_pnt_math_t;
#elif FIXED_PNT_BITS == 16
# define FIXED_PNT_MIN INT16_MIN
# define FIXED_PNT_MAX INT16_MAX
  typedef int16_t fixed_pnt_t;
  typedef int32_t fixed_pnt_math_t;
#elif FIXED_PNT_BITS == 8
# define FIXED_PNT_MIN INT8_MIN
# define FIXED_PNT_MAX INT8_MAX
  typedef int8_t fixed_pnt_t;
  typedef int16_t fixed_pnt_math_t;
#else
# error "Unsupported FIXED_PNT_BITS size"
#endif
//
// '1' converted to our fixed-point notation.
#define FIXED_PNT_1 ((fixed_pnt_t )1 << FIXED_PNT_FRACT_BITS)
//
// Create a fixed-point number from an integer
#define FIXED_PNT_FROM(x) ((fixed_pnt_t )(x) << FIXED_PNT_FRACT_BITS)
INLINE fixed_pnt_t fixed_pnt_from(fixed_pnt_t x) {
	return x << FIXED_PNT_FRACT_BITS;
}
//
// Create an integer from a fixed-point number.
#define FIXED_PNT_TO(x) ((fixed_pnt_t )(x) >> FIXED_PNT_FRACT_BITS)
INLINE fixed_pnt_t fixed_pnt_to(fixed_pnt_t x) {
	return x >> FIXED_PNT_FRACT_BITS;
}
//
// Multiply two fixed-point numbers.
// (X*Sx) * (Y*Sy) = (X*Y) * (Sx*Sy)
// The scaling factor is squared, so one needs to be removed
// ((X*Y) * (S*S)) / S
#define FIXED_PNT_MUL(x, y) ((fixed_pnt_t )(((fixed_pnt_math_t )(x) * (fixed_pnt_math_t )(y)) >> FIXED_PNT_FRACT_BITS))
INLINE fixed_pnt_t fixed_pnt_mul(fixed_pnt_math_t x, fixed_pnt_math_t y) {
	return (fixed_pnt_t )((x * y) >> FIXED_PNT_FRACT_BITS);
}
//
// Multiply a fixed-point number by an integer.
// Integers are unscaled so no shift is necessary.
#define FIXED_PNT_MUL_BY_INT(f, n) ((fixed_pnt_math_t )(f) * (n))
INLINE fixed_pnt_t fixed_pnt_mul_by_int(fixed_pnt_t x, fixed_pnt_t y) {
	return (x * y);
}
//
// Divide two fixed-point numbers.
// https:// en.wikipedia.org/wiki/Fixed-point_arithmetic#Operations
// (X*Sx) / (Y*Sy) = (X/Y) * (Sy/Sx)
// The scaling factor cancels out, so it needs to be re-added
// ((X/Y) * (S/S)) * S
// Use an overridable macro for division because a certain platform doesn't
// have native support for 64 bit division and using libc adds a full Kb to
// the .data section of our binary...
#if !defined(_FIXED_PNT_DIV_PRIM)
# define _FIXED_PNT_DIV_PRIM(_n, _d) ((_n) / (_d))
#endif
#define FIXED_PNT_DIV(n, d) ((fixed_pnt_t )(_FIXED_PNT_DIV_PRIM(((fixed_pnt_math_t )(n) << FIXED_PNT_FRACT_BITS), (fixed_pnt_t )(d))))
INLINE fixed_pnt_t fixed_pnt_div(fixed_pnt_math_t n, fixed_pnt_math_t d) {
	return (fixed_pnt_t )_FIXED_PNT_DIV_PRIM((n << FIXED_PNT_FRACT_BITS), d);
}
//
// Divide a fixed-point number by an integer.
// Integers are unscaled so no shift is necessary.
#define FIXED_PNT_DIV_BY_INT(f, n) (_FIXED_PNT_DIV_PRIM((fixed_pnt_t )f, n))
INLINE fixed_pnt_t fixed_pnt_div_by_int(fixed_pnt_t f, fixed_pnt_t n) {
	return (fixed_pnt_t )_FIXED_PNT_DIV_PRIM(f, n);
}

//
// Calculate the natural logarithm of a fixed-point number.
fixed_pnt_t log_fixed_pnt(fixed_pnt_t x);
//
// Calculate the base 10 logarithm of a fixed-point number.
fixed_pnt_t log10_fixed_pnt(fixed_pnt_t x);
//
// Calculate the base 2 logarithm of a fixed-point number.
fixed_pnt_t log2_fixed_pnt(fixed_pnt_t x);


#endif // ULIB_ENABLE_MATH
#endif // _ULIB_MATH_H
#ifdef __cplusplus
 }
#endif
