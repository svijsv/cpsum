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
// bits.h
// Operations on bitfields
// NOTES:
//   Macros should only ever expand any given argument once if it can be
//   helped so that any arguments with side-effects (like registers that
//   reset themselves) don't cause problems. Of course some already don't.
//
//   The inline functions are intended primarily for situations where type
//   checking the input is desired but also helps to protect against double-
//   expansion of arguments.
//
//   SET_BIT(), CLEAR_BIT(), TOGGLE_BIT(), and MODIFY_BITS() set the variable
//   given to them as the field, nothing else does.
//
//   http:// realtimecollisiondetection.net/blog/?p=78
//   http:// graphics.stanford.edu/~seander/bithacks.html
//   https:// gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_BITS_H
#define _ULIB_BITS_H

#include "configify.h"
#include "types.h"
#include "util.h"

// Type used for type-checked bitwise operations
#if BITOP_WIDTH <= 8
typedef uint8_t bitop_t;
#elif BITOP_WIDTH <= 16
typedef uint16_t bitop_t;
#elif BITOP_WIDTH <= 32
typedef uint32_t bitop_t;
#elif BITOP_WIDTH <= 64
typedef uint64_t bitop_t;
#else
# error "BITOP_WIDTH too large"
#endif

// Set one or more bits in a field
#ifndef SET_BIT
# define SET_BIT(field, bits) ((field) |= (bits))
#endif
INLINE bitop_t _set_bit(bitop_t field, bitop_t bits) {
	return SET_BIT(field, bits);
}
#define set_bit(field, bits) (field = (__typeof__(field) )_set_bit(field, bits))

// Unset one or more bits in a field
#ifndef CLEAR_BIT
# define CLEAR_BIT(field, bits) ((field) &= ~(bits))
#endif
INLINE bitop_t _clear_bit(bitop_t field, bitop_t bits) {
	return CLEAR_BIT(field, bits);
}
#define clear_bit(field, bits) (field = (__typeof__(field) )_clear_bit(field, bits))

// Toggle one or more bits in a field
#define TOGGLE_BIT(field, bits) ((field) ^= (bits))
INLINE bitop_t _toggle_bit(bitop_t field, bitop_t bits) {
	return TOGGLE_BIT(field, bits);
}
#define toggle_bit(field, bits) (field = (__typeof__(field) )_toggle_bit(field, bits))

// Set or clear bits in a field limited by a mask
#define MODIFY_BITS(field, mask, bits) ((field) = (((field) & ~(mask)) | ((bits) & (mask))))
INLINE bitop_t _modify_bits(bitop_t field, bitop_t mask, bitop_t bits) {
	return MODIFY_BITS(field, mask, bits);
}
#define modify_bits(field, mask, bits) (field = (__typeof__(field) )_modify_bits(field, mask, bits))

// Select every set bit in field that's also set in mask
#define SELECT_BITS(field, mask) ((field) & (mask))
INLINE bitop_t _select_bits(bitop_t field, bitop_t mask) {
	return SELECT_BITS(field, mask);
}
#define select_bits(field, bits) ((__typeof__(field) )_select_bits(field, bits))

// Select every set bit in field except those set in mask
#define MASK_BITS(field, mask)   ((field) & ~(mask))
INLINE bitop_t _mask_bits(bitop_t field, bitop_t mask) {
	return MASK_BITS(field, mask);
}
#define mask_bits(field, mask) ((__typeof__(field) )_mask_bits(field, mask))

// Select every bit in a mask at some offset and then shift those bits to the
// LSB end
// offset is expanded twice for convenience
#define GATHER_BITS(field, mask, offset) (SELECT_BITS((field), ((mask) << (offset))) >> (offset))
INLINE bitop_t _gather_bits(bitop_t field, bitop_t mask, bitop_t offset) {
	return GATHER_BITS(field, mask, offset);
}
#define gather_bits(field, mask, offset) ((__typeof__(field) )_gather_bits(field, mask, offset))

// Check if any bit set in mask is set in field
#define BIT_IS_SET(field, mask)    (((field) & (mask)) != 0)
INLINE bool bit_is_set(bitop_t field, bitop_t bits) {
	return BIT_IS_SET(field, bits);
}

// Check if every bit set in mask is set in field
// mask is expanded twice for convenience
#define BITS_ARE_SET(field, mask) (((field) & (mask)) == (mask))
INLINE bool bits_are_set(bitop_t field, bitop_t mask) {
	return BITS_ARE_SET(field, mask);
}

// Turn an integer into a bit mask
#define AS_BIT(n) (1U << (n))
INLINE bitop_t as_bit(bitop_t n) {
	return ((bitop_t )1U << n);
}
// The headers for the ATMega provide this. It probably shouldn't be used
// anywhere else since there's an equivalent above, but here it is anyway.
#ifndef _BV
# define _BV(n) (1U << (n))
#endif

// Find the lowest set bit in a field
#define LOWEST_BIT(field) ((field) & -(field))
INLINE bitop_t lowest_bit(bitop_t field) {
	return LOWEST_BIT(field);
}
// Same, for unsigned ints, longs, and long longs
#define LSB(x)   (__builtin_ffs(x) - 1)
#define LSBL(x)  (__builtin_ffsl(x) - 1)
#define LSBLL(x) (__builtin_ffsll(x) - 1)

// Shift right so lowest set bit ends up at bit 0
#define SHIFT_LOWEST_BIT(field) ((field) / ((field) & -(field)))
INLINE bitop_t shift_lowest_bit(bitop_t field) {
	return SHIFT_LOWEST_BIT(field);
}

// Find the number of leading zeroes in unsigned ints, longs, and long longs
#define CLZ(x)   __builtin_clz(x)
#define CLZL(x)  __builtin_clzl(x)
#define CLZLL(x) __builtin_clzll(x)

#endif // _ULIB__H
#ifdef __cplusplus
 }
#endif
