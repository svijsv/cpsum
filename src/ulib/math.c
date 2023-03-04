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
// math.c
// Math functions for use when libc isn't worth it
// NOTES:
//    https://github.com/torvalds/linux/blob/master/lib/math/div64.c
//    It's been adapted to my conventions, but that's only cosmetic.
//
//    https://www.bbcelite.com/deep_dives/shift-and-subtract_division.html
//    Used for div_u64_u64() because the Linux version truncates the divisor.
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "math.h"
#if ULIB_ENABLE_MATH

#include "debug.h"


//
// logE(2) and log10(2) converted to our fixed-point notation.
// The pre-calculated values are log(2)*(2^31) because that leaves the sign
// bit alone and uses the rest of the bits to store the values (which are
// both <1). To adjust them, they first need to be shifted to be the same
// number of bits as our fixed point type and then converted to the fixed-
// point type by shifting the non-fraction part out.
// logE(2)  == 0.69314718055995
// log10(2) == 0.30102999566398
#if FIXED_PNT_BITS <= 32
# define FIXED_PNT_LOG_ADJUST_SHIFT ((31 - (31 - (FIXED_PNT_BITS-1))) - FIXED_PNT_FRACT_BITS)
# define FIXED_PNT_LOGE_2Q31 0x58B90BFB // ln(2) * (1 << 31)
# define FIXED_PNT_LOGE_2 (FIXED_PNT_LOGE_2Q31 >> FIXED_PNT_LOG_ADJUST_SHIFT)
# define FIXED_PNT_LOG10_2Q31 0x268826A1 // log10(2) * (1 << 31)
# define FIXED_PNT_LOG10_2 (FIXED_PNT_LOG10_2Q31 >> FIXED_PNT_LOG_ADJUST_SHIFT)
#else
# define FIXED_PNT_LOG_ADJUST_SHIFT ((63 - (63 - (FIXED_PNT_BITS-1))) - FIXED_PNT_FRACT_BITS)
# define FIXED_PNT_LOGE_2Q63 0x58B90BFBE8E865D4 // ln(2) * (1 << 63)
# define FIXED_PNT_LOGE_2 (FIXED_PNT_LOGE_2Q63 >> FIXED_PNT_LOG_ADJUST_SHIFT)
# define FIXED_PNT_LOG10_2Q63 0x268826A13EF3D2D6 // log10(2) * (1 << 63)
# define FIXED_PNT_LOG10_2 (FIXED_PNT_LOG10_2Q63 >> FIXED_PNT_LOG_ADJUST_SHIFT)
#endif


int64_t div_s64_s64(int64_t n, int64_t d) {
	int64_t res, t;

	assert(d != 0);

#if DO_MATH_SAFETY_CHECKS
	if (d == 0) {
		return n;
	}
#endif

	t = (n ^ d) >> 63;
	res = (int64_t )div_u64_u64((uint64_t )ABS(n), (uint64_t )ABS(d));

	return (res ^ t) - t;
}

// This is just long division with 16-bit 'digits'
uint64_t div_u64_u16(uint64_t n, uint16_t d) {
	uint32_t r32, d32;
	union {
		uint64_t i;
		struct {
#if HAVE_BIG_ENDIAN
			uint16_t d;
			uint16_t c;
			uint16_t b;
			uint16_t a;
#elif HAVE_LITTLE_ENDIAN
			uint16_t a;
			uint16_t b;
			uint16_t c;
			uint16_t d;
#else
# error "Unhandled endianness"
#endif
		} p;
	} nparts, rparts;

	assert(d != 0);

#if DO_MATH_SAFETY_CHECKS
	if (d == 0) {
		return n;
	}
#endif

	if (d > n) {
		return 0;
	}

	nparts.i = n;
	d32 = d;

	r32 = nparts.p.a;
	rparts.p.a = (uint16_t )(r32 / d32);

	r32 = (r32 % d) << 16;
	r32 |= nparts.p.b;
	rparts.p.b = (uint16_t )(r32 / d32);

	r32 = (r32 % d) << 16;
	r32 |= nparts.p.c;
	rparts.p.c = (uint16_t )(r32 / d32);

	r32 = (r32 % d) << 16;
	r32 |= nparts.p.d;
	rparts.p.d = (uint16_t )(r32 / d32);

	return rparts.i;
}

uint64_t div_u64_u32(uint64_t n, uint32_t d) {
	uint64_t rem, d64, c, res;
	uint32_t high;

	assert(d != 0);

#if DO_MATH_SAFETY_CHECKS
	if (d == 0) {
		return n;
	}
#endif

	rem = n;
	d64 = d;
	c = 1;
	high = (uint32_t )(rem >> 32);

	res = 0;
	if (high >= d) {
		high /= d;
		res = (uint64_t )high << 32;
		rem -= (uint64_t )(high * d) << 32;
	}

	while (((int64_t )d64 > 0) && (d64 < rem)) {
		d64 = d64 + d64;
		c = c + c;
	}

	do {
		if (rem >= d64) {
			rem -= d64;
			res += c;
		}
		d64 >>= 1;
		c >>= 1;
	} while (c);

	/*
	if (ret_rem != NULL) {
		*ret_rem = rem;
	}
	*/

	return res;
}

uint64_t div_u64_u64(uint64_t n, uint64_t d) {
	uint64_t high, res, rem;
	high = n >> 32;

	assert(d != 0);

#if DO_MATH_SAFETY_CHECKS
	if (d == 0) {
		return n;
	}
#endif

	if (d > n) {
		return 0;
	}

	if (high == 0) {
		res = div_u64_u32(n, (uint32_t )d);
	} else {
		uint64_t im = (uint64_t )1U << 63;
		res = 0;
		rem = 0;

		for (uiter_t i = 0; i < 64; ++i) {
			rem <<= 1;
			rem |= ((n & im) != 0);
			if (rem >= d) {
				rem -= d;
				res |= im;
			}
			im >>= 1;
		}
	}

	return res;
}
/*
// This is the linux version, which truncates the divisor:
uint64_t div_u64_u64(uint64_t n, uint64_t d) {
	uint64_t high, res;
	high = n >> 32;

	if (high == 0) {
		res = div_u64_u32(n, d);
	} else {
		int s;
		s = MSB32_IDX(high);
		res = div_u64_u32(n >> s, d >> s);

		if (res != 0) {
			res--;
		}
		if ((n - (res * d)) >= d) {
			res++;
		}
	}

	return res;
}
*/

fixed_pnt_t log10_fixed_pnt(fixed_pnt_t x) {
	assert(x != 0);

#if DO_MATH_SAFETY_CHECKS
	if (x == 0) {
		return 0;
	}
#endif
	// Calculating log2(x) is easi-ish and log10(x) = log2(x) * log10(2)
	return FIXED_PNT_MUL(log2_fixed_pnt(x), FIXED_PNT_LOG10_2);
}
fixed_pnt_t log_fixed_pnt(fixed_pnt_t x) {
	assert(x != 0);

#if DO_MATH_SAFETY_CHECKS
	if (x == 0) {
		return 0;
	}
#endif

	// Calculating log2(x) is easi-ish and log(x) = log2(x) * log(2)
	return FIXED_PNT_MUL(log2_fixed_pnt(x), FIXED_PNT_LOGE_2);
}
fixed_pnt_t log2_fixed_pnt(fixed_pnt_t x) {
	fixed_pnt_t log2_x, b;
	fixed_pnt_math_t z;

	assert(x > 0);

#if DO_MATH_SAFETY_CHECKS
	if (x == 0) {
		return 0;
	}
#endif

	log2_x = 0;
	b = 1U << (FIXED_PNT_FRACT_BITS - 1);

	// https:// stackoverflow.com/questions/4657468/fast-fixed-point-pow-log-exp-and-sqrt
	//   (Second answer)
	//    references http:// www.claysturner.com/dsp/BinaryLogarithm.pdf
	// https:// github.com/dmoulding/log2fix
	while (x < FIXED_PNT_1) {
		x <<= 1;
		log2_x -= FIXED_PNT_1;
	}
	while (x >= (2 << FIXED_PNT_FRACT_BITS)) {
		x >>= 1;
		log2_x += 1 << FIXED_PNT_FRACT_BITS;
	}
	z = x;
	for (uiter_t i = 0; i < FIXED_PNT_FRACT_BITS; ++i) {
		z = (z * z) >> FIXED_PNT_FRACT_BITS;
		if (z >= (2U << FIXED_PNT_FRACT_BITS)) {
			z >>= 1;
			log2_x += b;
		}
		b >>= 1;
	}

	return log2_x;
}

/*
// https:// stackoverflow.com/questions/54661131/log2-approximation-in-fixed-point
#define FRAC_BITS_OUT (FIXED_PNT_FRACT_BITS)
#define INT_BITS_OUT  (32-FIXED_PNT_FRACT_BITS)
#define FRAC_BITS_IN  (FIXED_PNT_FRACT_BITS)
#define INT_BITS_IN   (32-FIXED_PNT_FRACT_BITS)
#define RND_SHIFT     (31 - FRAC_BITS_OUT)
#define RND_CONST     ((1 << RND_SHIFT) / 2)
#define RND_ADJUST    (0x10d) // established heuristically
#define LOG2_TBL_SIZE (6)
#define TBL_SIZE      ((1 << LOG2_TBL_SIZE) + 2)
int32_t log2_fp(int32_t x) {
	// for i = [0,65]: log2(1 + i/64) * (1 << 31)
	static FMEM_STORAGE const uint32_t log2Tab [TBL_SIZE] = {
		0x00000000, 0x02dcf2d1, 0x05aeb4dd, 0x08759c50, 
		0x0b31fb7d, 0x0de42120, 0x108c588d, 0x132ae9e2, 
		0x15c01a3a, 0x184c2bd0, 0x1acf5e2e, 0x1d49ee4c, 
		0x1fbc16b9, 0x22260fb6, 0x24880f56, 0x26e2499d, 
		0x2934f098, 0x2b803474, 0x2dc4439b, 0x30014ac6, 
		0x32377512, 0x3466ec15, 0x368fd7ee, 0x38b25f5a, 
		0x3acea7c0, 0x3ce4d544, 0x3ef50ad2, 0x40ff6a2e, 
		0x43041403, 0x450327eb, 0x46fcc47a, 0x48f10751, 
		0x4ae00d1d, 0x4cc9f1ab, 0x4eaecfeb, 0x508ec1fa, 
		0x5269e12f, 0x5440461c, 0x5612089a, 0x57df3fd0, 
		0x59a80239, 0x5b6c65aa, 0x5d2c7f59, 0x5ee863e5, 
		0x60a02757, 0x6253dd2c, 0x64039858, 0x65af6b4b, 
		0x675767f5, 0x68fb9fce, 0x6a9c23d6, 0x6c39049b, 
		0x6dd2523d, 0x6f681c73, 0x70fa728c, 0x72896373, 
		0x7414fdb5, 0x759d4f81, 0x772266ad, 0x78a450b8, 
		0x7a231ace, 0x7b9ed1c7, 0x7d17822f, 0x7e8d3846, 
		0x80000000, 0x816fe50b
	};
	int32_t f1, f2, dx, a, b, approx, lz, i, idx;
	uint32_t t;

	// x = 2**i * (1 + f), 0 <= f < 1. Find i
	lz = clz (x);
	i = INT_BITS_IN - lz;
	// normalize f
	t = (uint32_t)x << (lz + 1);
	// index table of log2 values using LOG2_TBL_SIZE msbs of fraction
	idx = t >> (32 - LOG2_TBL_SIZE);
	// difference between argument and smallest sampling point
	dx = t - (idx << (32 - LOG2_TBL_SIZE));
	// fit parabola through closest three sampling points; find coeffs a, b
	f1 = (log2Tab[idx+1] - log2Tab[idx]);
	f2 = (log2Tab[idx+2] - log2Tab[idx]);
	a = f2 - (f1 << 1);
	b = (f1 << 1) - a;
	// find function value for argument by computing ((a*dx+b)*dx)
	approx = (int32_t)((((int64_t)a)*dx) >> (32 - LOG2_TBL_SIZE)) + b;
	approx = (int32_t)((((int64_t)approx)*dx) >> (32 - LOG2_TBL_SIZE + 1));
	approx = log2Tab[idx] + approx;
	// round fractional part of result
	approx = (((uint32_t)approx) + RND_CONST + RND_ADJUST) >> RND_SHIFT;
	// combine integer and fractional parts of result
	return (i << FRAC_BITS_OUT) + approx;
}
*/

#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_MATH
#ifdef __cplusplus
 }
#endif
