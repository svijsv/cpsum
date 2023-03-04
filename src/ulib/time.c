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
// time.c
// Tools for dealing with time
//
// NOTES:
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "time.h"
#if ULIB_ENABLE_TIME

#include "debug.h"


#if ((((TIME_YEAR_0) % 4) == 0) && ((((TIME_YEAR_0) % 100) != 0) || (((TIME_YEAR_0) % 400) == 0)))
# error "TIME_YEAR_0 Cannot be a leap year"
#endif

#define MAX_YEARS (((utime_t )-1) / SECONDS_PER_YEAR)

// Calculate the number of leap years up to some year
// This calculation excludes TIME_YEAR_0 when it's a multiple of the factor
// This calculation includes year y when it's a multiple of the factor and not 0
#define _GET_LEAPS(y, f) (((TIME_YEAR_0 + (y)) - (TIME_YEAR_0 - (TIME_YEAR_0 % (f)))) / (f))
// Determine if a year relative to TIME_YEAR_0 is a leap year
#define _IS_LEAP_YEAR(y) ((((TIME_YEAR_0 + (y)) % 4) == 0) && ((((TIME_YEAR_0 + (y)) % 100) != 0) || (((TIME_YEAR_0 + (y)) % 400) == 0)))

FMEM_STORAGE const uint8_t days_per_month[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

INLINE uint8_t GET_LEAPS(uint16_t year, uint16_t factor) {
	return (uint8_t )_GET_LEAPS(year, factor);
}
INLINE bool IS_LEAP_YEAR(uint16_t year) {
	return _IS_LEAP_YEAR(year);
}

utime_t date_to_seconds(uint8_t year, uint8_t month, uint8_t day) {
	utime_t days;
	uint8_t year_4s, year_100s, year_400s, leap_days;

	assert(year <= MAX_YEARS);
	assert(IS_BETWEEN_INCLUSIVE(month, 1, 12));
	assert(IS_BETWEEN_INCLUSIVE(day, 1, 31));

#if DO_TIME_SAFETY_CHECKS
	if (year > MAX_YEARS) {
		year = 0;
	}
	if (!IS_BETWEEN_INCLUSIVE(month, 1, 12)) {
		month = 1;
	}
	if (!IS_BETWEEN_INCLUSIVE(day, 1, 31)) {
		day = 1;
	}
#endif

	// Dates are 1-indexed, but they're counted in a 0-indexed manner
	days = day - 1;

	// Find the number of days in all previous months
	for (uiter_t i = 1; i < month; ++i) {
		days += days_per_month[i-1];
	}

	// Leap years are years that are divisible by 4 but not by 100, or years
	// that are divisible by 400
	year_4s   = GET_LEAPS(year, 4);
	year_100s = GET_LEAPS(year, 100);
	year_400s = GET_LEAPS(year, 400);
	leap_days = (uint8_t )(year_4s - year_100s) + year_400s;
	if (IS_LEAP_YEAR(0)) {
		++leap_days;
	}
	if (IS_LEAP_YEAR(year)) {
		if (month < 3) {
			--leap_days;
		}
	}
	days += leap_days;

	return (utime_t )(year * SECONDS_PER_YEAR) + (utime_t )(days * SECONDS_PER_DAY);
}
void seconds_to_date(utime_t seconds, uint8_t *restrict ret_year, uint8_t *restrict ret_month, uint8_t *restrict ret_day) {
	uint8_t tmp_month;
	uint16_t tmp_year, tmp_day, leap_days;
	uint8_t year_4s, year_100s, year_400s;

	assert(ret_year != NULL);
	assert(ret_month != NULL);
	assert(ret_day != NULL);

	tmp_year = (uint16_t )(seconds / SECONDS_PER_YEAR);
	tmp_day = (uint16_t )((seconds % SECONDS_PER_YEAR) / SECONDS_PER_DAY);

	// Leap years are years that are divisible by 4 but not by 100, or years
	// that are divisible by 400
	// Exclude the current year from the calculation to simplify things later
	// on
	year_4s   = GET_LEAPS(tmp_year-1, 4);
	year_100s = GET_LEAPS(tmp_year-1, 100);
	year_400s = GET_LEAPS(tmp_year-1, 400);
	leap_days = (uint8_t )(year_4s - year_100s) + year_400s;
	if ((IS_LEAP_YEAR(0)) && (tmp_year != 0)) {
		++leap_days;
	}
	// TODO: Handle leap_days > 365?
	if (leap_days > tmp_day) {
		// FIXME: Handle tmp_year == 0
		--tmp_year;
		// Day 0 of one year is the same as day 366 of the previous year
		tmp_day = 366 - (uint16_t )(leap_days - tmp_day);
	} else {
		tmp_day -= leap_days;
	}

	// Months and days are 1-indexed
	tmp_month = 1;
	++tmp_day;
	for (uiter_t i = 0; (days_per_month[i] < tmp_day); ++i) {
		tmp_day -= days_per_month[i];
		++tmp_month;
	}

	if (IS_LEAP_YEAR(tmp_year) && (tmp_month > 2)) {
		--tmp_day;

		if (tmp_day == 0) {
			--tmp_month;

			if (tmp_month == 2) {
				tmp_day = 29;
			} else {
				tmp_day = days_per_month[tmp_month-1];
			}
		}
	}

#if DO_TIME_SAFETY_CHECKS
	if (ret_year != NULL) {
		*ret_year  = (uint8_t )tmp_year;
	}
	if (ret_month != NULL) {
		*ret_month = (uint8_t )tmp_month;
	}
	if (ret_day != NULL) {
		*ret_day = (uint8_t )tmp_day;
	}
#else
	*ret_year  = (uint8_t )tmp_year;
	*ret_month = (uint8_t )tmp_month;
	*ret_day   = (uint8_t )tmp_day;
#endif

	return;
}

void seconds_to_time(utime_t seconds, uint8_t *restrict ret_hour, uint8_t *restrict ret_minute, uint8_t *restrict ret_second) {
	assert(ret_hour != NULL);
	assert(ret_minute != NULL);
	assert(ret_second != NULL);

#if DO_TIME_SAFETY_CHECKS
	if (ret_hour != NULL) {
		*ret_hour   = (uint8_t )((seconds % SECONDS_PER_DAY) / SECONDS_PER_HOUR);
	}
	if (ret_minute != NULL) {
		*ret_minute = (uint8_t )((seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE);
	}
	if (ret_second != NULL) {
		*ret_second = (uint8_t )((seconds % SECONDS_PER_MINUTE));
	}
#else
	*ret_hour   = (uint8_t )((seconds % SECONDS_PER_DAY) / SECONDS_PER_HOUR);
	*ret_minute = (uint8_t )((seconds % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE);
	*ret_second = (uint8_t )((seconds % SECONDS_PER_MINUTE));
#endif

	return;
}
utime_t time_to_seconds(uint8_t hour, uint8_t minute, uint8_t second) {
	assert(hour < 24);
	assert(minute < 60);
	assert(second < 60);

#if DO_TIME_SAFETY_CHECKS
	if (hour >= 24) {
		hour = 0;
	}
	if (minute >= 60) {
		minute = 0;
	}
	if (second >= 60) {
		second = 0;
	}
#endif

	return ((utime_t )hour * SECONDS_PER_HOUR) + ((utime_t )minute * SECONDS_PER_MINUTE) + (utime_t )second;
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_TIME
#ifdef __cplusplus
 }
#endif
