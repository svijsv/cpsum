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
// time.h
// Tools for dealing with time
// NOTES:
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_TIME_H
#define _ULIB_TIME_H

#include "configify.h"
#if ULIB_ENABLE_TIME

#include "fmem.h"
#include "types.h"
#include "util.h"


// A possibly-smaller-than-time_t unsigned time-tracking type for embedded systems.
typedef uint32_t utime_t;

/*
* Periods
*/
// Seconds in a given time period.
/*
#define MINUTES(x) ((x) * SECONDS_PER_MINUTE)
#define HOURS(x)   ((x) * SECONDS_PER_HOUR)
#define DAYS(x)    ((x) * SECONDS_PER_DAY)
#define YEARS(x)   ((x) * SECONDS_PER_YEAR)
*/
#define SECONDS_PER_MINUTE (60U)
#define SECONDS_PER_HOUR   (SECONDS_PER_MINUTE * 60U)
#define SECONDS_PER_DAY    (SECONDS_PER_HOUR   * 24U)
#define SECONDS_PER_YEAR   (SECONDS_PER_DAY    * 365U)
//
// Minutes in a given time period.
#define MINUTES_PER_HOUR (60U)
#define MINUTES_PER_DAY  (MINUTES_PER_HOUR * 24U)
#define MINUTES_PER_YEAR (MINUTES_PER_DAY  * 365U)
//
// Convert a frequency to a millisecond time period, truncated.
#define HZ_TO_MS_TRUNC(freq) (1000 / freq)
// Convert a frequency to a millisecond time period, rounded.
#define HZ_TO_MS(freq) ((1000 + (freq/2)) / freq)
//
// Convert a frequency to a microsecond time period, truncated.
#define HZ_TO_US_TRUNC(freq) (1000000 / freq)
// Convert a frequency to a microsecond time period, rounded.
#define HZ_TO_US(freq) ((1000000 + (freq/2)) / freq)


/*
* Dates
*/
// A list of the number of days in each month.
extern FMEM_STORAGE const uint8_t days_per_month[];
//
// Convert between epoch-based times and calendar times.
// year is the number of years after TIME_YEAR_0.
utime_t date_to_seconds(uint8_t year, uint8_t month, uint8_t day);
utime_t time_to_seconds(uint8_t hour, uint8_t minute, uint8_t second);
void seconds_to_date(utime_t seconds, uint8_t *restrict ret_year, uint8_t *restrict ret_month, uint8_t *restrict ret_day);
void seconds_to_time(utime_t seconds, uint8_t *restrict ret_hour, uint8_t *restrict ret_minute, uint8_t *restrict ret_second);

/*
* Timers
*/
// Calculate when a timer started now would expire.
#define SET_TIMEOUT_MS(delay) ((GET_SYSTICKS_MS()) + (delay))
//
// Check whether a timer set for some time has expired.
// Depending on the system, SYSTICKS may not update continuously (such as
// during low-power modes).
#define TIMES_UP(timer) (UNLIKELY((GET_SYSTICKS_MS()) >= (timer)))
//
// Like SET_TIMEOUT_MS() and TIMES_UP() but for working with timeouts that may
// span periods when systicks are unavailable, like a low power mode.
#define SET_RTC_TIMEOUT_S(delay) ((GET_RTCTICKS_S()) + (delay))
#define RTC_TIMES_UP(timer) (UNLIKELY((GET_RTCTICKS_S()) >= (timer)))
//
// A dumb timeout that counts loop iterations.
// Can't check (--(timer) <= 0) because that will rollover if timer is 0
// and unsigned.
// The timer variable should probably be declared volatile to keep the compiler
// from optimizing the loop out.
#define DUMB_TIMEOUT(timer) ((timer)-- == 0)


#endif // ULIB_ENABLE_TIME
#endif // _ULIB_TIME_H
#ifdef __cplusplus
 }
#endif
