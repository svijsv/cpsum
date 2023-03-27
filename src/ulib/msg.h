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
// msg.h
// Communicate with the user
// NOTES:
//    This is very much *not* thread-safe.
//
//    Unless otherwise noted, functions which return an error code return
//    -errno where 'errno' is the errno number corresponding to the problem
//    encountered.
//
// BUGS:
//    When not using malloc(), the prefix and format strings can't be set to
//    an empty string because that's taken to mean leave the value alone.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_MSG_H
#define _ULIB_MSG_H

#include "configify.h"
#if ULIB_ENABLE_MSG

#include "types.h"

#include <time.h>

/*
 * Named verbosity levels
 */
#define MSG_VERB_ERR   -2
#define MSG_VERB_WARN  -1
#define MSG_VERB_NORM   0
#define MSG_VERB_INFO   1
#define MSG_VERB_EXTRA  2
#define MSG_VERB_TMI    3

/*
 * Flags passed to msg_init() to change msg.c behavior
 */
// Set forced mode for questions
#define MSG_FORCE         0x01
// Set interactive mode for questions
#define MSG_INTERACT      0x02
// Allow modules to print error messages
#define MSG_LIBERRORS     0x04
// Print the time before log messages
#define MSG_LOG_PRINTTIME 0x08
// Use direct I/O when writing to log files
#define MSG_LOG_DIRECT    0x10

/*
 * Structure passed to msg_init() to initialize the module.
 */
typedef struct {
	// FD used for stdin; defaults to STDIN_FILENO. Set to -1 to ignore.
	int stdin_fd;
	// FD used for stdout; defaults to STDOUT_FILENO. Set to -1 to ignore.
	int stdout_fd;
	// FD used for stderr; defaults to STDERR_FILENO. Set to -1 to ignore.
	int stderr_fd;
	// Verbosity level for printing messages; default is 0.
	int8_t verbosity;
	// Behavior-modifying flags; defaults to 0.
	uint8_t flags;
#if MSG_USE_MALLOC
	// Prefix used before warning messages; defaults to "WARNING: ". Set to
	// NULL to ignore.
	char *warn_prefix;
	// Prefix used before error messages; defaults to "ERROR: ". Set to NULL
	// to ignore.
	char *error_prefix;
	// Prefix used before debug messages; defaults to "DEBUG: ". Set to NULL
	// to ignore.
	char *debug_prefix;
	// Format used when printing the time; defaults to "%x %X %Z". Set to NULL
	// to ignore.
	char *time_format;
	// Name of the program printed before messages; defaults to none. Set to
	// NULL to ignore or empty string to disable.
	char *program_name;
#else
	// Same as above but set to an empty string to ignore.
	char warn_prefix[MSG_STR_BYTES];
	char error_prefix[MSG_STR_BYTES];
	char time_format[MSG_STR_BYTES];
	char program_name[MSG_STR_BYTES];
#endif
} msg_init_t;

/*
 * msg_init()
 * Set up the message system.
 *
 * This doesn't need to be called unless changing from the defaults, which
 * are defined in msg.c.
 *
 * Can be called repeatedly without issues.
 *
 * The return value is always 0.
 */
int msg_init(msg_init_t *init);

/*
 * msg_open_log()
 * Open a log file.
 *
 * If a log file is already opened, it's closed before opening the new one.
 * The log is always opened in append mode.
 */
int msg_open_log(const char* path);
/*
 * msg_close_log()
 * Close the log file.
 *
 * If no log file is open, return successfully.
 */
int msg_close_log(void);

/*
 * msg_ask()
 * Ask a yes/no question.
 *
 * Keeps asking until either 'y' or 'n' are the first letter of the response,
 * or until a blank response is given and the default used.
 *
 * If MSG_FORCE is set, the default answer is ans_force. Otherwise it's ans_default.
 * If MSG_INTERACT isn't set, retuns immediately with the default answer.
 */
bool msg_ask(bool ans_default, bool ans_forced, const char *restrict fmt, ...)
	__attribute__ ((format(printf, 3, 4)));

/*
 * msg_print_time()
 * Print the current time to a string.
 *
 * If 't' is 0, use the current time.
 * If 'fmt' is NULL, use the default set in msg.c.
 *
 * The returned string is internal to msg_print_time() and should be copied
 * before another call to the function.
 */
const char* msg_print_time(time_t t, const char *fmt);

/*
 * msg_log()
 * Print a message to the log.
 *
 * If there is no log opened, nothing is done.
 * If MSG_PRINTTIME is set, the message is prefixed by the current time.
 */
void msg_log(const char *restrict fmt, ...)
	__attribute__ ((format(printf, 1, 2)));

/*
 * msg_error()
 * Print an error message to stderr, followed by a newline.
 *
 * Messages are prefixed with the string set in msg_init().
 * If MSG_PRINTNAME is set and PROGRAM_NAME is defined, messages are prefixed
 * with 'PROGRAM_NAME: '.
 */
void msg_error(const char *restrict fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
/*
 * msg_errno()
 * Print an error message to stderr.
 *
 * Same as msg_error(), but after printing the message the result of strerror(errnum)
 * is printed in the format ': %s.\n'
 */
void msg_errno(int errnum, const char *restrict fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
/*
 * msg_liberrno()
 * Print an error message to stderr.
 *
 * Same as msg_errno(), but output is disabled unless MSG_LIBERRORS is set.
 */
void msg_liberrno(int errnum, const char *restrict fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
/*
 * msg_warn()
 * Print a warning message to stderr, followed by a newline.
 *
 * Same as msg_error() but prefixed with the warning prefix.
 */
void msg_warn(const char *restrict fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
/*
 * msg_warnno()
 * Print a warning message to stderr, followed by a newline.
 *
 * Same as msg_errno() but prefixed with the warning prefix.
 */
void msg_warnno(int errnum, const char *restrict fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
/*
 * msg_debug()
 * Print a string to stderr if the macro DEBUG is non-zero.
 */
void msg_debug(const char *restrict fmt, ...)
	__attribute__ ((format(printf, 1, 2)));
/*
 * msg_print()
 * Print a message to stdout.
 *
 * If MSG_PRINTNAME is set and PROGRAM_NAME is defined, messages are prefixed
 * with 'PROGRAM_NAME: '.
 *
 * Nothing is printed unless priority <= msg_verbosity.
 */
void msg_print(int8_t priority, const char *restrict fmt, ...)
	__attribute__ ((format(printf, 2, 3)));
// This may be more efficient, but not majorly so (and I'd have to export msg_verbosity).
//#define msg_print(priority, ...) (if (priority <= msg_verbosity) _msg_print( ## __VA_ARGS__);)
/*
 * msg_puts()
 * Print a string to stdout
 *
 * This differs from puts() in that no trailing newline is printed and the
 * return value is -errno on error.
 */
int msg_puts(const char *s);
/*
 * msg_gets()
 * Retrieve a string from stdin
 *
 * This behaves like fgets() except for the return value, that any trailing
 * newline is *not* stored in the string, and that reading stops if a NUL
 * byte is recieved.
 *
 * The return value is the number of non-NUL bytes placed in the string on
 * success or -errno on error.
 */
int msg_gets(char *s, int size);

#endif // _ULIB_MSG_H
#endif // ULIB_ENABLE_MSG
#ifdef __cplusplus
 }
#endif
