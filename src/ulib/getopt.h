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
// getopt.h
// Parse command-line options
// NOTES:
//    This is not unicode-aware. Not even close.
//
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_GETOPT_H
#define _ULIB_GETOPT_H

#include "configify.h"
#if ULIB_ENABLE_GETOPT

#include "types.h"

#include <stdio.h>


// The type used to iterate through options. The max of this type determines
// the maximum size of strings in argv and the maximum number of strings in
// argv.
// To simplify things, use an int that allows adding 1 to the maximum size
// without overflowing.
#if OPT_LEN_MAX < 0xFFU
 typedef uint8_t opt_iter_t;
#elif OPT_LEN_MAX < 0xFFFFU
 typedef uint16_t opt_iter_t;
#elif OPT_LEN_MAX < 0xFFFFFFFFU
 typedef uint32_t opt_iter_t;
#elif OPT_LEN_MAX < 0xFFFFFFFFFFFFFFFFU
 typedef uint64_t opt_iter_t;
#else
# error "OPT_LEN_MAX is too big"
#endif

//
// Option flags for opt_option_t.pflags.
//
typedef uint_fast8_t opt_pflags_t;
// The option has no arguments.
static const opt_pflags_t OPT_ARG_NONE     = 0x01U;
// The option requires an argument.
static const opt_pflags_t OPT_ARG_REQUIRED = 0x02U;
// The option may be given an argument.
static const opt_pflags_t OPT_ARG_ACCEPTED = 0x04U;

//
// Structure for defining options.
//
typedef struct {
	// The single-character flag representing an option. This is also the value
	// returned when the option is found, so options with only long names must
	// be set to non-printing characters.
	// 0 is reserved to mark the end of opt_option_t arrays.
	// Values < 0 are reserved for special return codes.
	signed char oflag;
	// The long name of an option. If NULL, there is none.
	char *long_name;
	// Option flags for the parser. See definitions above.
	// Exactly one of OPT_ARG_NONE, OPT_ARG_REQUIRED, or OPT_ARG_ACCEPTED must
	// be set.
	opt_pflags_t pflags;
	// The description printed from opt_print_help().
	char   *desc;
} opt_option_t;
//
// Option flags for opt_ctx_t.flags.
//
typedef uint_fast8_t opt_ctxflags_t;
// Disable option parsing - all encountered strings are treated as arguments
// while this is set.
static const opt_ctxflags_t OPT_PARSE_DISABLE_OPTIONS      = 0x01U;
// If the string '--' is encountered set OPT_PARSE_DISABLE_OPTIONS.
static const opt_ctxflags_t OPT_PARSE_AUTO_DISABLE_OPTIONS = 0x02U;
// If the string '++' is encountered unset OPT_PARSE_DISABLE_OPTIONS.
static const opt_ctxflags_t OPT_PARSE_AUTO_ENABLE_OPTIONS  = 0x04U;
// Options can be preceded by '-' or '+' instead of just '-'.
static const opt_ctxflags_t OPT_PARSE_ALLOW_PLUS           = 0x08U;

//
// Structure for storing parser state.
//
typedef struct {
	//
	// These fields must be cleared before first using the opt_ctx_t structure.
	//
	// Current position within argv.
	opt_iter_t pos;
	// Current position within the current word.
	opt_iter_t wpos;
	//
	// These fields must be set before first using the opt_ctx_t structure.
	//
	// Option flags for the parser itself.
	// These can be updated by the caller at any point during parsing if a
	// change in behavior is desired.
	opt_ctxflags_t flags;
	// An array of strings, each representing one word from the command line.
	// This differs from the argv parameter from main() in that the first string
	// is assumed to be valid rather than the program's name - use &argv[1] to
	// convert main()'s to this one.
	// NULL strings are skipped.
	char **argv;
	// The number of strings in argv. Use argc-1 to convert from main()'s argc
	// to this one.
	opt_iter_t argc;
	// An array of opt_option_t objects describing the desired options with the final
	// object having it's oflag field set to 0.
	const opt_option_t *opts;
	//
	// These fields hold the details of the most recent match.
	//
	// The argument associated with the option. NULL if there is none.
	// If OPT_ARGUMENT is returned, this is the argument that provoked it.
	const char *arg;
	// The index of the option in opts[].
	opt_iter_t opts_i;
	// Prefix of seen option ('-' or '+').
	char prefix;
} opt_ctx_t;

//
// Return values for opt_getopt().
//
// No more options to parse
#define OPT_DONE      0
// Matched an argument instead of an option
#define OPT_ARGUMENT -1
// General error
#define OPT_ERROR    -2
// Unrecognized option
#define OPT_ERROR_UNRECOGNIZED -3
// Recognized option requires an argument but none was found
#define OPT_ERROR_MISSING_ARG -4
// Recognized option can't take an argument but one was supplied
#define OPT_ERROR_EXTRA_ARG -5

// Parse a command line described in an opt_ctx_t structure.
// The return value is either the oflag field of the matched opt_option_t structure
// or one of the codes defined above.
int opt_getopt(opt_ctx_t *ctx);
//
// Print a help message based on the information in an opt_option_t structure.
// prefix is printed before each line. It can't be NULL but can be an empty string ("").
// postfix is printed after each description. It can't be NULL but can be an empty string ("").
// opts is as with the opts field of the opt_ctx_t structure.
void opt_print_help(const char *prefix, const char *postfix, const opt_option_t *opts);


#endif // ULIB_ENABLE_GETOPT
#endif // _ULIB_GETOPT_H
#ifdef __cplusplus
 }
#endif
