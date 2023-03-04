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
// getopt.c
// Parse command-line options
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "getopt.h"
#if ULIB_ENABLE_GETOPT

#include "bits.h"
#include "cstrings.h"
#include "debug.h"
#include "msg.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


static int _opt_find_flag(opt_ctx_t *ctx) {
	opt_iter_t i;
	int c;

	assert(POINTER_IS_VALID(ctx));
	assert(POINTER_IS_VALID(ctx->argv));
	assert(POINTER_IS_VALID(ctx->opts));

#if DO_OPT_SAFETY_CHECKS
	if (!POINTER_IS_VALID(ctx)) {
		return OPT_DONE;
	}
	if (!POINTER_IS_VALID(ctx->argv)) {
		return OPT_DONE;
	}
	if (!POINTER_IS_VALID(ctx->opts)) {
		return OPT_DONE;
	}
#endif

	c = ctx->argv[ctx->pos][ctx->wpos];
	++ctx->wpos;

	for (i = 0; ctx->opts[i].oflag != 0; ++i) {
		if (c != ctx->opts[i].oflag) {
			continue;
		}

		ctx->opts_i = i;
		ctx->arg = NULL;
		if (BIT_IS_SET(ctx->opts[i].pflags, OPT_ARG_REQUIRED)) {
			if (ctx->argv[ctx->pos][ctx->wpos] != 0) {
				ctx->arg = &ctx->argv[ctx->pos][ctx->wpos];
				++ctx->pos;
				ctx->wpos = 0;
			} else if ((ctx->pos+1 < ctx->argc) && (ctx->argv[ctx->pos+1] != NULL)) {
				ctx->arg = ctx->argv[ctx->pos+1];
				ctx->pos += 2;
				ctx->wpos = 0;
			} else {
				++ctx->pos;
				ctx->wpos = 0;
				return OPT_ERROR_MISSING_ARG;
			}
		} else if (BIT_IS_SET(ctx->opts[i].pflags, OPT_ARG_ACCEPTED)) {
			if (ctx->argv[ctx->pos][ctx->wpos] != 0) {
				ctx->arg = &ctx->argv[ctx->pos][ctx->wpos];
			}
			++ctx->pos;
			ctx->wpos = 0;
		} else if (ctx->argv[ctx->pos][ctx->wpos] == 0) {
			++ctx->pos;
			ctx->wpos = 0;
		}

		return ctx->opts[i].oflag;
	}

	return OPT_ERROR_UNRECOGNIZED;
}

static int _opt_find_word(opt_ctx_t *ctx) {
	opt_iter_t i, len;
	const char* word;

	assert(POINTER_IS_VALID(ctx));
	assert(POINTER_IS_VALID(ctx->argv));
	assert(POINTER_IS_VALID(ctx->opts));

#if DO_OPT_SAFETY_CHECKS
	if (!POINTER_IS_VALID(ctx)) {
		return OPT_DONE;
	}
	if (!POINTER_IS_VALID(ctx->argv)) {
		return OPT_DONE;
	}
	if (!POINTER_IS_VALID(ctx->opts)) {
		return OPT_DONE;
	}
#endif

	// Skip the leading '--'/'++'.
	word = ctx->argv[ctx->pos] + 2;

	// We won't need these here so get ready for the next word now so we can
	// return as we're ready to instead of using a single return point.
	ctx->wpos = 0;
	++ctx->pos;

	for (len = 0; ((word[len] != 0) && (word[len] != '=')); ++len) {};
	if (word[len] == '=') {
		ctx->arg = &word[len+1];
	} else {
		ctx->arg = NULL;
	}

	for (i = 0; ctx->opts[i].oflag != 0; ++i) {
		if ((ctx->opts[i].long_name == NULL) || (!cstring_eqn(ctx->opts[i].long_name, word, len) || (ctx->opts[i].long_name[len] != 0))) {
			continue;
		}

		ctx->opts_i = i;

		if (BIT_IS_SET(ctx->opts[i].pflags, OPT_ARG_NONE)) {
			if (ctx->arg != NULL) {
				return OPT_ERROR_EXTRA_ARG;
			}
		} else if (BIT_IS_SET(ctx->opts[i].pflags, OPT_ARG_REQUIRED) && (ctx->arg == NULL)) {
			if ((ctx->pos >= ctx->argc) || (ctx->argv[ctx->pos] == NULL)) {
				return OPT_ERROR_MISSING_ARG;
			}
			ctx->arg = ctx->argv[ctx->pos];
			++ctx->pos;
		}

		return ctx->opts[i].oflag;
	}

	return OPT_ERROR_UNRECOGNIZED;
}

int opt_getopt(opt_ctx_t *ctx) {
	assert(POINTER_IS_VALID(ctx));
	assert(POINTER_IS_VALID(ctx->argv));
	assert(POINTER_IS_VALID(ctx->opts));

#if DO_OPT_SAFETY_CHECKS
	if (!POINTER_IS_VALID(ctx)) {
		return OPT_DONE;
	}
	if (!POINTER_IS_VALID(ctx->argv)) {
		return OPT_DONE;
	}
	if (!POINTER_IS_VALID(ctx->opts)) {
		return OPT_DONE;
	}
#endif

	while (ctx->pos < ctx->argc) {
		if (ctx->argv[ctx->pos] == NULL) {
			ctx->wpos = 0;
			++ctx->pos;
			continue;
		}
		if (ctx->argv[ctx->pos][ctx->wpos] == 0) {
			ctx->wpos = 0;
			++ctx->pos;
			continue;
		}

		if (BIT_IS_SET(ctx->flags, OPT_PARSE_DISABLE_OPTIONS)) {
			const char *c = &ctx->argv[ctx->pos][0];

			if (BIT_IS_SET(ctx->flags, OPT_PARSE_AUTO_ENABLE_OPTIONS) && (c[0] == '+') && (c[1] == '+') && (c[2] == 0)) {
				CLEAR_BIT(ctx->flags, OPT_PARSE_DISABLE_OPTIONS);
				++ctx->pos;
				return opt_getopt(ctx);
			} else {
				ctx->arg = &ctx->argv[ctx->pos][ctx->wpos];
				++ctx->pos;
				ctx->wpos = 0;
				return OPT_ARGUMENT;
			}
		}

		if (ctx->wpos == 0) {
			// Make things simpler by pre-handling the one-character argument
			// condition.
			if (ctx->argv[ctx->pos][1] == 0) {
				ctx->arg = ctx->argv[ctx->pos];
				++ctx->pos;
				return OPT_ARGUMENT;
			} else if (ctx->argv[ctx->pos][2] == 0) {
				if (BIT_IS_SET(ctx->flags, OPT_PARSE_AUTO_DISABLE_OPTIONS) && (ctx->argv[ctx->pos][0] == '-') && (ctx->argv[ctx->pos][1] == '-')) {
					SET_BIT(ctx->flags, OPT_PARSE_DISABLE_OPTIONS);
					++ctx->pos;
					return opt_getopt(ctx);
				}
			}

			if ((ctx->argv[ctx->pos][0] == '-') || (BIT_IS_SET(ctx->flags, OPT_PARSE_ALLOW_PLUS) && (ctx->argv[ctx->pos][0] == '+'))) {
				ctx->prefix = ctx->argv[ctx->pos][0];
				if (ctx->argv[ctx->pos][1] == ctx->argv[ctx->pos][0]) {
					return _opt_find_word(ctx);
				} else {
					++ctx->wpos;
					return _opt_find_flag(ctx);
				}
			} else {
				ctx->arg = ctx->argv[ctx->pos];
				++ctx->pos;
				return OPT_ARGUMENT;
			}
		} else {
			return _opt_find_flag(ctx);
		}
	}

	return OPT_DONE;
}

void opt_print_help(const char *prefix, const char *postfix, const opt_option_t *opts) {
	uint16_t i;
	const char *char_lead, *word_lead, *char_arg, *long_name_arg;

	assert(POINTER_IS_VALID(prefix));
	assert(POINTER_IS_VALID(postfix));
	assert(POINTER_IS_VALID(opts));

#if DO_OPT_SAFETY_CHECKS
	if (!POINTER_IS_VALID(prefix)) {
		prefix = "";
	}
	if (!POINTER_IS_VALID(postfix)) {
		postfix = "";
	}
	if (!POINTER_IS_VALID(opts)) {
		return;
	}
#endif

	char_lead = "-";
	word_lead = "--";
	for (i = 0; opts[i].oflag != 0; ++i) {
		/*
		if (BIT_IS_SET(opts[i].pflags, OPT_ALLOW_INVERT)) {
			char_lead = "[-|+]";
			word_lead = "[--|++]";
		} else {
			char_lead = "-";
			word_lead = "--";
		}
		*/

		if (BIT_IS_SET(opts[i].pflags, OPT_ARG_NONE)) {
			char_arg = "";
			long_name_arg = "";
		} else if (BIT_IS_SET(opts[i].pflags, OPT_ARG_REQUIRED)) {
			char_arg = " ARG";
			long_name_arg = " ARG";
		} else if (BIT_IS_SET(opts[i].pflags, OPT_ARG_ACCEPTED)) {
			char_arg = "[ARG]";
			long_name_arg = "[=ARG]";
		} else {
			char_arg = "";
			long_name_arg = "";
		}

		if (isprint(opts[i].oflag) && ((opts[i].long_name != NULL) && (opts[i].long_name[0] != 0))) {
			msg_print(-100, "%s%s%c%s, %s%s%s", prefix, char_lead, opts[i].oflag, char_arg, word_lead, opts[i].long_name, long_name_arg);
		} else if (isprint(opts[i].oflag)) {
			msg_print(-100, "%s%s%c%s", prefix, char_lead, opts[i].oflag, char_arg);
		} else if ((opts[i].long_name != NULL) && (opts[i].long_name[0] != 0)) {
			msg_print(-100, "%s%s%s%s", prefix, word_lead, opts[i].long_name, long_name_arg);
		}
		if (opts[i].desc != NULL) {
			msg_print(-100, "%s    %s%s", prefix, opts[i].desc, postfix);
		}
	}

	return;
}

#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_GETOPT
#ifdef __cplusplus
 }
#endif
