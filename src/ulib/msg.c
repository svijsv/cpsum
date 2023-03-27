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
// msg.c
// Communicate with the user
// NOTES:
//
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "msg.h"
#if ULIB_ENABLE_MSG

#include "array.h"
#include "bits.h"
#include "buffer.h"
#include "cstrings.h"
#include "debug.h"
#include "strings.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#if MSG_USE_MALLOC
# include <stdlib.h>
#endif
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(O_DIRECT)
# define O_DIRECT 0
#endif
#if !defined(O_CLOEXEC)
# define O_CLOEXEC 0
#endif

// The only reason the msg_* stuff isn't in config is that config just uses
// the init structure to simplify things and I don't want the log fd and
// path in there.
static int msg_log_fd = -1;
static char msg_log_path[MSG_STR_BYTES];

#define DEFAULT_ERROR_PREFIX "ERROR: "
#define DEFAULT_WARN_PREFIX  "WARNING: "
#define DEFAULT_DEBUG_PREFIX  "DEBUG: "
// dd/mm/yyyy hh:mm:ss TZ
#define DEFAULT_TIME_FORMAT  "%x %X %Z"
#define DEFAULT_PROGRAM_NAME ""

#if MSG_USE_MALLOC
static char default_error_prefix[] = DEFAULT_ERROR_PREFIX;
static char default_warn_prefix[] = DEFAULT_WARN_PREFIX;
static char default_debug_prefix[] = DEFAULT_DEBUG_PREFIX;
static char default_time_format[] = DEFAULT_TIME_FORMAT;
static char default_program_name[] = DEFAULT_PROGRAM_NAME;
#endif

static msg_init_t config = {
	.stdin_fd = STDIN_FILENO,
	.stdout_fd = STDOUT_FILENO,
	.stderr_fd = STDERR_FILENO,
#if MSG_USE_MALLOC
	.error_prefix = default_error_prefix,
	.warn_prefix = default_warn_prefix,
	.debug_prefix = default_debug_prefix,
	.time_format = default_time_format,
	.program_name = default_program_name,
#else
	.error_prefix = DEFAULT_ERROR_PREFIX,
	.warn_prefix = DEFAULT_WARN_PREFIX,
	.debug_prefix = DEFAULT_DEBUG_PREFIX,
	.time_format = DEFAULT_TIME_FORMAT,
	.program_name = DEFAULT_PROGRAM_NAME,
#endif
};

int msg_puts(const char *s) {
	size_t len;
	ssize_t writ = 0;

	assert(s != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (s == NULL) {
		return -EINVAL;
	}
#endif

	len = strlen(s);
	do {
		if (writ > 0) {
			len -= (size_t )writ;
		}
		writ = write(config.stdout_fd, s, len);
	} while ((writ < (ssize_t )len) && ((writ != -1) || (errno == EINTR)));
	if (writ == -1) {
		return -errno;
	}

	return 0;
}
int msg_gets(char *restrict s, int size) {
	char b;
	ssize_t r;
	int have;

	assert(s != NULL);
	assert(size > 0);
#if DO_MSG_SAFETY_CHECKS
	if (s == NULL) {
		return -EINVAL;
	}
	if (size <= 0) {
		return -EINVAL;
	}
#endif

	size -= 1;
	for (have = 0; have < size;) {
		r = read(config.stdin_fd, &b, 1);
		if (r == -1) {
			if (errno != EINTR) {
				return -errno;
			}
		} else if ((r == 0) || (b == '\n') || (b == 0)) {
			break;
		} else if (b == '\r') {
			// Nothing to  do here.
		} else if (b == '\b') {
			if (have > 0) {
				--have;
				s[have] = 0;
			}
		} else {
			s[have] = b;
			++have;
		}
	}
	s[have] = 0;

	return have;
}

#if MSG_USE_MALLOC
static char* set_config_string(char *now, const char *new, const char *def) {
	if (new == NULL) {
		return now;
	}
	if ((now != def) && (now != NULL)) {
		free(now);
	}
	return strdup(new);
}
#else
// FIXME: Can't set any of these to an empty string...
static void set_config_string(char now[MSG_STR_BYTES], char new[MSG_STR_BYTES]) {
	//assert(new != NULL);

	if (new[0] == 0) {
		return;
	}
	strncpy(now, new, MSG_STR_BYTES);

	return;
}
#endif
int msg_init(msg_init_t *init) {
	assert(init != NULL);

#if DO_MSG_SAFETY_CHECKS
	if (init == NULL) {
		return 0;
	}
#endif

	config.verbosity = init->verbosity;
	config.flags = init->flags;

	if (init->stdin_fd >= 0) {
		config.stdin_fd = init->stdin_fd;
	}
	if (init->stdout_fd >= 0) {
		config.stdout_fd = init->stdout_fd;
	}
	if (init->stderr_fd >= 0) {
		config.stderr_fd = init->stderr_fd;
	}

#if MSG_USE_MALLOC
	config.warn_prefix = set_config_string(config.warn_prefix, init->warn_prefix, default_warn_prefix);
	config.debug_prefix = set_config_string(config.debug_prefix, init->debug_prefix, default_debug_prefix);
	config.error_prefix = set_config_string(config.error_prefix, init->error_prefix, default_error_prefix);
	config.time_format = set_config_string(config.time_format, init->time_format, default_time_format);
	config.program_name = set_config_string(config.program_name, init->program_name, default_program_name);
#else
	set_config_string(config.warn_prefix, init->warn_prefix);
	set_config_string(config.debug_prefix, init->debug_prefix);
	set_config_string(config.error_prefix, init->error_prefix);
	set_config_string(config.time_format, init->time_format);
	set_config_string(config.program_name, init->program_name);
#endif

	return 0;
}

int msg_open_log(const char* path) {
	int o_flags = O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC;

	assert(path != NULL);

#if DO_MSG_SAFETY_CHECKS
	if (path == NULL) {
		return -EINVAL;
	}
#endif

	if (BIT_IS_SET(config.flags, MSG_LOG_DIRECT)) {
		SET_BIT(o_flags, O_DIRECT);
	}

	if (msg_log_fd != -1) {
		// TODO: Should errors here be reported?
		close(msg_log_fd);
	}
	do {
		msg_log_fd = open(path, o_flags, 0755);
	} while ((msg_log_fd == -1) && (errno == EINTR));
	if (msg_log_fd == -1) {
		int ret = -errno;

		msg_liberrno(errno, "%s: failed to open log file", path);
		return ret;
	}

	strncpy(msg_log_path, cstring_basename(path), sizeof(msg_log_path));

	return 0;
}
int msg_close_log(void) {
	if (msg_log_fd != -1) {
		if (close(msg_log_fd) == -1) {
			int ret = -errno;

			msg_liberrno(errno, "%s: close() error", msg_log_path);
			return ret;
		}
	}

	return 0;
}

bool msg_ask(bool ans_default, bool ans_forced, const char *restrict fmt, ...) {
	va_list args;
	char answer[8] = { 0 };
	bool ans;

	assert(fmt != NULL);

	if (BIT_IS_SET(config.flags, MSG_FORCE)) {
		ans = ans_forced;
	} else {
		ans = ans_default;
	}

#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return ans;
	}
#endif
	if (!BIT_IS_SET(config.flags, MSG_INTERACT)) {
		return ans;
	}

	va_start(args, fmt);
	vdprintf(config.stdout_fd, fmt, args);
	va_end(args);

	while (true) {
		if (ans) {
			msg_puts(" (YES/no) ");
		} else {
			msg_puts(" (yes/NO) ");
		}

		msg_gets(answer, 8);
		switch (answer[0]) {
			case 'y':
			case 'Y':
				return true;
				break;
			case 'n':
			case 'N':
				return false;
				break;
			case 0:
			case '\n':
				return ans;
				break;
		}
	}

	return ans;
}

const char* msg_print_time(time_t t, const char *fmt) {
	size_t writ;
	struct tm* tm;
	static buffer_t buf = { 0 };
	const buffer_init_t buf_init = {
		.initial_size = 32,
	};

	if (buf.allocated == 0) {
		buffer_init(&buf, &buf_init);
	}

	if (t == 0) {
		t  = time(NULL);
	}
	if (fmt == NULL) {
		fmt = config.time_format;
	}

	tm = localtime(&t);
	do {
		writ = strftime((char *)buf.bank, buf.allocated, fmt, tm);
		if ((writ == 0) && (buffer_grow(&buf, 0) == 0)) {
			buf.bank[buf.allocated-1] = 0;
			goto END;
		}
	} while (writ == 0);

END:
	return (char *)buf.bank;
}

void msg_log(const char *restrict fmt, ...) {
	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (msg_log_fd != -1) {
		va_list args;

		if (BIT_IS_SET(config.flags, MSG_LOG_PRINTTIME)) {
			dprintf(msg_log_fd, "[%s] ", msg_print_time(0, NULL));
		}

		va_start(args, fmt);
		vdprintf(msg_log_fd, fmt, args);
		va_end(args);

		write(msg_log_fd, "\n", 1);
	}

	return;
}

void msg_error(const char *restrict fmt, ...) {
	va_list args;

	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (config.program_name[0] != 0) {
		dprintf(config.stderr_fd, "%s: ", config.program_name);
	}
	if (config.error_prefix[0] != 0) {
		dprintf(config.stderr_fd, "%s", config.error_prefix);
	}

	va_start(args, fmt);
	vdprintf(config.stderr_fd, fmt, args);
	va_end(args);

	write(config.stderr_fd, "\n", 1);

	return;
}

static void _msg_errno(int errnum, const char *restrict fmt, va_list args) {
	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (config.program_name[0] != 0) {
		dprintf(config.stderr_fd, "%s: ", config.program_name);
	}
	if (config.error_prefix[0] != 0) {
		dprintf(config.stderr_fd, "%s", config.error_prefix);
	}

	vdprintf(config.stderr_fd, fmt, args);
	dprintf(config.stderr_fd, ": %s.\n", strerror(errnum));

	return;
}
void msg_errno(int errnum, const char *restrict fmt, ...) {
	va_list args;

	va_start(args, fmt);
	_msg_errno(errnum, fmt, args);
	va_end(args);

	return;
}
void msg_liberrno(int errnum, const char *restrict fmt, ...) {
	if (BIT_IS_SET(config.flags, MSG_LIBERRORS)) {
		va_list args;

		va_start(args, fmt);
		_msg_errno(errnum, fmt, args);
		va_end(args);
	}

	return;
}

void msg_warnno(int errnum, const char *restrict fmt, ...) {
	va_list args;

	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (config.program_name[0] != 0) {
		dprintf(config.stderr_fd, "%s: ", config.program_name);
	}
	if (config.warn_prefix[0] != 0) {
		dprintf(config.stderr_fd, "%s", config.warn_prefix);
	}

	va_start(args, fmt);
	vdprintf(config.stderr_fd, fmt, args);
	va_end(args);
	dprintf(config.stderr_fd, "%s.\n", strerror(errnum));

	return;
}
void msg_warn(const char *restrict fmt, ...) {
	va_list args;

	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (config.program_name[0] != 0) {
		dprintf(config.stderr_fd, "%s: ", config.program_name);
	}
	if (config.warn_prefix[0] != 0) {
		dprintf(config.stderr_fd, "%s", config.warn_prefix);
	}

	va_start(args, fmt);
	vdprintf(config.stderr_fd, fmt, args);
	va_end(args);

	write(config.stderr_fd, "\n", 1);

	return;
}

void msg_print(int8_t priority, const char *restrict fmt, ...) {
	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (priority <= config.verbosity) {
		va_list args;

		if (config.program_name[0] != 0) {
			dprintf(config.stdout_fd, "%s: ", config.program_name);
		}

		va_start(args, fmt);
		vdprintf(config.stdout_fd, fmt, args);
		va_end(args);

		write(config.stdout_fd, "\n", 1);
	}

	return;
}
void msg_debug(const char *restrict fmt, ...) {
#if DEBUG
	va_list args;

	assert(fmt != NULL);
#if DO_MSG_SAFETY_CHECKS
	if (fmt == NULL) {
		return;
	}
#endif

	if (config.program_name[0] != 0) {
		dprintf(config.stderr_fd, "%s: ", config.program_name);
	}
	if (config.debug_prefix[0] != 0) {
		dprintf(config.stderr_fd, "%s", config.debug_prefix);
	}

	va_start(args, fmt);
	vdprintf(config.stderr_fd, fmt, args);
	va_end(args);

	write(config.stderr_fd, "\n", 1);
#else // !DEBUG
	UNUSED(fmt);
#endif

	return;
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_MSG
#ifdef __cplusplus
 }
#endif
