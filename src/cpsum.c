/***********************************************************************
*                                                                      *
*                                                                      *
* Copyright 2018, 2022, 2023 svijsv                                    *
* This program is free software: you can redistribute it and/or modify *
* it under the terms of the GNU General Public License as published by *
* the Free Software Foundation, version 2 of the License.              *
*                                                                      *
* This program is distributed in the hope that it will be useful, but  *
* WITHOUT ANY WARRANTY; without even the implied warranty of           *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU    *
* General Public License for more details.                             *
*                                                                      *
* You should have received a copy of the GNU General Public License    *
* along with this program.  If not, see <http://www.gnu.org/licenses/>.*
*                                                                      *
*                                                                      *
***********************************************************************/
#include "config.h"

#include "gnulib/md5.h"
#include "gnulib/sha1.h"
#include "gnulib/sha256.h"
#include "gnulib/sha512.h"
#include "ulib/array.h"
#include "ulib/bits.h"
#include "ulib/debug.h"
#include "ulib/files.h"
#include "ulib/getopt.h"
#include "ulib/list.h"
#include "ulib/msg.h"
#include "ulib/strings.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#if !defined(ABS)
# define ABS(_n) ((_n < 0) ? -_n : _n)
#endif

typedef uint_fast32_t flag_t;
//
// Flags for program options
// Reserve top 2 bytes for behavior flags.
//
//static const flag_t OPT_UNLINK      = 0x000001U;
static const flag_t OPT_PARENTS       = 0x000002U;
static const flag_t OPT_NOCLOBBER     = 0x000004U;
//static const flag_t OPT_BACKUP      = 0x000008U;
static const flag_t OPT_INTERACTIVE   = 0x000010U;
static const flag_t OPT_FOLLOW_LINKS = 0x000020U;
static const flag_t OPT_FOLLOW_INITIAL_LINKS = 0x000040U;
//static const flag_t OPT_HARDLINK    = 0x000080U;
static const flag_t OPT_UPDATE        = 0x000100U;
static const flag_t OPT_NOXDEV        = 0x000200U;
//static const flag_t OPT_ = 0x000400U;
//static const flag_t OPT_ = 0x000800U;
static const flag_t OPT_SYNC_AFTER    = 0x002000U;
static const flag_t OPT_COPY_CONTENTS = 0x004000U;
static const flag_t OPT_BACKUP_DEST   = 0x008000U;
static const flag_t OPT_INCR_BACKUP   = 0x010000U;
//
// Flags for program behavior
//
//static const flag_t FLAG_TRACK_HASH_MASK = 0xFF000000U;
static const flag_t FLAG_TRACK_MD5       = 0x01000000U;
static const flag_t FLAG_TRACK_SHA1      = 0x02000000U;
static const flag_t FLAG_TRACK_SHA224    = 0x04000000U;
static const flag_t FLAG_TRACK_SHA256    = 0x08000000U;
static const flag_t FLAG_TRACK_SHA384    = 0x10000000U;
static const flag_t FLAG_TRACK_SHA512    = 0x20000000U;

//
// Codes used for option parsing (and a few other things).
// Must be a non-printing ascii character or one that won't be used as a flag
// or string format specifier, so stick to >0 and <=32 or >256.
//
#define CODE_MD5    1
#define CODE_SHA1   2
#define CODE_SHA224 3
#define CODE_SHA256 4
#define CODE_SHA384 5
#define CODE_SHA512 6
#define CODE_MD5_VERIFY    7
#define CODE_SHA1_VERIFY   8
#define CODE_SHA224_VERIFY 9
#define CODE_SHA256_VERIFY 10
#define CODE_SHA384_VERIFY 11
#define CODE_SHA512_VERIFY 12
#define CODE_VERIFY_FORMAT 13
#define CODE_VERIFY_FILE   14
#define CODE_SYNC_AFTER    15
#define CODE_SYNC_DURING   16
#define CODE_MAX_ERRORS    17
#define CODE_PARENTS       18
#define CODE_COPY_CONTENTS 19
#define CODE_MAX_WARNINGS  20
#define CODE_SET_TEMP_EXT  21
#define CODE_INCR_BACKUP   22
#define CODE_MAX_FAILED    23

//
// Report a warning/error and increment the count
#define ERROR(...) do { msg_error(__VA_ARGS__); ++g_error_count; abort_for_errors(); } while (0);
#define ERROR_NO(...) do { msg_errno(__VA_ARGS__); ++g_error_count; abort_for_errors(); } while (0);
#define WARNING(...) do { msg_warn(__VA_ARGS__); ++g_warning_count; abort_for_errors(); } while (0);
#define WARNING_NO(...) do { msg_warnno(__VA_ARGS__); ++g_warning_count; abort_for_errors(); } while (0);
#define FAILED(...) do { msg_warn(__VA_ARGS__); ++g_failed_count; abort_for_errors(); } while (0);

//
// Common assertions
#define ASSERT_PATH(_p) assert((_p != NULL) && (_p[0] != 0))
#define ASSERT_FD(_fd) assert((_fd >= 0))
#define ASSERT_BUF(_buf, _siz) assert((_buf != NULL) && (_siz > 0))
#define ASSERT_CTX(_ctx) assert( \
	(_ctx != NULL) && \
	(_ctx->paths != NULL) && \
	(_ctx->paths->src_path != NULL) && \
	(_ctx->paths->dest_path != NULL) \
	)

static const char *g_program_name = "cpsum";
static string_t *g_temp_ext = NULL;
static string_t *g_backup_ext = NULL;
// 2 seconds is the timestamp resolution for FAT32 filesystems.
static time_t g_update_time_fudge_seconds = 2;
static uint8_t *g_copy_buffer = NULL;
static int g_verbosity = 0;

static uint16_t g_max_errors    = 0xFFFF;
static uint16_t g_max_warnings  = 0xFFFF;
static uint16_t g_max_failed    = 0xFFFF;
static uint16_t g_error_count   = 0;
static uint16_t g_warning_count = 0;
static uint16_t g_failed_count  = 0;
static uint16_t g_unverified_count = 0;
static uint64_t g_total_bytes   = 0;
static uint32_t g_total_files   = 0;
static jmp_buf g_abort_jmp;

static void abort_for_errors(void);
static uint8_t hash_digest_size(uint8_t code);
static uint8_t hash_char_buffer_size(uint8_t code);
static uint8_t match_hash_name(const char *name, size_t *cnt);
static uint8_t hex_to_nibble(char digit);
static void cache_fmt_str(array_t *cache, const char *fmtstr);
static void show_help(const opt_option_t *options);

//
// Structure for managing file paths.
//
typedef struct {
	// The full path of the source file.
	string_t *src_path;
	// The root path of the source file.
	string_t *src_root;
	// The non-root part of the source path.
	string_t *src_affix;
	// The full path of the destination file.
	string_t *dest_path;
	// The root path of the destination file.
	string_t *dest_root;
	// The non-root part of the destination path.
	string_t *dest_affix;
} copy_path_t;
//
// Structure for managing directory descent.
//
typedef struct {
	struct stat st;
	DIR *dir;
} cwd_t;
void free_cwd(void *ptr) {
	cwd_t *cwd = ptr;

	if (ptr == NULL) {
		return;
	}

	if (cwd->dir != NULL) {
		if (closedir(cwd->dir) < 0) {
			ERROR_NO(errno, "directory close error");
		}
	}
	free(cwd);

	return;
}
//
// Structures for managing output checksum files.
//
typedef struct {
	int fmt_code;
	string_t *str;
} fmt_cache_t;
typedef struct {
	int   fd;
	char *path;
	array_t fmtstr;
} output_file_t;
static output_file_t* output_file_new(const char *path, const char *fmtstr) {
	output_file_t *of = malloc(sizeof(*of));

	ASSERT_PATH(path);
	assert(fmtstr != NULL);

	of->fd = -1;
	of->path = strdup(path);
	array_init(&of->fmtstr, NULL);
	cache_fmt_str(&of->fmtstr, fmtstr);

	return of;
}
//
// Structures for managing file verification
//
// The target for verification - that is, the file being verified.
typedef struct {
	string_t *path;
	uint8_t *digest;
} verify_target_t;
static verify_target_t *verify_target_new(const string_t *path, const string_t *hash, uint8_t fmt_code) {
	verify_target_t *t = malloc(sizeof(*t));
	uint8_t digest_size;

	t->path = string_new_from_string(path);

	digest_size = hash_digest_size(fmt_code);
	assert(digest_size > 0);
	t->digest = malloc(digest_size);

	for (strlen_t i = 0; i < hash->length; i+=2) {
		uint8_t b = 0;

		b |= hex_to_nibble(hash->cstring[i]) << 4;
		b |= hex_to_nibble(hash->cstring[i+1]);

		t->digest[i/2] = b;
	}

	return t;
}
static void verify_target_free(void *ptr) {
	verify_target_t *t = ptr;

	if (t != NULL) {
		assert(t->path != NULL);
		assert(t->digest != NULL);

		string_free(t->path);
		free(t->digest);
		free(t);
	}

	return;
}
//
// The file containing checksums to verify against.
typedef struct {
	string_t *path;
	array_t *targets;
	uint8_t format;
} verify_file_t;
/*
static void verify_file_free(void *ptr) {
	verify_file_t *v = ptr;

	if (v != NULL) {
		if (v->path != NULL) {
			string_free(v->path);
		}
		if (v->targets != NULL) {
			array_free(v->targets);
		}
		free(v);
	}

	return;
}
*/
static verify_file_t* verify_file_new(const char *path, uint8_t fmt_code) {
	int fd = -1;
	char *buf = NULL;
	verify_file_t *v = NULL;
	ssize_t bytes = 0;
	uint8_t state = 0;
	string_t *hash = NULL;
	string_t *target_path = NULL;
	uint8_t hash_end = 0;
	size_t lineno = 1;
	const array_init_t ainit = {
		verify_target_free,
		NULL
	};

	v = malloc(sizeof(*v));
	v->path = string_new_from_cstring(path, 0);
	v->targets = array_new(&ainit);
	v->format = 0;
	target_path = string_new();
	hash = string_new();
	buf = (char *)g_copy_buffer;

	if (fmt_code == 0) {
		for (ssize_t i = (ssize_t )strlen(path); i >= 0; --i) {
			if (path[i] == '.') {
				fmt_code = match_hash_name(&path[i+1], NULL);
				break;
			}
		}
		if (fmt_code == 0) {
			ERROR("%s: unable to determine file format", path);
			goto END;
		}
	}
	v->format = fmt_code;

	if ((fd = open(path, O_RDONLY)) < 0) {
		ERROR_NO(errno, "%s: open() failed", path);
		goto END;
	}

	// Subtract 1 because we don't care about the trailing 0.
	hash_end = hash_char_buffer_size(fmt_code) - 1;
	while ((bytes = read(fd, buf, IO_BUF_SIZE)) != 0) {
		if (bytes < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				ERROR_NO(errno, "%s: read() failed", path);
				goto END;
			}
		}
		for (ssize_t i = 0; i < bytes; ++i) {
			//
			// State 0: Reading the hash
			//
			if (state == 0) {
				if (hash->length == 0) {
					if (isspace(buf[i])) {
						continue;
					} else if (buf[i] == '#') {
						state = 0xFF;
						continue;
					}
				}

				if (hex_to_nibble(buf[i]) == 0xFF) {
					ERROR("%s: line %u malformed", path, (uint_t )lineno);
					state = 0xFF;
					continue;
				}
				// This could maybe be more efficient by storing the digest directly
				// instead of copying the string and then converting it, but that
				// adds work here and I doubt it's a big impact.
				string_append_from_char(hash, buf[i]);

				if (hash->length == hash_end) {
					state = 1;
				}

			//
			// States 1 and 2: Transition spaces between hash and path
			//
			} else if (state == 1) {
				if (buf[i] != ' ') {
					ERROR("%s: line %u malformed", path, (uint_t )lineno);
					state = 0xFF;
					continue;
				}
				++state;
			} else if (state == 2) {
				if ((buf[i] != ' ') && (buf[i] != '*')) {
					ERROR("%s: line %u malformed", path, (uint_t )lineno);
					state = 0xFF;
					continue;
				}
				++state;

			//
			// State 3: Reading the file path
			//
			} else if (state == 3) {
				if (buf[i] == '\n') {
					array_append(v->targets, verify_target_new(target_path, hash, fmt_code));
					string_clear(target_path);
					string_clear(hash);

					++lineno;
					state = 0;
				} else {
					string_append_from_char(target_path, buf[i]);
				}

			//
			// State anything else: Skipping a comment or broken line
			//
			} else {
				if (buf[i] == '\n') {
					++lineno;
					state = 0;
				}
			}
		}
	}
	// This is the expected end state - a newline followed by nothing.
	if ((state == 0) && (hash->length == 0)) {
		// Nothing to do here, it just simplifies things to check for this first.

	// This means the file was missing the final newline - potentially annoying
	// but not an error.
	} else if ((state == 3) && (target_path->length > 0)) {
		array_append(v->targets, verify_target_new(target_path, hash, fmt_code));
		WARNING("%s: missing newline at end of file", path);

	// Any other state is an error.
	} else {
		ERROR("%s: malformed file: final line incomplete", path);
	}

END:
	if (fd >= 0) {
		close(fd);
	}
	string_free(target_path);
	string_free(hash);
	return v;
}
// Used to find a file in an array of targets.
static int verify_target_path_cmp(const void *obj, const void *ent) {
	const copy_path_t *path = obj;
	const verify_target_t *vt = ent;

	if (string_eq_string(path->src_path, vt->path) || string_eq_string(path->src_affix, vt->path)) {
		return 0;
	}
	return -1;
}
//
// Structure for managing hash state.
//
typedef struct {
	flag_t flags;
	copy_path_t *paths;

	// MD5 context
	struct md5_ctx md5ctx;
	uint8_t md5res[MD5_DIGEST_SIZE];
	char    md5print[(MD5_DIGEST_SIZE*2)+1];

	// SHA1 context
	struct sha1_ctx sha1ctx;
	uint8_t sha1res[SHA1_DIGEST_SIZE];
	char    sha1print[(SHA1_DIGEST_SIZE*2)+1];

	// SHA224 context
	struct sha256_ctx sha224ctx;
	uint8_t sha224res[SHA224_DIGEST_SIZE];
	char    sha224print[(SHA224_DIGEST_SIZE*2)+1];

	// SHA256 context
	struct sha256_ctx sha256ctx;
	uint8_t sha256res[SHA256_DIGEST_SIZE];
	char    sha256print[(SHA256_DIGEST_SIZE*2)+1];

	// SHA384 context
	struct sha512_ctx sha384ctx;
	uint8_t sha384res[SHA384_DIGEST_SIZE];
	char    sha384print[(SHA384_DIGEST_SIZE*2)+1];

	// SHA512 context
	struct sha512_ctx sha512ctx;
	uint8_t sha512res[SHA512_DIGEST_SIZE];
	char    sha512print[(SHA512_DIGEST_SIZE*2)+1];
} hash_ctx_t;
static hash_ctx_t* hash_ctx_init(hash_ctx_t *ctx) {
	assert(ctx != NULL);

	memset(ctx, 0, sizeof(*ctx));

	md5_init_ctx(&ctx->md5ctx);
	sha1_init_ctx(&ctx->sha1ctx);
	sha256_init_ctx(&ctx->sha256ctx);
	sha224_init_ctx(&ctx->sha224ctx);
	sha512_init_ctx(&ctx->sha512ctx);
	sha384_init_ctx(&ctx->sha384ctx);

	return ctx;
}

static array_t *output_files = NULL;
static array_t *verify_files = NULL;

//
// Helper functions
//
static void abort_for_errors(void) {
	if (((g_max_errors != 0xFFFF) && (g_max_errors < g_error_count)) ||
	    ((g_max_warnings != 0xFFFF) && (g_max_warnings < (g_warning_count + g_error_count))) ||
	    ((g_max_failed != 0xFFFF) && (g_max_failed < g_failed_count))) {
		longjmp(g_abort_jmp, 1);
	}
	return;
}
static uint16_t get_max_fault(const opt_ctx_t *optctx) {
	char *end;
	long tmp;

	tmp = strtol(optctx->arg, &end, 10);
	if ((end[0] != 0) || (end == optctx->arg) || (tmp < -1)) {
		ERROR("Invalid argument to --%s: %s", optctx->opts[optctx->opts_i].long_name, optctx->arg);
		show_help(optctx->opts);
		longjmp(g_abort_jmp, 1);
	}

	return (tmp == -1) ? 0xFFFF : (uint16_t )tmp;
}
static int get_arg_fd(const opt_ctx_t *optctx) {
	char *end;
	long tmp;

	// First char is '&', so skip it.
	tmp = strtol(&optctx->arg[1], &end, 10);
	if ((end[0] != 0) || (end == optctx->arg) || (tmp < 0)) {
		ERROR("Invalid argument to --%s: %s", optctx->opts[optctx->opts_i].long_name, optctx->arg);
		show_help(optctx->opts);
		longjmp(g_abort_jmp, 1);
	}

	return (int )tmp;
}
static void cache_fmt_str(array_t *cache, const char *fmtstr) {
	const char *c = fmtstr;
	string_t *str = NULL;
	size_t cnt;

	assert(fmtstr != NULL);
	assert(cache != NULL);

	for (; *c != 0; ++c) {
		if (*c == '%') {
			fmt_cache_t *fmt = malloc(sizeof(*fmt));
			memset(fmt, 0, sizeof(*fmt));

			switch (match_hash_name(&c[1], &cnt)) {
				case CODE_MD5:
					fmt->fmt_code = CODE_MD5;
					break;
				case CODE_SHA1:
					fmt->fmt_code = CODE_SHA1;
					break;
				case CODE_SHA224:
					fmt->fmt_code = CODE_SHA224;
					break;
				case CODE_SHA256:
					fmt->fmt_code = CODE_SHA256;
					break;
				case CODE_SHA384:
					fmt->fmt_code = CODE_SHA384;
					break;
				case CODE_SHA512:
					fmt->fmt_code = CODE_SHA512;
					break;
				default:
					switch (c[1]) {
						case 's':
							fmt->fmt_code = 's';
							cnt = 1;
							break;
						case 'S':
							fmt->fmt_code = 'S';
							cnt = 1;
							break;
						case 'd':
							fmt->fmt_code = 'd';
							cnt = 1;
							break;
						case 'D':
							fmt->fmt_code = 'D';
							cnt = 1;
							break;
						case 'n':
							fmt->fmt_code = 'n';
							cnt = 1;
							break;
						// '%%' is '%'
						case '%':
							cnt = 1;
							/* fall through */
						default:
							if (str == NULL) {
								str = string_new();
							}
							string_append_from_char(str, '%');
							break;
					}
			}
			c += cnt;
			if (fmt->fmt_code != 0) {
				if (!string_is_empty(str)) {
					fmt_cache_t *fmt2 = malloc(sizeof(*fmt2));
					memset(fmt2, 0, sizeof(*fmt2));

					fmt2->str = str;
					array_append(cache, fmt2);
					str = NULL;
				}
				array_append(cache, fmt);
			} else {
				free(fmt);
			}
		} else {
			if (str == NULL) {
				str = string_new();
			}
			string_append_from_char(str, *c);
		}
	}
	if (!string_is_empty(str)) {
		fmt_cache_t *fmt = malloc(sizeof(*fmt));
		memset(fmt, 0, sizeof(*fmt));

		fmt->str = str;
		array_append(cache, fmt);
		str = NULL;
	}
	string_free(str);

	return;
}
static void timeval_diff(struct timeval *tv_start, struct timeval *tv_end, uint_t *ret_s, uint_t *ret_us) {
	struct timeval now;

	assert(tv_start != NULL);
	//assert(tv_end != NULL);
	assert(ret_s != NULL);
	assert(ret_us != NULL);

	if (tv_end == NULL) {
		tv_end = &now;

		if (gettimeofday(&now, NULL) < 0) {
			msg_warnno(errno, "gettimeofday() failed");
			*ret_s = 0;
			*ret_us = 0;
			return;
		}
	}

	if (tv_start->tv_usec > tv_end->tv_usec) {
		*ret_s = (uint_t )(tv_end->tv_sec - tv_start->tv_sec)-1;
		*ret_us = (uint_t )(tv_end->tv_usec + (1000000 - tv_start->tv_usec));
	} else {
		*ret_s = (uint_t )(tv_end->tv_sec - tv_start->tv_sec);
		*ret_us = (uint_t )(tv_end->tv_usec - tv_start->tv_usec);
	}

	return;
}
static uint8_t match_hash_name(const char *name, size_t *cnt) {
	size_t tcnt;

	assert(name != NULL);

	if (cnt == NULL) {
		cnt = &tcnt;
	}

	switch (name[0]) {
	case 'm':
		switch (name[1]) {
		case 'd':
			switch (name[2]) {
			case '5':
				*cnt = 3;
				return CODE_MD5;
				break;
			}
			break;
		}
		break;

	case 's':
		switch (name[1]) {
		case 'h':
			switch (name[2]) {
			case 'a':
				switch (name[3]) {
				case '1':
					*cnt = 4;
					return CODE_SHA1;
					break;
				case '2':
					switch (name[4]) {
					case '2':
						switch (name[5]) {
						case '4':
							*cnt = 6;
							return CODE_SHA224;
							break;
						}
						break;
					case '5':
						switch (name[5]) {
						case '6':
							*cnt = 6;
							return CODE_SHA256;
							break;
						}
						break;
					}
					break;
				case '3':
					switch (name[4]) {
					case '8':
						switch (name[5]) {
						case '4':
							*cnt = 6;
							return CODE_SHA384;
							break;
						}
						break;
					}
					break;
				case '5':
					switch (name[4]) {
					case '1':
						switch (name[5]) {
						case '2':
							*cnt = 6;
							return CODE_SHA512;
							break;
						}
						break;
					}
					break;
				}
				break;
			}
			break;
		}
		break;
	}

	*cnt = 0;
	return 0;
}
/*
static char nibble_to_hex(uint8_t nibble) {
	assert(nibble <= 0x0F);

	switch (nibble) {
		case 0x0A:
		case 0x0B:
		case 0x0C:
		case 0x0D:
		case 0x0E:
		case 0x0F:
			return (char )((nibble - 0x0A) + HEX_BASECHAR);
	}
	return (char )(nibble + '0');
}
*/
static uint8_t hex_to_nibble(char digit) {
	switch (digit) {
		case 'A':
		case 'a':
			return 0x0A;
		case 'B':
		case 'b':
			return 0x0B;
		case 'C':
		case 'c':
			return 0x0C;
		case 'D':
		case 'd':
			return 0x0D;
		case 'E':
		case 'e':
			return 0x0E;
		case 'F':
		case 'f':
			return 0x0F;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return (uint8_t )(digit - '0');
	}
	return 0xFF;
}
static flag_t find_format_flags(array_t *fmt_cache) {
	flag_t flags = 0;

	assert(fmt_cache != NULL);

	for (arlen_t i = 0; i < fmt_cache->used; ++i) {
		fmt_cache_t *fmt = fmt_cache->bank[i];

		switch(fmt->fmt_code) {
			case CODE_MD5:
				SET_BIT(flags, FLAG_TRACK_MD5);
				break;
			case CODE_SHA1:
				SET_BIT(flags, FLAG_TRACK_SHA1);
				break;
			case CODE_SHA224:
				SET_BIT(flags, FLAG_TRACK_SHA224);
				break;
			case CODE_SHA256:
				SET_BIT(flags, FLAG_TRACK_SHA256);
				break;
			case CODE_SHA384:
				SET_BIT(flags, FLAG_TRACK_SHA384);
				break;
			case CODE_SHA512:
				SET_BIT(flags, FLAG_TRACK_SHA512);
				break;
		}
	}

	return flags;
}
static const char* print_hash(char *dest, const uint8_t *src, size_t bytes) {
	size_t i, d;
	uint_t A, B;

	assert(dest != NULL);
	assert(src != NULL);
	assert(bytes > 0);

	for (i = 0, d = 0; i < bytes; ++i, d += 2) {
		A = (src[i] & 0xF0u) >> 4;
		B = (src[i] & 0x0Fu);

		A += (A >= 10) ? (HEX_BASECHAR-10) : '0';
		B += (B >= 10) ? (HEX_BASECHAR-10) : '0';

		dest[d]   = (char )A;
		dest[d+1] = (char )B;
	}
	dest[bytes*2] = (char )0;

	return dest;
}
static uint8_t hash_digest_size(uint8_t code) {
	switch (code) {
		case CODE_MD5:
			return MD5_DIGEST_SIZE;
			break;
		case CODE_SHA1:
			return SHA1_DIGEST_SIZE;
			break;
		case CODE_SHA224:
			return SHA224_DIGEST_SIZE;
			break;
		case CODE_SHA256:
			return SHA256_DIGEST_SIZE;
			break;
		case CODE_SHA384:
			return SHA384_DIGEST_SIZE;
			break;
		case CODE_SHA512:
			return SHA512_DIGEST_SIZE;
			break;
	}

	return 0;
}
static uint8_t hash_char_buffer_size(uint8_t code) {
	return (uint8_t )((hash_digest_size(code) * 2) + 1);
}
static void checked_write(int fd, const void *buf, ssize_t count, const char *path) {
	ssize_t bytes;

	ASSERT_FD(fd);
	assert(buf != NULL);
	//assert(count >= 0);
	ASSERT_PATH(path);

	if (count <= 0) {
		return;
	}

	while (count > 0) {
		do {
			bytes = write(fd, buf, (size_t )count);
		} while ((bytes < 0) && (errno == EINTR));
		if (bytes < 0) {
			ERROR_NO(errno, "%s: write error", path);
			return;
		}
		count -= bytes;
	}

	return;
}
static int vstat(const char *pathname, struct stat *statbuf, flag_t flags) {
	if (BIT_IS_SET(flags, OPT_FOLLOW_LINKS)) {
		return stat(pathname, statbuf);
	} else {
		return lstat(pathname, statbuf);
	}
}

//
// Main functions
//
static void sighandler(int sig) {
	fprintf(stderr, "%s: caught signal %d, exiting now.\n", g_program_name, sig);
	exit(127 + sig);
	return;
}
static void show_help(const opt_option_t *options) {
	msg_print(-100, "Usage: %s [options] source [source2 [...]] destination", g_program_name);
	msg_print(-100, "       %s [options] -t destination source [source2 [...]]", g_program_name);
	msg_print(-100, "\nRecognized options:");
	opt_print_help("   ", "\n", options);
	msg_print(-100, "Format specifiers for output lines are:\n"
			"   %%md5: The MD5 checksum of the file\n"
			"   %%sha1: The SHA1 checksum of the file\n"
			"   %%sha224: The SHA224 checksum of the file\n"
			"   %%sha256: The SHA256 checksum of the file\n"
			"   %%sha384: The SHA384 checksum of the file\n"
			"   %%sha512: The SHA512 checksum of the file\n"
			"   %%S: The full source path\n"
			"   %%s: The part of the source path after the source root\n"
			"   %%D: The full destination path\n"
			"   %%d: The part of the destination path after the destination root\n"
			"   %%n: The base name of the destination file\n"
			"   %%%%: A literal '%%'"
	);
	msg_print(-100,
		"\nNotes:"
		"\n   When verifying, a search is made for the source file using both the full path\n"
		"   and non-root part of the path. Only the first match found is used.\n"
	);

	return;
}
static void write_fmt(output_file_t *of, hash_ctx_t *ctx) {
	static string_t *basename = NULL;

	assert(of != NULL);
	assert(ctx != NULL);

	if (of->fd < 0) {
		return;
	}

	for (arlen_t i = 0; i < of->fmtstr.used; ++i) {
		fmt_cache_t *fmt = of->fmtstr.bank[i];

		switch (fmt->fmt_code) {
			case CODE_MD5:
				checked_write(of->fd, ctx->md5print, MD5_DIGEST_SIZE*2, of->path);
				break;
			case CODE_SHA1:
				checked_write(of->fd, ctx->sha1print, SHA1_DIGEST_SIZE*2, of->path);
				break;
			case CODE_SHA224:
				checked_write(of->fd, ctx->sha224print, SHA224_DIGEST_SIZE*2, of->path);
				break;
			case CODE_SHA256:
				checked_write(of->fd, ctx->sha256print, SHA256_DIGEST_SIZE*2, of->path);
				break;
			case CODE_SHA384:
				checked_write(of->fd, ctx->sha384print, SHA384_DIGEST_SIZE*2, of->path);
				break;
			case CODE_SHA512:
				checked_write(of->fd, ctx->sha512print, SHA512_DIGEST_SIZE*2, of->path);
				break;
			case 's':
				checked_write(of->fd, ctx->paths->src_affix->cstring, (ssize_t )ctx->paths->src_affix->length, of->path);
				break;
			case 'S':
				checked_write(of->fd, ctx->paths->src_path->cstring, (ssize_t )ctx->paths->src_path->length, of->path);
				break;
			case 'd':
				checked_write(of->fd, ctx->paths->dest_affix->cstring, (ssize_t )ctx->paths->dest_affix->length, of->path);
				break;
			case 'D':
				checked_write(of->fd, ctx->paths->dest_path->cstring, (ssize_t )ctx->paths->dest_path->length, of->path);
				break;
			case 'n': {
				if (basename == NULL) {
					basename = string_new();
				}
				string_basename(string_set_from_string(basename, ctx->paths->dest_path), '/');
				checked_write(of->fd, basename->cstring, (ssize_t )basename->length, of->path);
				break;
			}
			case 0:
				assert(fmt->str != NULL);
				checked_write(of->fd, fmt->str->cstring, fmt->str->length, of->path);
				break;
			default:
				// Should never reach this point.
				assert(false);
				break;
		}
	}
	checked_write(of->fd, "\n", 1, of->path);

	return;
}
// block_update() is called from file_copy_path_to_path() on each block as it's copied.
static int block_update(uint8_t *restrict buf, size_t bufsize, size_t *bytes, void *extra) {
	hash_ctx_t *ctx = extra;

	ASSERT_BUF(buf, bufsize);
	//bytes == NULL means to finish up.
	//assert(bytes != NULL);
	ASSERT_CTX(ctx);

	if (bytes != NULL) {
		g_total_bytes += (size_t )(*bytes);

		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_MD5)) {
			md5_process_bytes(buf, *bytes, &ctx->md5ctx);
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA1)) {
			sha1_process_bytes(buf, *bytes, &ctx->sha1ctx);
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA224)) {
			sha256_process_bytes(buf, *bytes, &ctx->sha224ctx);
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA256)) {
			sha256_process_bytes(buf, *bytes, &ctx->sha256ctx);
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA384)) {
			sha512_process_bytes(buf, *bytes, &ctx->sha384ctx);
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA512)) {
			sha512_process_bytes(buf, *bytes, &ctx->sha512ctx);
		}

	} else {
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_MD5)) {
			md5_finish_ctx(&ctx->md5ctx, ctx->md5res);
			print_hash(ctx->md5print, ctx->md5res, sizeof(ctx->md5res));
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA1)) {
			sha1_finish_ctx(&ctx->sha1ctx, ctx->sha1res);
			print_hash(ctx->sha1print, ctx->sha1res, sizeof(ctx->sha1res));
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA224)) {
			sha224_finish_ctx(&ctx->sha224ctx, ctx->sha224res);
			print_hash(ctx->sha224print, ctx->sha224res, sizeof(ctx->sha224res));
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA256)) {
			sha256_finish_ctx(&ctx->sha256ctx, ctx->sha256res);
			print_hash(ctx->sha256print, ctx->sha256res, sizeof(ctx->sha256res));
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA384)) {
			sha384_finish_ctx(&ctx->sha384ctx, ctx->sha384res);
			print_hash(ctx->sha384print, ctx->sha384res, sizeof(ctx->sha384res));
		}
		if (BIT_IS_SET(ctx->flags, FLAG_TRACK_SHA512)) {
			sha512_finish_ctx(&ctx->sha512ctx, ctx->sha512res);
			print_hash(ctx->sha512print, ctx->sha512res, sizeof(ctx->sha512res));
		}

		for (arlen_t i = 0; i < output_files->used; ++i) {
			output_file_t *of = output_files->bank[i];
			write_fmt(of, ctx);
		}

		bool seen = false;
		for (arlen_t i = 0; i < verify_files->used; ++i) {
			verify_file_t *vf = verify_files->bank[i];
			//verify_target_t *vt = array_find_object(vf->targets, ctx->paths->src_path, verify_target_path_cmp);
			verify_target_t *vt = array_find_object(vf->targets, ctx->paths, verify_target_path_cmp);

			if (vt != NULL) {
				size_t len = hash_digest_size(vf->format);
				uint8_t *digest = NULL;

				seen = true;
				switch (vf->format) {
					case CODE_MD5:
						digest = ctx->md5res;
						break;
					case CODE_SHA1:
						digest = ctx->sha1res;
						break;
					case CODE_SHA224:
						digest = ctx->sha224res;
						break;
					case CODE_SHA256:
						digest = ctx->sha256res;
						break;
					case CODE_SHA384:
						digest = ctx->sha384res;
						break;
					case CODE_SHA512:
						digest = ctx->sha512res;
						break;
					default:
						break;
				}
				if (memcmp(digest, vt->digest, len) == 0) {
					msg_print(MSG_VERB_INFO, "%s: checksum passed (from %s)", ctx->paths->src_path->cstring, vf->path->cstring);
				} else {
					FAILED("%s: checksum failed (from %s)", ctx->paths->src_path->cstring, vf->path->cstring);
				}
				break;
			}
		}
		if ((verify_files->used > 0) && !seen) {
			WARNING("%s: file can't be verified", ctx->paths->src_path->cstring);
			//msg_print(MSG_VERB_INFO, "%s: file can't be verified", ctx->paths->src_path->cstring);
			++g_unverified_count;
		}
	}

	return 0;
}

static void copy_file(copy_path_t *copy_path, struct stat *src_st, struct stat *dest_st, file_type_t dest_ft, flag_t flags) {
	int err;
	bool backup_dest = false;
	struct timeval tv_start;
	size_t previous_bytes = g_total_bytes;
	static string_t *dest_tmp = NULL;
	flag_t file_flags = 0;
	file_copy_callback_t bcallback = { 0 };
	static hash_ctx_t *ctx = NULL;

	if (BIT_IS_SET(flags, OPT_FOLLOW_LINKS)) {
		SET_BIT(file_flags, FILE_DEREF);
	}
	if (BIT_IS_SET(flags, OPT_SYNC_AFTER)) {
		SET_BIT(file_flags, FILE_FSYNC);
	}
	if (BIT_IS_SET(flags, OPT_COPY_CONTENTS)) {
		SET_BIT(file_flags, FILE_COPY_CONTENTS);
	}

	if (dest_tmp == NULL) {
		dest_tmp = string_new();
	}
	if (ctx == NULL) {
		ctx = malloc(sizeof(*ctx));
	}
	hash_ctx_init(ctx);
	ctx->flags = flags;
	ctx->paths = copy_path;
	bcallback.block_callback = block_update;
	bcallback.extra = ctx;

	if (dest_ft == FILE_FT_DIR) {
		ERROR("%s: file exists, but is a directory.", copy_path->dest_path->cstring);
		goto END;
	}
	if (dest_ft != FILE_FT_NONE) {
		if (BIT_IS_SET(flags, OPT_INTERACTIVE)) {
			bool def = (BIT_IS_SET(flags, OPT_NOCLOBBER)) ? false : true;
			if (msg_ask(def, def, "Replace %s with %s?", copy_path->dest_path->cstring, copy_path->src_path->cstring) == false) {
				goto END;
			}
		} else if (BIT_IS_SET(flags, OPT_NOCLOBBER)) {
			msg_print(MSG_VERB_INFO, "%s: file already exists", copy_path->dest_path->cstring);
			goto END;
		} else if (BIT_IS_SET(flags, OPT_UPDATE)) {
			if ((src_st->st_mtime <= dest_st->st_mtime) || ((src_st->st_mtime - dest_st->st_mtime) <= g_update_time_fudge_seconds)) {
				msg_print(MSG_VERB_INFO, "%s: destination file is newer than source", copy_path->dest_path->cstring);
				goto END;
			}
		}
		if (BIT_IS_SET(flags, OPT_BACKUP_DEST)) {
			backup_dest = true;
		}
	}

	msg_print(MSG_VERB_INFO, "%s -> %s", copy_path->src_path->cstring, copy_path->dest_path->cstring);
	if (backup_dest == true) {
		string_set_from_string(dest_tmp, copy_path->dest_path);
		string_append_from_string(dest_tmp, g_backup_ext);

		if (BIT_IS_SET(flags, OPT_INCR_BACKUP)) {
			struct stat st;
			strlen_t sl;
			int inc = 0;

			sl = dest_tmp->length;
			while (lstat(dest_tmp->cstring, &st) == 0) {
				++inc;
				string_truncate(dest_tmp, sl);
				string_append_from_int(dest_tmp, inc, 0, 0);
			}
		}

		msg_print(MSG_VERB_INFO, "   %s -> %s", copy_path->dest_path->cstring, dest_tmp->cstring);
		if (rename(copy_path->dest_path->cstring, dest_tmp->cstring) < 0) {
			ERROR_NO(errno, "%s: destination file backup failed", copy_path->dest_path->cstring);
			goto END;
		}
	}
	if (g_verbosity >= MSG_VERB_EXTRA) {
		if (gettimeofday(&tv_start, NULL) < 0) {
			msg_errno(errno, "gettimeofday() failed");
		}
	}

	string_set_from_string(dest_tmp, copy_path->dest_path);
	if (g_temp_ext->cstring[0] != 0) {
		string_append_from_string(dest_tmp, g_temp_ext);
		if ((unlink(dest_tmp->cstring) < 0) && (errno != ENOENT)) {
			ERROR_NO(errno, "%s: unlink() failed", dest_tmp->cstring);
			goto END;
		}
	}

	++g_total_files;
	err = file_copy_path_to_path(copy_path->src_path->cstring, dest_tmp->cstring, g_copy_buffer, IO_BUF_SIZE, &bcallback, file_flags);
	if (err < 0) {
		ERROR_NO(-err, "failed to copy %s to %s", copy_path->src_path->cstring, dest_tmp->cstring);
		// FIXME: Should the backup file be moved back when the copy fails?
		//unlink(dest_tmp->cstring);
		goto END;
	}
	if (err > 0) {
		WARNING("warning generated while copying %s to %s: %s", copy_path->src_path->cstring, dest_tmp->cstring, strerror(err));
	}
	if (g_temp_ext->cstring[0] != 0) {
		if (rename(dest_tmp->cstring, copy_path->dest_path->cstring) < 0) {
			// FIXME: Should this remove the temporary file, or leave it for
			// manual handling?
			ERROR_NO(errno, "%s: rename() failed", dest_tmp->cstring);
			//unlink(dest_tmp->cstring);
		}
	}

	if (g_verbosity >= MSG_VERB_EXTRA) {
		uint_t s, us;

		timeval_diff(&tv_start, NULL, &s, &us);
		msg_print(MSG_VERB_EXTRA, "   %lu bytes copied in %u.%06u seconds.", (long unsigned )(g_total_bytes - previous_bytes), s, us);
	}

END:
	return;
}
static cwd_t* dir_stack_pop(list_t *stack, copy_path_t *copy_path, uint16_t *depth, flag_t flags) {
	cwd_t *cwd;

	UNUSED(flags);

	*depth -= 1;
	string_pop_path(copy_path->src_path);
	string_pop_path(copy_path->src_affix);
	string_pop_path(copy_path->dest_path);
	string_pop_path(copy_path->dest_affix);

	list_pop(stack, (void **)&cwd);

	return cwd;
}
static int dir_stack_push(list_t *stack, cwd_t *cwd, copy_path_t *copy_path, const char *name, uint16_t *depth, flag_t flags) {
	strlen_t len;
	struct stat st;

	UNUSED(flags);

	if (*depth == RECURSION_MAX) {
		ERROR("%s: skipping: directory depth limit exceeded.", copy_path->src_path->cstring);
		return -1;
	}

	len = (strlen_t )strlen(name);
	string_push_path_from_cstring(copy_path->src_path, name, len);
	if (vstat(copy_path->src_path->cstring, &st, flags) < 0) {
		int ee = errno;

		ERROR_NO(ee, "%s: stat() failed", copy_path->src_path->cstring);
		string_pop_path(copy_path->src_path);
		return -ee;
	} else if (BIT_IS_SET(flags, OPT_NOXDEV) && (cwd->st.st_dev != st.st_dev)) {
		msg_print(MSG_VERB_INFO, "%s: not crossing device boundary.", copy_path->src_path->cstring);
		string_pop_path(copy_path->src_path);
		return 1;
	}
	string_push_path_from_cstring(copy_path->src_affix,  name, len);
	string_push_path_from_cstring(copy_path->dest_path,  name, len);
	string_push_path_from_cstring(copy_path->dest_affix, name, len);
	list_push(stack, cwd);

	*depth += 1;

	return 0;
}
static void finish_cwd(cwd_t *cwd, copy_path_t *copy_path, bool created_dest, flag_t flags) {
	int err;

	assert(cwd->dir != NULL);

	if (closedir(cwd->dir) < 0) {
		ERROR_NO(errno, "%s: close error", copy_path->src_path->cstring);
	}
	cwd->dir = NULL;

	// FIXME: Don't copy metadata if destination folder is newer than source
	// and OPT_UPDATE is set.
	if (created_dest || !BIT_IS_SET(flags, OPT_NOCLOBBER)) {
		if ((err = file_copy_stat_to_path(&cwd->st, copy_path->dest_path->cstring, FILE_DEREF)) < 0) {
			WARNING_NO(ABS(err), "%s: unable to copy directory metadata.", copy_path->dest_path->cstring);
		}
	}
	// The files themselves are written to disk but the directory entries
	// may not be until the directory is synced.
	if (BIT_IS_SET(flags, OPT_SYNC_AFTER)) {
		if (file_fsync_path(copy_path->dest_path->cstring, 0) < 0) {
			ERROR("%s: unable to sync directory", copy_path->dest_path->cstring);
		}
	}

	return;
}
static void copy_src(copy_path_t *copy_path, flag_t flags) {
	int err;
	flag_t mflags;
	uint16_t depth = 1;
	list_t *dir_stack = NULL;
	list_init_t dir_stack_init = {
		.free_obj = free_cwd,
	};
	cwd_t *cwd = NULL;

	assert(copy_path != NULL);
	assert(copy_path->src_path != NULL);
	ASSERT_PATH(copy_path->src_path->cstring);
	assert(copy_path->src_root != NULL);
	assert(copy_path->src_affix != NULL);
	assert(copy_path->dest_path != NULL);
	ASSERT_PATH(copy_path->dest_path->cstring);
	assert(copy_path->dest_root != NULL);
	assert(copy_path->dest_affix != NULL);

	if (BIT_IS_SET(flags, OPT_PARENTS)) {
		char *c = copy_path->dest_path->cstring;

		for (strlen_t i = 0; i < copy_path->dest_path->length; ++i) {
			if (c[i] == '/') {
				c[i] = 0;
				if (mkdir(copy_path->dest_path->cstring, NEWDIR_PERMS) < 0) {
					// If the path exists but isn't a directory, the error will
					// be caught later.
					if (errno != EEXIST) {
						ERROR_NO(errno, "%s: mkdir() failed", copy_path->dest_path->cstring);
						c[i] = '/';
						return;
					}
				}
				c[i] = '/';
			}
		}
	}

	dir_stack = list_new(&dir_stack_init);

	mflags = flags;
	while (depth > 0) {
		struct dirent *dirp = NULL;
		bool created_dest = true;

		if (cwd == NULL) {
			struct stat src_st, dest_st;
			file_type_t src_ft, dest_ft;
			bool cycle = false;
			DIR *dir;

			if (vstat(copy_path->src_path->cstring, &src_st, mflags) < 0) {
				ERROR_NO(errno, "%s: stat() failed", copy_path->src_path->cstring);
				cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
				continue;
			}
			src_ft = file_get_type_stat(&src_st, 0);
			for (list_entry_t *pe = dir_stack->head; pe != NULL; pe = pe->next) {
				cwd_t *p = pe->obj;

				if ((p->st.st_ino == src_st.st_ino) && (p->st.st_dev == src_st.st_dev)) {
					cycle = true;
					break;
				}
			}
			if (cycle) {
				ERROR("%s: directory cycle encountered", copy_path->src_path->cstring);
				cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
				continue;
			}

			// We always dereference existing destinations because that's the least
			// surprising thing to do.
			if (vstat(copy_path->dest_path->cstring, &dest_st, OPT_FOLLOW_LINKS) < 0) {
				dest_ft = FILE_FT_NONE;
			} else {
				dest_ft = file_get_type_stat(&dest_st, 0);
			}
			if (src_ft != FILE_FT_DIR) {
				copy_file(copy_path, &src_st, &dest_st, dest_ft, mflags);
				cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
				continue;
			}

			if (dest_ft != FILE_FT_NONE) {
				if (dest_ft != FILE_FT_DIR) {
					ERROR("%s: file exists but is not a directory.", copy_path->dest_path->cstring);
					cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
					continue;
				}
				created_dest = false;
			}

			if ((err = file_create_dir(copy_path->dest_path->cstring, NEWDIR_PERMS, 0)) < 0) {
				ERROR_NO(-err, "%s: failed to create directory", copy_path->dest_path->cstring);
				cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
				continue;
			} else if (err > 0) {
				WARNING_NO(err, "%s: warning while creating directory", copy_path->dest_path->cstring);
			}

			if ((dir = opendir(copy_path->src_path->cstring)) == NULL) {
				ERROR_NO(errno, "%s: opendir() failed", copy_path->src_path->cstring);
				cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
				continue;
			}
			cwd = malloc(sizeof(*cwd));
			cwd->st = src_st;
			cwd->dir = dir;
		}
		if (BIT_IS_SET(flags, OPT_FOLLOW_INITIAL_LINKS)) {
			mflags = MASK_BITS(flags, OPT_FOLLOW_LINKS);
		}

		assert(cwd != NULL);
		assert(cwd->dir != NULL);
		while (true) {
			errno = 0;
			dirp = readdir(cwd->dir);
			if (dirp == NULL) {
				if (errno != 0) {
					ERROR_NO(errno, "%s: readdir() failed", copy_path->src_path->cstring);
				}
				finish_cwd(cwd, copy_path, created_dest, mflags);
				free(cwd);
				cwd = dir_stack_pop(dir_stack, copy_path, &depth, mflags);
				break;
			}

			if (dirp->d_name[0] == '.') {
				if (dirp->d_name[1] == 0) {
					continue;
				} else if ((dirp->d_name[1] == '.') && (dirp->d_name[2] == 0)) {
					continue;
				}
			}

			err = dir_stack_push(dir_stack, cwd, copy_path, dirp->d_name, &depth, mflags);
			if (err == 0) {
				cwd = NULL;
				break;
			}
		}
	}

	list_free(dir_stack);
	return;
}

int main(int argc, char **argv) {
	int ret = 0;
	int opt;
	flag_t flags = 0;
	array_t *arguments;
	string_t *dest_root = NULL, *src_root = NULL;
	bool dest_is_dir = false;
	struct sigaction sa = { 0 };
	const char *output_fmt = "%md5  %d";
	struct timeval tv_start;
	msg_init_t msg_init_struct = {
		.stdin_fd = -1,
		.stdout_fd = -1,
		.stderr_fd = -1,
		.verbosity = MSG_VERB_NORM,
		.flags = MSG_LIBERRORS,
		.program_name = NULL
	};
	static const opt_option_t options[] = {
		{ 'b', "backup",      OPT_ARG_ACCEPTED,  "Backup existing destination files. Use [ARG] as the suffix if supplied." },
		{ CODE_COPY_CONTENTS, "copy-contents", OPT_ARG_NONE, "Copy the contents of special files instead of the file itself." },
		{ 'F', "source",      OPT_ARG_REQUIRED, "Interpret source paths relative to directory.\n       Source files beginning with '/' ignore this." },
		{ CODE_SYNC_AFTER, "fsync-after",  OPT_ARG_NONE, "Call fdatasync() on each destination file after copying." },
		{ 'h', "help",        OPT_ARG_NONE,    "Show program help." },
		{ 'H', "dereference-initial", OPT_ARG_NONE, "Follow symbolic links in sources named on the command line." },
		{ 'i', "interactive", OPT_ARG_NONE,    "Ask before overwriting existing destination files." },
		{ CODE_INCR_BACKUP, "incr-backup", OPT_ARG_NONE,  "When backing up existing destination files, append a number if the backup file also exists.\n       Implies --backup." },
		{ 'L', "dereference", OPT_ARG_NONE, "Always follow symbolic links when encountered." },
		{ CODE_MAX_ERRORS, "max-errors", OPT_ARG_REQUIRED, "Abort if more than this many errors are encountered.\n       Set to '-1' to disable (default)." },
		{ CODE_MAX_FAILED, "max-failed", OPT_ARG_REQUIRED, "Abort if more than this many files fail verification.\n       Set to '-1' to disable (default)." },
		{ CODE_MAX_WARNINGS, "max-warnings", OPT_ARG_REQUIRED, "Abort if more than this many warnings+errors are encountered.\n       Set to '-1' to disable (default)." },
		{ 'n', "no-clobber",  OPT_ARG_NONE,    "Don't replace existing destination files." },
		{ 'o', "output-file",   OPT_ARG_REQUIRED, "Print checksums to file. Can be specified multiple times.\n       '-' is treated as stdout and names of the form '&<N>' are treated as open file descriptors.\n       Existing files are appended to." },
		{ 'O', "output-format", OPT_ARG_REQUIRED, "Specify output format. Only applies to output files specified after it with -o." },
		{ CODE_PARENTS, "parents", OPT_ARG_NONE, "Use full source file name under destination." },
		{ 'q', "quiet",       OPT_ARG_NONE,    "Print less information to stdout. Can be given multiple times." },
		//{ CODE_SYNC_DURING, "synchronous", OPT_ARG_NONE, "Use synchronous IO to write destination files." },
		{ CODE_SET_TEMP_EXT, "set-temp-ext", OPT_ARG_REQUIRED, "Set the temporary file extension. Set to \"\" to write directly to destination files." },
		{ 't', "target",      OPT_ARG_REQUIRED, "Copy into specified directory." },
		{ 'u', "update",      OPT_ARG_ACCEPTED,  "Only replace files if the source is newer than the destination.\n       Use a fudge factor of [ARG] seconds if supplied when comparing times, otherwise use 2 seconds." },
		{ 'v', "verbose",     OPT_ARG_NONE,    "Print more information to stdout. Can be given multiple times." },
		{ 'x', "one-file-system", OPT_ARG_NONE, "Don't cross into other file systems." },
		{ CODE_MD5,    "md5",    OPT_ARG_REQUIRED, "Output md5 checksums to file." },
		{ CODE_SHA1,   "sha1",   OPT_ARG_REQUIRED, "Output sha1 checksums to file." },
		{ CODE_SHA224, "sha224", OPT_ARG_REQUIRED, "Output sha224 checksums to file." },
		{ CODE_SHA256, "sha256", OPT_ARG_REQUIRED, "Output sha256 checksums to file." },
		{ CODE_SHA384, "sha384", OPT_ARG_REQUIRED, "Output sha384 checksums to file." },
		{ CODE_SHA512, "sha512", OPT_ARG_REQUIRED, "Output sha512 checksums to file." },
		{ CODE_MD5_VERIFY,    "verify-md5",    OPT_ARG_REQUIRED, "Verify md5 checksums from file." },
		{ CODE_SHA1_VERIFY,   "verify-sha1",   OPT_ARG_REQUIRED, "Verify sha1 checksums from file." },
		{ CODE_SHA224_VERIFY, "verify-sha224", OPT_ARG_REQUIRED, "Verify sha224 checksums from file." },
		{ CODE_SHA256_VERIFY, "verify-sha256", OPT_ARG_REQUIRED, "Verify sha256 checksums from file." },
		{ CODE_SHA384_VERIFY, "verify-sha384", OPT_ARG_REQUIRED, "Verify sha384 checksums from file." },
		{ CODE_SHA512_VERIFY, "verify-sha512", OPT_ARG_REQUIRED, "Verify sha512 checksums from file." },
//		{ '', "", OPT_ARG_NONE, "" },
		{ 0, NULL, OPT_ARG_NONE, NULL }
	};
	opt_ctx_t optctx = {
		.flags = OPT_PARSE_AUTO_DISABLE_OPTIONS,
		.opts = options,
		.argv = &argv[1],
		.argc = (opt_iter_t )argc-1
	};

	g_copy_buffer = malloc(IO_BUF_SIZE);

	g_program_name = argv[0];
	if ((g_program_name == NULL) || (g_program_name[0] == 0)) {
		g_program_name = "CPSUM";
	}

	sa.sa_handler = sighandler;
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGHUP,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);

	// This will be re-initialized after the options are parsed and isn't
	// really used before then, but that may change.
	msg_init(&msg_init_struct);

	if (argc < 2) {
		ERROR("no arguments supplied");
		show_help(options);
		ret = 1;
		goto END;
	}

	dest_root = string_new();
	src_root  = string_new();

	// None of these need to be free()d before program exit.
	arguments = array_new(NULL);
	output_files = array_new(NULL);
	verify_files = array_new(NULL);

	if (gettimeofday(&tv_start, NULL) < 0) {
		msg_errno(errno, "gettimeofday() failed");
	}

	if (setjmp(g_abort_jmp) != 0) {
		ret = 1;
		goto END;
	}

	while ((opt = opt_getopt(&optctx)) != OPT_DONE) {
		switch (opt) {
			case 'h':
				show_help(options);
				ret = 0;
				goto END;
				break;
			case 't':
				string_set_from_cstring(dest_root, optctx.arg, 0);
				//If given -t, dest is always taken as a directory:
				dest_is_dir = true;
				break;
			case 'F':
				string_set_from_cstring(src_root, optctx.arg, 0);
				break;
			case 'H':
				SET_BIT(flags, OPT_FOLLOW_LINKS);
				SET_BIT(flags, OPT_FOLLOW_INITIAL_LINKS);
				break;
			case 'L':
				SET_BIT(flags, OPT_FOLLOW_LINKS);
				break;
			case 'n':
				SET_BIT(flags, OPT_NOCLOBBER);
				break;
			case 'u':
				SET_BIT(flags, OPT_UPDATE);
				if (optctx.arg != NULL) {
					char *end;

					g_update_time_fudge_seconds = strtol(optctx.arg, &end, 10);
					if ((end[0] != 0) || (end == optctx.arg) || (g_update_time_fudge_seconds < 0)) {
						ERROR("Invalid argument to -u: %s", optctx.arg);
						show_help(options);
						ret = 1;
						goto END;
					}
				}
				break;
			case 'x':
				SET_BIT(flags, OPT_NOXDEV);
				break;
			case 'i':
				SET_BIT(flags, OPT_INTERACTIVE);
				SET_BIT(msg_init_struct.flags, MSG_INTERACT);
				break;
			case 'b':
				SET_BIT(flags, OPT_BACKUP_DEST);
				if (optctx.arg != NULL) {
					if (g_backup_ext == NULL) {
						g_backup_ext = string_new();
					}
					string_set_from_cstring(g_backup_ext, optctx.arg, 0);
				}
				break;
			case 'v':
				++msg_init_struct.verbosity;
				break;
			case 'q':
				--msg_init_struct.verbosity;
				break;
			case CODE_SYNC_AFTER:
				SET_BIT(flags, OPT_SYNC_AFTER);
				break;
			case CODE_MAX_ERRORS:
				g_max_errors = get_max_fault(&optctx);
				break;
			case CODE_MAX_FAILED:
				g_max_failed = get_max_fault(&optctx);
				break;
			case CODE_MAX_WARNINGS:
				g_max_warnings = get_max_fault(&optctx);
				break;
			case CODE_PARENTS:
				SET_BIT(flags, OPT_PARENTS);
				break;
			case CODE_COPY_CONTENTS:
				SET_BIT(flags, OPT_COPY_CONTENTS);
				break;
			case CODE_SET_TEMP_EXT:
				if (g_temp_ext == NULL) {
					g_temp_ext = string_new();
				}
				string_set_from_cstring(g_temp_ext, optctx.arg, 0);
				break;
			case CODE_INCR_BACKUP:
				SET_BIT(flags, OPT_BACKUP_DEST|OPT_INCR_BACKUP);
				break;

			case 'O':
				output_fmt = optctx.arg;
				break;
			case 'o': {
				output_file_t *of = output_file_new(optctx.arg, output_fmt);
				if ((of->path[0] == '&') && (of->path[1] >= '0') && (of->path[1] <= '9')) {
					of->fd = get_arg_fd(&optctx);
				}
				array_push(output_files, of);
				break;
			}
			case CODE_MD5:
				array_push(output_files, output_file_new(optctx.arg, "%md5  %d"));
				break;
			case CODE_SHA1:
				array_push(output_files, output_file_new(optctx.arg, "%sha1  %d"));
				break;
			case CODE_SHA224:
				array_push(output_files, output_file_new(optctx.arg, "%sha224  %d"));
				break;
			case CODE_SHA256:
				array_push(output_files, output_file_new(optctx.arg, "%sha256  %d"));
				break;
			case CODE_SHA384:
				array_push(output_files, output_file_new(optctx.arg, "%sha384  %d"));
				break;
			case CODE_SHA512:
				array_push(output_files, output_file_new(optctx.arg, "%sha512  %d"));
				break;

			case CODE_MD5_VERIFY: {
				array_push(verify_files, verify_file_new(optctx.arg, CODE_MD5));
				SET_BIT(flags, FLAG_TRACK_MD5);
				break;
			}
			case CODE_SHA1_VERIFY: {
				array_push(verify_files, verify_file_new(optctx.arg, CODE_SHA1));
				SET_BIT(flags, FLAG_TRACK_SHA1);
				break;
			}
			case CODE_SHA224_VERIFY: {
				array_push(verify_files, verify_file_new(optctx.arg, CODE_SHA224));
				SET_BIT(flags, FLAG_TRACK_SHA224);
				break;
			}
			case CODE_SHA256_VERIFY: {
				array_push(verify_files, verify_file_new(optctx.arg, CODE_SHA256));
				SET_BIT(flags, FLAG_TRACK_SHA256);
				break;
			}
			case CODE_SHA384_VERIFY: {
				array_push(verify_files, verify_file_new(optctx.arg, CODE_SHA384));
				SET_BIT(flags, FLAG_TRACK_SHA384);
				break;
			}
			case CODE_SHA512_VERIFY: {
				array_push(verify_files, verify_file_new(optctx.arg, CODE_SHA512));
				SET_BIT(flags, FLAG_TRACK_SHA512);
				break;
			}

			case OPT_ARGUMENT:
				array_push(arguments, string_new_from_cstring(optctx.arg, 0));
				SET_BIT(optctx.flags, OPT_PARSE_DISABLE_OPTIONS);
				break;

			default:
				ERROR("Invalid option");
				show_help(options);
				ret = 1;
				goto END;
				break;
		}
	}
	// Initialize messages for real now.
	msg_init(&msg_init_struct);
	g_verbosity = msg_init_struct.verbosity;

	if (g_temp_ext == NULL) {
		pid_t pid = getpid();

		g_temp_ext = string_new();
		string_set_from_cstring(g_temp_ext, ".tmp.", 0);
		string_append_from_int(g_temp_ext, pid, 0, 0);
	}
	if (g_backup_ext == NULL) {
		g_backup_ext = string_new();
		string_set_from_cstring(g_backup_ext, ".bak", 0);
	}

	if (output_files->used == 0) {
		array_push(output_files, output_file_new("-", output_fmt));
	}
	for (arlen_t i = 0; i < output_files->used; ++i) {
		output_file_t *of = output_files->bank[i];

		if (of->fd >= 0) {
			// Nothing to do here
		} else if (strcmp(of->path, "-") == 0) {
			if ((of->fd = dup(fileno(stdout))) < 0) {
				ERROR_NO(errno, "stdout: can't open for writing");
				continue;
			}
		} else if ((of->fd = open(of->path, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644)) < 0) {
			ERROR_NO(errno, "%s: can't open for writing", of->path);
			continue;
		}

		SET_BIT(flags, find_format_flags(&of->fmtstr));
	}

	if (string_is_empty(dest_root)) {
		string_free(dest_root);
		array_pop(arguments, (void **)&dest_root);
	}
	if (arguments->used < 1) {
		ERROR("expected another argument");
		show_help(options);
		ret = 1;
		goto END;
	}
	if (string_is_empty(dest_root)) {
		ERROR("destination path is empty");
		show_help(options);
		ret = 1;
		goto END;
	}

	if (!dest_is_dir) {
		if (arguments->used > 1) {
			dest_is_dir = true;
		// Checked for length>0 earlier with string_is_empty()
		} else if (dest_root->cstring[dest_root->length-1] == '/') {
			dest_is_dir = true;
		} else if (file_get_type_path(dest_root->cstring, FILE_DEREF) == FILE_FT_DIR) {
			dest_is_dir = true;
		}
	}

	if (dest_is_dir) {
		string_t *empty = string_new();
		copy_path_t paths = {
			.src_path = string_new(),
			.src_root = src_root,
			.src_affix = string_new(),
			.dest_path = string_new(),
			.dest_root = dest_root,
			.dest_affix = string_new(),
		};

		string_strip_trailing(src_root, '/');
		string_strip_trailing(dest_root, '/');

		for (arlen_t i = 0; i < arguments->used; ++i) {
			string_t *src = arguments->bank[i];
			char *c;

			string_set_from_string(paths.src_affix, src);
			if (src->cstring[0] != '/') {
				paths.src_root = src_root;
			} else {
				paths.src_root = empty;
			}

			// Get rid of any leading '/' from the source path.
			for (c = src->cstring; *c == '/'; ++c) {};
			string_set_from_cstring(paths.dest_affix, c, 0);

			// Handle any trailing '..'
			while (paths.dest_affix->length >= 2) {
				string_t *s = paths.dest_affix;
				strlen_t of = s->length-2;

				if ((s->cstring[of] == '.') && (s->cstring[of+1] == '.')) {
					if ((s->length >= 3) && (s->cstring[of-1] == '/')) {
						string_pop_path(paths.dest_affix);
						string_pop_path(paths.dest_affix);
					} else {
						// There's no good way to handle empty destinations, but
						// using '.' is at least acceptable.
						if (s->length == 2) {
							string_set_from_char(s, '.');
						}
						break;
					}
				} else {
					break;
				}
			}
			if (!BIT_IS_SET(flags, OPT_PARENTS)) {
				string_basename(paths.dest_affix, '/');
			}

			if (!string_is_empty(paths.src_root)) {
				string_set_from_string(paths.src_path, paths.src_root);
				string_append_from_char(paths.src_path, '/');
				string_append_from_string(paths.src_path, paths.src_affix);
			} else {
				string_set_from_string(paths.src_path, paths.src_affix);
			}
			string_set_from_string(paths.dest_path, paths.dest_root);
			string_append_from_char(paths.dest_path, '/');
			string_append_from_string(paths.dest_path, paths.dest_affix);

			copy_src(&paths, flags);
		}
#if DEBUG
		string_free(empty);
		string_free(paths.src_path);
		string_free(paths.src_affix);
		string_free(paths.dest_path);
		string_free(paths.dest_affix);
#endif

	} else {
		string_t *empty = string_new();
		string_t *src = arguments->bank[0];
		copy_path_t paths = {
			.src_path = string_new(),
			.src_root = src_root,
			.src_affix = src,
			.dest_path = dest_root,
			.dest_root = empty,
			// Using the same string for both the root and the affix causes the
			// path to be updated twice. Using a new copy is easier and less
			// likely to lead to future problems than just checking to see if
			// they're the same pointer when pushing the path name.
			//.dest_affix = dest_root,
			.dest_affix = string_new(),
		};

		string_strip_trailing(src_root, '/');
		if (src->cstring[0] == '/') {
			paths.src_root = empty;
		}
		if (!string_is_empty(paths.src_root)) {
			string_set_from_string(paths.src_path, paths.src_root);
			string_append_from_char(paths.src_path, '/');
			string_append_from_string(paths.src_path, paths.src_affix);
		} else {
			string_set_from_string(paths.src_path, paths.src_affix);
		}
		string_set_from_string(paths.dest_affix, dest_root);

		copy_src(&paths, flags);

#if DEBUG
		string_free(empty);
		string_free(paths.src_path);
		string_free(paths.dest_affix);
#endif
	}

END:
	if (g_total_files > 0) {
		uint_t s, us;

		timeval_diff(&tv_start, NULL, &s, &us);
		msg_print(MSG_VERB_NORM, "%lu bytes copied from %u files in %u.%06u seconds.", (long unsigned )g_total_bytes, (uint_t )g_total_files, s, us);
	}

	if ((g_error_count > 0) || (g_warning_count > 0)) {
		fprintf(stderr, "%s: %u error(s) and %u warning(s) encountered.\n", g_program_name, (uint_t )g_error_count, (uint_t )g_warning_count);
	}
	if ((g_failed_count > 0) || (g_unverified_count > 0)) {
		fprintf(stderr, "%s: %u files failed verification and %u files could not be verified.\n", g_program_name, (uint_t )g_failed_count, (uint_t )g_unverified_count);
	}

	return ret;
}
