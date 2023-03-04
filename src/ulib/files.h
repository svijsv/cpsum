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
// files.h
// Manage files
// NOTES:
//    Unless otherwise noted, functions which return an error code return 0
//    for success and -errno for fatal errors and errno for non-fatal errors
//    where 'errno' is the errno number corresponding to the problem encountered.
//
//    File descriptors named 'atfd' or similar are directories relative to which
//    paths are specified. AT_FDCWD is a valid argument to work with the current
//    directory.
//
//    All functions accept a 'flags' argument even when unused. With few exceptions
//    flags are passed on to other called functions called internally.
//
//    Right now this is all written for POSIX systems.
//
//    Most of the functions here require _POSIX_C_SOURCE to be set to 200809L
//    or higher.
//
//    Some functions require _XOPEN_SOURCE to be set to 500 or higher, these
//    will compiled out if it's not.
//
#ifdef __cplusplus
 extern "C" {
#endif
#ifndef _ULIB_FILES_H
#define _ULIB_FILES_H

#include "configify.h"
#if ULIB_ENABLE_FILES

#include "strings.h"
#include "types.h"

#include <sys/stat.h>


//
//  File type definitions used by file_get_type().
//
typedef enum {
	// File doesn't exist:
	FILE_FT_NONE    = 0,
	// Directory:
	FILE_FT_DIR     = 1,
	// Regular file:
	FILE_FT_REG     = 2,
	// Block device:
	FILE_FT_BLK     = 3,
	// FIFO:
	FILE_FT_FIFO    = 4,
	// Socket:
	FILE_FT_SOCK    = 5,
	// Symbolic link:
	FILE_FT_LNK     = 6,
	// Character device:
	FILE_FT_CHR     = 7,
	// File type isn't recognized:
	FILE_FT_UNKNOWN = 127,
} file_type_t;
//
//  Behavior flags
//
typedef uint_fast16_t file_flag_t;
// Don't cross volumes during recursive actions:
static const file_flag_t FILE_NOXVOL       = 0x0001U;
// Dereference symbolic links as encountered:
static const file_flag_t FILE_DEREF        = 0x0002U;
// Don't act on the passed path just the children:
static const file_flag_t FILE_ONLY_CHILDREN= 0x0004U;
// Call fdatasync() on files after modifying:
static const file_flag_t FILE_FSYNC        = 0x0008U;
// Unlink files before opening for writing or creating a new one:
static const file_flag_t FILE_UNLINK       = 0x0010U;
// Fallback to plan B if some initial action fails:
static const file_flag_t FILE_FALLBACK     = 0x0020U;
// Force continuation after (some) errors:
static const file_flag_t FILE_FORCE        = 0x0040U;
// Act recursively on the contents of a directory:
static const file_flag_t FILE_RECURSIVE    = 0x0080U;
// Merge the contents during recursive copies when the target directory already
// exists:
static const file_flag_t FILE_MERGE_CONTENTS = 0x0100U;
// Copy the contents of special files instead of the file itself:
static const file_flag_t FILE_COPY_CONTENTS = 0x0200U;

//
// Callbacks
//
// Copy callback
typedef struct {
	// The callback executed for each block of data after it's read and before
	// it's written.
	// buf is the data buffer
	// bufsize is the size of buf
	// bytes is set by the caller to the number of bytes currently in the
	// buffer and by the callback to the number of bytes that are in the buffer
	// when it returns, which shouldn't exceed bufsize. If bytes is NULL when
	// the callback is entered, all data has been copied and any cleanup should
	// be performed.
	// extra is the .extra field of this struct.
	// Return <0 (preferably a -errno value) on any error which should cause
	// the copy to abort.
	int (*block_callback)(uint8_t *restrict buf, size_t bufsize, size_t *bytes, void *extra);

	// Set by user to any data wanted passed to the callback. Ignored by files.c.
	void *extra;
} file_copy_callback_t;


//
//  file_same()
//  Check if two file names refer to the same file on disk.
//
//  Returns true for same or false for not same.
//
//  Flags:
//     FILE_DEREF: Dereference 'a' and 'b' if they're symbolic links.
//
bool file_same_stat(struct stat *a, struct stat *b, file_flag_t flags);
bool file_same_pathat(const char *a, int a_atfd, const char *b, int b_atfd, file_flag_t flags);
bool file_same_path(const char *a, const char *b, file_flag_t flags);
//
//  file_get_type()
//  Get a file's type.
//
//  Returns one of the above defined FILE_FT_* values.
//  If an error is encountered, errno is set and FILE_FT_UNKNOWN is returned.
//
//  Flags:
//     FILE_DEREF: Dereference path if it's a symbolic link.
//
file_type_t file_get_type_stat(const struct stat* st, file_flag_t flags);
file_type_t file_get_type_pathat(const char *path, int atfd, file_flag_t flags);
file_type_t file_get_type_path(const char *path, file_flag_t flags);
//
//  file_create_dir()
//  Create a directory.
//
//  Flags:
//     FILE_DEREF: Consider path to be a directory if it's a link to a directory.
//     FILE_FORCE: If FILE_UNLINK is set, ignore unlink failure.
//     FILE_UNLINK: Unlink destination before trying to create the directory.
//
int file_create_dir_at(const char *path, int atfd, mode_t mode, file_flag_t flags);
int file_create_dir(const char *path, mode_t mode, file_flag_t flags);
//
//  file_create_parent_dir()
//  Create parent directories of the passed path.
//
//  'path' is modified during the call, but returned to its original state.
//
//  Flags:
//     Same as file_create_dir().
//
int file_create_parent_dir_at(char *path, int atfd, const mode_t mode, file_flag_t flags);
int file_create_parent_dir(char *path, const mode_t mode, file_flag_t flags);
//
//  file_remove()
//  Remove a file or directory.
//
//  A check is made that '/' is not the target path.
//
//  Flags:
//     FILE_DEREF: Completely ignored. You don't want it.
//     FILE_NOXVOL: Don't cross into other mounted volumes during recursive removal.
//     FILE_ONLY_CHILDREN: Recursive removal won't touch the root path when this is given.
//     FILE_RECURSIVE: Remove recursively.
//
int file_remove_pathat(const char *path, int atfd, file_flag_t flags);
int file_remove_path(const char *path, file_flag_t flags);
//
//  file_copy_stat()
//  Copy file owner, mode, and [am]time from a stat structure to a file.
//
//  Due to limitations in glibc, the mode will not be set on symbolic links
//  when FILE_DEREF is not set.
//
//  Flags:
//     FILE_DEREF: If path is a symbolic link, operate on the target.
//
int file_copy_stat_to_fd(const struct stat* st, int path_fd, file_flag_t flags);
int file_copy_stat_to_pathat(const struct stat* st, const char *path, int atdfd, file_flag_t flags);
int file_copy_stat_to_path(const struct stat* st, const char *path, file_flag_t flags);
//
//  file_copy_bytes()
//  Copy data from one file to another.
//
//  If max_bytes is (size_t )-1, copy until the end of the source file.
//
//  If 'ret_bread' or 'ret_bwrote' aren't NULL, they are set to the number
//  of bytes read and written.
//
//  Flags:
//     FILE_FSYNC: Call fdatasync() on the destination file after successfully writing.
//
int file_copy_bytes_fd_to_fd(int src_fd, int dest_fd, size_t max_bytes, size_t *restrict ret_bread, size_t *restrict ret_bwrote, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
//
//  file_copy_file()
//  Copy a regular file.
//
//  No check is made for whether 'src' and 'dest' are the same file.
//
//  Flags:
//     FILE_DEREF: If src is a symbolic link, copy the target.
//     FILE_DIRECT_WRITE: Use unbuffered I/O when writing destination file.
//     FILE_FORCE: If FILE_UNLINK is set and unlink fails, continue anyway.
//     FILE_FSYNC: Call fdatasync() on the destination file after successfully writing.
//     FILE_UNLINK: Try to unlink destination files before opening for writing.
//
int file_copy_file_fd_to_fd(int src_fd, int dest_fd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
int file_copy_file_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
int file_copy_file_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
//
//  file_copy_special()
//  Copy a special file - i.e. device, fifo, or socket.
//
//  This requires mknodat() which in turn requires _XOPEN_SOURCE to be set
//  to >=500 in glibc.
//
//  No check is made for whether 'src' and 'dest' are the same file.
//
//  Flags:
//     FILE_DEREF: If src is a symbolic link, copy the target.
//     FILE_FORCE: If FILE_UNLINK is set and unlink fails, continue anyway.
//     FILE_UNLINK: Try to unlink destination files before creating them.
//
#if _XOPEN_SOURCE >= 500
int file_copy_special_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, file_flag_t flags);
int file_copy_special_path_to_path(const char *src, const char *dest, file_flag_t flags);
#endif
//
//  file_copy_symlink()
//  Copy a symbolic link.
//
//  No check is made for whether 'src' and 'dest' are the same file.
//
//  Flags:
//     FILE_FORCE: If FILE_UNLINK and unlink fails, continue anyway.
//                 If the buffer is too small to hold the link target, silently
//                 truncate it.
//     FILE_UNLINK: Try to unlink destination files before creating them.
//
int file_copy_symlink_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_flag_t flags);
int file_copy_symlink_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_flag_t flags);
//
//  file_copy_dir()
//  Copy a directory.
//
//  No check is made for whether 'src' and 'dest' are the same.
//
//  Flags:
//     FILE_DEREF: If src is a symbolic link, copy the target instead of failing.
//     FILE_FORCE: If also FILE_UNLINK and unlink fails, continue anyway.
//     FILE_NOXVOL: If also FILE_RECURSIVE, don't cross mounted volumes while reading 'src'.
//     FILE_RECURSIVE: Copy recursively.
//     FILE_UNLINK: Try to unlink destination before creating it.
//
int file_copy_dir_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
int file_copy_dir_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
//
//  file_copy_path()
//  Copy a file or directory.
//
//  Returns -EINVAL if src and dest are the same file.
//
//  Flags:
//     FILE_COPY_CONTENTS: Copy the contents of special files.
//     FILE_DEREF: Dereference 'src' and 'dest'.
//     FILE_FORCE: If FILE_UNLINK is set and unlink fails, continue anyway.
//     FILE_UNLINK: Try to unlink destination before copying.
//     All flags are passed to the other copy_* functions, so any flag
//     recognized by one of them can be used here.
//
int file_copy_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
int file_copy_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
//
//  file_move()
//  Move a file or directory.
//
//  No check is made for whether 'src' and 'dest' are the same.
//
//  Flags:
//     FILE_FALLBACK: Fall back to copy & delete if rename() fails.
//     FILE_FORCE: If FILE_UNLINK is set and unlink fails, continue anyway.
//     FILE_UNLINK: Try to unlink destination before creating it.
//
int file_move_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
int file_move_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
//
//  file_hlink()
//  Create a hard link to a file.
//
//  No check is made for whether 'src' and 'dest' are the same.
//
//  Flags:
//     FILE_DEREF: Dereference 'src'.
//     FILE_FORCE: If FILE_UNLINK is set and unlink fails, continue anyway.
//     FILE_FALLBACK: Fall back to copying the file if linkat() fails.
//     FILE_UNLINK: Try to unlink destination before creating it. This isn't recursive.
//
int file_hlink_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
int file_hlink_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags);
//
//  file_fsync()
//  Sync a file descryptor to disk.
//
//  Flags:
//
int file_fsync_fd(int fd, file_flag_t flags);
int file_fsync_pathat(const char *path, int atfd, file_flag_t flags);
int file_fsync_path(const char *path, file_flag_t flags);

#endif // ULIB_ENABLE_FILES
#endif // _ULIB_FILES_H
#ifdef __cplusplus
 }
#endif
