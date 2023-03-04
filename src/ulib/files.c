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
// files.c
// Manage files
// NOTES
//    Where applicable, fdatasync() and similar behavior are prefered to fsync().
//
//    If the flags used by a function are changed, the description in files.h
//    must be updated.
//
//    Check for errors in libc functions with '< 0' in order to minimize the
//    chance of carelessly checking for a file_*() function error with '== -1'.
//
//    When deciding whether to return -errno or errno, keep context in mind -
//    metadata copy errors matter more for metadata copy functions than a file
//    copy function that calls a metadata copy function.
//
//    To prevent the proliferation of duplicate checks only validate arguments
//    which are used in a function, not those which are passed on unchanged.
//
#ifdef __cplusplus
 extern "C" {
#endif

#include "files.h"
#if ULIB_ENABLE_FILES

#include "bits.h"
#include "debug.h"
#include "math.h"
#include "msg.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


#ifdef FILE_PROVIDED_BUF
extern uint8_t* FILE_PROVIDED_BUF;
#endif

#if !defined(O_CLOEXEC)
# define O_CLOEXEC 0
#endif
#if !defined(O_PATH)
# define O_PATH O_RDONLY
#endif
#if !defined(O_DSYNC)
# define O_DSYNC O_SYNC
#endif
#if !defined(O_DIRECT)
# define O_DIRECT 0
#endif

#define O_ATFD_FLAGS (O_DIRECTORY|O_RDONLY|O_PATH)
#define O_READDIR_FLAGS (O_DIRECTORY|O_RDONLY)
#define O_SYNCFD_FLAGS (O_RDONLY|O_PATH)
#define O_READ_FLAGS (O_RDONLY)
#define O_WRITE_FLAGS (O_WRONLY|O_CREAT|O_TRUNC)

#define FD_IS_VALID(_fd) (((_fd) >= 0) || ((_fd) == AT_FDCWD))
#define PATH_IS_VALID(_p) (POINTER_IS_VALID(_p) && (_p[0] != 0))
#define PATH_IS_ROOT(_p) ((_p[0] == '/') && (_p[1] == 0))
// Checking that _st.st_mode != 0 is just a cludge to see if the structure
// was initialized.
#define STAT_IS_VALID(_st) (POINTER_IS_VALID(_st) && (_st->st_mode != 0))
#define COPY_CALLBACK_IS_VALID(_cb) ((_cb == NULL) || (POINTER_IS_VALID(_cb) && POINTER_IS_VALID(_cb->block_callback)))
#define MODE_IS_VALID(_m) ((_m & 07777) == (_m))

#define VALIDIZE_MODE(_m) (_m = (_m & 07777))

// Set an errno-based return value if appropriate.
// Try to return the first error encountered.
//    If the existing return is already a fatal error code, use that.
//    Otherwise if the new value is a fatal error code, use that.
//    Otherwise if the existing return is a non-fatal error code, use that.
//    Otherwise if the new value is a non-fatal error code, use that.
//    Otherwise both are 0, so use either.
//#define SET_ERRNO_RET(_ret, _val) (_ret = (_ret < 0) ? _ret : (_val < 0) ? _val : (_ret == 0) ? _val : _ret)
INLINE int _SET_ERRNO_RET(int _ret, int _val) {
	if (_ret == 0) {
		return _val;
	} else if ((_ret > 0) && (_val < 0)) {
		return _val;
	}
	return _ret;
}
#define SET_ERRNO_RET(_ret, _val) (_ret = _SET_ERRNO_RET(_ret, _val))

//
// Helper functions
//
static int v_unlinkat(int atfd, const char *path, int flags) {
#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(FD_IS_VALID(atfd));
	assert(PATH_IS_VALID(path));

	if (!FD_IS_VALID(atfd)) {
		errno = EBADF;
		return -1;
	}
	if (!PATH_IS_VALID(path)) {
		errno = EINVAL;
		return -1;
	}
#endif
	UNUSED(atfd);
	UNUSED(flags);

	if ((unlinkat(atfd, path, flags)) < 0) {
		//if (errno == ENOENT) {
		if ((errno == ENOENT) || ((errno == EISDIR) && (unlinkat(atfd, path, flags|AT_REMOVEDIR) >= 0))) {
			return 0;
		}
		return -1;
	}

	return 0;
}
static ssize_t v_write(int fd, const void *buf, size_t count) {
	ssize_t bytes, total_bytes = 0;

#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(FD_IS_VALID(fd));
	assert(POINTER_IS_VALID(buf));

	if (!FD_IS_VALID(fd)) {
		errno = EBADF;
		return -1;
	}
	if (!POINTER_IS_VALID(buf)) {
		errno = EINVAL;
		return -1;
	}
#endif

	while (count > 0) {
		bytes = write(fd, buf, count);
		if (bytes < 0) {
			if (errno != EINTR) {
				return -1;
			}
		} else {
			count -= (size_t )bytes;
			total_bytes += bytes;
		}
	}

	return total_bytes;
}
static ssize_t v_read(int fd, void *buf, size_t count) {
	ssize_t bytes;

#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(FD_IS_VALID(fd));
	assert(POINTER_IS_VALID(buf));

	if (!FD_IS_VALID(fd)) {
		errno = EBADF;
		return -1;
	}
	if (!POINTER_IS_VALID(buf)) {
		errno = EINVAL;
		return -1;
	}
#endif

	do {
		bytes = read(fd, buf, count);
	} while ((bytes < 0) && (errno == EINTR));

	return bytes;
}
static int v_close(int fd) {
	int ret = 0;

	// According to the man page, one should never call close() on the same
	// fd a second time regardless of the success status.
	if (fd >= 0) {
		ret = close(fd);
	}

	return ret;
}
static int v_closedir(DIR *dirp) {
	if (POINTER_IS_VALID(dirp)) {
		return closedir(dirp);
	}
	return 0;
}
static int v_openat(int atfd, const char *path, int flags, mode_t mode) {
	int ret = 0;

#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(FD_IS_VALID(atfd));
	assert(PATH_IS_VALID(path));
	assert(MODE_IS_VALID(mode));

	if (!FD_IS_VALID(atfd)) {
		errno = EBADF;
		return -1;
	}
	if (!PATH_IS_VALID(path) || !MODE_IS_VALID(mode)) {
		errno = EINVAL;
		return -1;
	}
#endif

	SET_BIT(flags, O_CLOEXEC);
	do {
		ret = openat(atfd, path, flags, mode);
	} while ((ret < 0) && (errno == EINTR));

	return ret;
}
static int v_mkdirat(int atfd, const char *path, mode_t mode) {
	int ret = 0;

#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(FD_IS_VALID(atfd));
	assert(PATH_IS_VALID(path));
	assert(MODE_IS_VALID(mode));

	if (!FD_IS_VALID(atfd)) {
		errno = EBADF;
		return -1;
	}
	if (!PATH_IS_VALID(path) || !MODE_IS_VALID(mode)) {
		errno = EINVAL;
		return -1;
	}
#endif

	if ((ret = mkdirat(atfd, path, mode)) < 0) {
		if (errno == EEXIST) {
			if (file_get_type_pathat(path, atfd, FILE_DEREF) == FILE_FT_DIR) {
				ret = 0;
			}
		}
	}

	return ret;
}
static int v_fdatasync(int fd) {
	int ret = 0;

#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(FD_IS_VALID(fd));

	if (!FD_IS_VALID(fd)) {
		errno = EBADF;
		return -1;
	}
#endif

	do {
		ret = fdatasync(fd);
	} while ((ret < 0) && (errno == EINTR));

	return ret;
}
static bool is_self_link(const char *name) {
#if DO_FILE_EXTRA_SAFETY_CHECKS
	assert(POINTER_IS_VALID(name));

	if (!POINTER_IS_VALID(name)) {
		return false;
	}
#endif

	if (name[0] == '.') {
		if (name[1] == 0) {
			return true;
		} else if ((name[1] == '.') && (name[2] == 0)) {
			return true;
		}
	}
	return false;
}
static int at_flags_from_file_flags(file_flag_t flags) {
	int sflags = 0;

	if (!BIT_IS_SET(flags, FILE_DEREF)) {
		SET_BIT(sflags, AT_SYMLINK_NOFOLLOW);
	}

	return sflags;
}
// Keep errno set so that the caller doesn't need to keep a second variable
// to store the return value.
static int try_unlink(const char *path, int atfd, file_flag_t flags) {
	if (BIT_IS_SET(flags, FILE_UNLINK) && (v_unlinkat(atfd, path, 0) < 0)) {
		if (!BIT_IS_SET(flags, FILE_FORCE)) {
			return -errno;
		}
	}

	return 0;
}

//
// Exported functions
//
bool file_same_stat(struct stat *a, struct stat *b, file_flag_t flags) {
	assert(STAT_IS_VALID(a));
	assert(STAT_IS_VALID(b));

#if DO_FILE_SAFETY_CHECKS
	if (!STAT_IS_VALID(a) || !STAT_IS_VALID(b)) {
		return false;
	}
#endif

	UNUSED(flags);

	return ((a->st_rdev == b->st_rdev) && (a->st_ino == b->st_ino));
}
bool file_same_pathat(const char *a, int a_atfd, const char *b, int b_atfd, file_flag_t flags) {
	int sflags;
	struct stat ast, bst;

	assert(PATH_IS_VALID(a));
	assert(FD_IS_VALID(a_atfd));
	assert(PATH_IS_VALID(b));
	assert(FD_IS_VALID(b_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(a) || !PATH_IS_VALID(b) || !FD_IS_VALID(a_atfd) || !FD_IS_VALID(b_atfd)) {
		return false;
	}
#endif

	sflags = at_flags_from_file_flags(flags);
	if (fstatat(a_atfd, a, &ast, sflags) >= 0) {
		if (fstatat(b_atfd, b, &bst, sflags) >= 0) {
			return file_same_stat(&ast, &bst, flags);
		}
	}

	return false;
}
bool file_same_path(const char *a, const char *b, file_flag_t flags) {
	return file_same_pathat(a, AT_FDCWD, b, AT_FDCWD, flags);
}

file_type_t file_get_type_stat(const struct stat* st, file_flag_t flags) {
	assert(STAT_IS_VALID(st));

#if DO_FILE_SAFETY_CHECKS
	if (!STAT_IS_VALID(st)) {
		errno = EINVAL;
		return FILE_FT_UNKNOWN;
	}
#endif

	UNUSED(flags);

	switch (st->st_mode & S_IFMT) {
		case S_IFREG:
			return FILE_FT_REG;
			break;
		case S_IFDIR:
			return FILE_FT_DIR;
			break;
		case S_IFCHR:
			return FILE_FT_CHR;
			break;
		case S_IFBLK:
			return FILE_FT_BLK;
			break;
		case S_IFIFO:
			return FILE_FT_FIFO;
			break;
		case S_IFSOCK:
			return FILE_FT_SOCK;
			break;
		case S_IFLNK:
			return FILE_FT_LNK;
			break;
	}

	errno = ENOTSUP;
	return FILE_FT_UNKNOWN;
}
file_type_t file_get_type_pathat(const char *path, int atfd, file_flag_t flags) {
	int sflags;
	struct stat st;

	assert(PATH_IS_VALID(path));
	assert(FD_IS_VALID(atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(path)) {
		errno = EINVAL;
		return FILE_FT_UNKNOWN;
	}
	if (!FD_IS_VALID(atfd)) {
		errno = EBADF;
		return FILE_FT_UNKNOWN;
	}
#endif

	sflags = at_flags_from_file_flags(flags);

	if (fstatat(atfd, path, &st, sflags) < 0) {
		return FILE_FT_NONE;
	}

	return file_get_type_stat(&st, flags);
}
file_type_t file_get_type_path(const char *path, file_flag_t flags) {
	return file_get_type_pathat(path, AT_FDCWD, flags);
}

int file_create_dir_at(const char *path, int atfd, mode_t mode, file_flag_t flags) {
	assert(PATH_IS_VALID(path));
	assert(FD_IS_VALID(atfd));
	assert(MODE_IS_VALID(mode));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(path) || !MODE_IS_VALID(mode)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(atfd)) {
		return -EBADF;
	}
#endif

	if (try_unlink(path, atfd, flags) < 0) {
		return -errno;
	}

	if (v_mkdirat(atfd, path, mode) < 0) {
		return -errno;
	}

	return 0;
}
int file_create_dir(const char *path, mode_t mode, file_flag_t flags) {
	return file_create_dir_at(path, AT_FDCWD, mode, flags);
}

int file_create_parent_dir_at(char *path, int atfd, const mode_t mode, file_flag_t flags) {
	int ret = 0;
	size_t len, i;
	size_t name_i;

	assert(PATH_IS_VALID(path));
	assert(FD_IS_VALID(atfd));
	assert(MODE_IS_VALID(mode));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(path) || !MODE_IS_VALID(mode)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(atfd)) {
		return -EBADF;
	}
#endif

	len = strlen(path);
	// Skip any trailing '/'
	for (name_i = len-1; (name_i > 0) && (path[name_i] == '/'); --name_i) {
		// Nothing to do here
	}
	// Need to skip the last part of the path, we're only creating the parents.
	for (; (name_i > 0) && (path[name_i] != '/'); --name_i) {
		// Nothing to do here
	}
	if (name_i == 0) {
		return 0;
	}
	path[name_i] = 0;

	for (i = 0; path[i] != 0; ++i) {
		if (path[i] == '/') {
			path[i] = 0;
			ret = file_create_dir_at(path, atfd, mode, flags);
			path[i] = '/';

			if (ret < 0) {
				break;
			}
		}
	}

	path[name_i] = '/';
	return ret;
}
int file_create_parent_dir(char *path, const mode_t mode, file_flag_t flags) {
	return file_create_parent_dir_at(path, AT_FDCWD, mode, flags);
}

static int file_remove_dir_contents_pathat(const char *path, int atfd, uint16_t depth, struct stat *st_dir, file_flag_t flags) {
	int ret = 0;
	dev_t vid;
	struct stat st;
	int cfd = -1, tfd = -1;
	DIR *dirp = NULL;
	struct dirent *dire;

	assert(PATH_IS_VALID(path));
	assert(FD_IS_VALID(atfd));
	assert(depth >= 1);

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(path)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(atfd)) {
		return -EBADF;
	}
#endif

	if (depth < 1) {
		depth = 1;
	}
	if ((FILE_MAX_RECURSION > 0) && (depth > FILE_MAX_RECURSION)) {
		return -ELOOP;
	}

	if (st_dir == NULL) {
		if (fstatat(atfd, path, &st, AT_SYMLINK_NOFOLLOW) < 0) {
			return -errno;
		}
		st_dir = &st;
	}
	vid = st_dir->st_dev;

	if (!S_ISDIR(st_dir->st_mode)) {
		return -ENOTDIR;
	}

	// The specified path is always dereferenced because we're expected to
	// only operate on directories - the caller must check for symlinks if
	// required.
	if ((cfd = v_openat(atfd, path, O_READDIR_FLAGS, 0)) < 0) {
		return -errno;
	}
	// This is done because the man page for fdopendir() says not to
	// use the fd passed to it afterwards; it may not be necessary.
	if ((tfd = dup(cfd)) < 0) {
		v_close(cfd);
		return -errno;
	}
	if ((dirp = fdopendir(tfd)) == NULL) {
		v_close(cfd);
		v_close(tfd);
		return -errno;
	}
	errno = 0;
	for (dire = readdir(dirp); dire != NULL; dire = readdir(dirp)) {
		if (is_self_link(dire->d_name)) {
			continue;
		}

		// Don't check for FILE_DEREF here, since that's very probably not
		// what's intended by the caller.
		if (fstatat(cfd, dire->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
			ret = errno;
			continue;
		}
		if (BIT_IS_SET(flags, FILE_NOXVOL) && (st.st_dev != vid)) {
			continue;
		}

		// Handling the directory/file check here saves a recursive call for
		// files.
		if (S_ISDIR(st.st_mode)) {
			int ee;

			if ((ee = file_remove_dir_contents_pathat(dire->d_name, cfd, depth+1, &st, flags)) < 0) {
				SET_ERRNO_RET(ret, ee);
				continue;
			}
		}
		if (v_unlinkat(cfd, dire->d_name, 0) < 0) {
			SET_ERRNO_RET(ret, -errno);
			continue;
		}
		errno = 0;
	}
	if (errno != 0) {
		ret = -errno;
	}

	v_closedir(dirp);
	v_close(cfd);
	return ret;
}
int file_remove_pathat(const char *path, int atfd, file_flag_t flags) {
	int ret = 0;
	struct stat st;

	assert(PATH_IS_VALID(path));
	assert(FD_IS_VALID(atfd));
	assert(!BIT_IS_SET(flags, FILE_DEREF));
	// Don't want to remove the root directory now do we?
	assert(!PATH_IS_ROOT(path));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(path)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(atfd)) {
		return -EBADF;
	}
#endif
	if (PATH_IS_ROOT(path)) {
		return -EINVAL;
	}
	// Trying to deref a removal could be catastrophic...
	flags = MASK_BITS(flags, FILE_DEREF);

	if (fstatat(atfd, path, &st, AT_SYMLINK_NOFOLLOW) < 0) {
		return -errno;
	}
	if (BIT_IS_SET(flags, FILE_RECURSIVE) && S_ISDIR(st.st_mode)) {
		ret = file_remove_dir_contents_pathat(path, atfd, 1, &st, flags);
	}
	if ((ret >= 0) && !BIT_IS_SET(flags, FILE_ONLY_CHILDREN)) {
		if (v_unlinkat(atfd, path, 0) < 0) {
			if (errno != ENOENT) {
				ret = -errno;
			}
		}
	}

	return ret;
}
int file_remove_path(const char *path, file_flag_t flags) {
	return file_remove_pathat(path, AT_FDCWD, flags);
}

int file_copy_stat_to_fd(const struct stat* st, int dest_fd, file_flag_t flags) {
	int ret = 0;
	struct timespec tv[2];

	assert(STAT_IS_VALID(st));
	assert(FD_IS_VALID(dest_fd));

#if DO_FILE_SAFETY_CHECKS
	if (!STAT_IS_VALID(st)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(dest_fd)) {
		return -EBADF;
	}
#endif

	UNUSED(flags);

	tv[0].tv_sec  = st->st_atime;
	tv[0].tv_nsec = st->st_atim.tv_nsec;
	tv[1].tv_sec  = st->st_mtime;
	tv[1].tv_nsec = st->st_mtim.tv_nsec;

	if (fchown(dest_fd, st->st_uid, st->st_gid) < 0) {
		ret = -errno;
	}
	if (fchmod(dest_fd, 07777 & st->st_mode) < 0) {
		ret = -errno;
	}
	if (futimens(dest_fd, tv) < 0) {
		ret = -errno;
	}

	return ret;
}
int file_copy_stat_to_pathat(const struct stat* st, const char *path, int atfd, file_flag_t flags) {
	int ret = 0;
	int fflags = 0;
	struct timespec tv[2];

	assert(STAT_IS_VALID(st));
	assert(PATH_IS_VALID(path));
	assert(FD_IS_VALID(atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!STAT_IS_VALID(st) || !PATH_IS_VALID(path)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(atfd)) {
		return -EBADF;
	}
#endif

	fflags = at_flags_from_file_flags(flags);

	tv[0].tv_sec  = st->st_atime;
	tv[0].tv_nsec = st->st_atim.tv_nsec;
	tv[1].tv_sec  = st->st_mtime;
	tv[1].tv_nsec = st->st_mtim.tv_nsec;

	if (fchownat(atfd, path, st->st_uid, st->st_gid, fflags) < 0) {
		ret = -errno;
	}
	// FIXME
	// As of 2023.01.06 the AT_SYMLINK_NOFOLLOW flag isn't actually implemented
	// for fchmodat() in Glibc and attempting to use it returns an error.
	if ((BIT_IS_SET(flags, FILE_DEREF) || !S_ISLNK(st->st_mode)) && (fchmodat(atfd, path, 07777 & st->st_mode, MASK_BITS(fflags, AT_SYMLINK_NOFOLLOW)) < 0)) {
		ret = -errno;
	}
	if (utimensat(atfd, path, tv, fflags) < 0) {
		ret = -errno;
	}

	return ret;
}
int file_copy_stat_to_path(const struct stat* st, const char *path, file_flag_t flags) {
	return file_copy_stat_to_pathat(st, path, AT_FDCWD, flags);
}

int file_copy_bytes_fd_to_fd(int src_fd, int dest_fd, size_t max_bytes, size_t *ret_bread, size_t *ret_bwrote, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int ret = 0;
	int tmp;
	ssize_t sbytes;
	size_t bytes, expected;
	size_t bwrote = 0, bread = 0;
	size_t todo;

	assert(FD_IS_VALID(src_fd));
	assert(FD_IS_VALID(dest_fd));
	assert(COPY_CALLBACK_IS_VALID(copy_callback));
#ifdef FILE_PROVIDED_BUF
	if (buf == NULL) {
		buf = FILE_PROVIDED_BUF;
		bufsize = FILE_PROVIDED_BUF_SIZE;
	}
#endif
	assert(POINTER_IS_VALID(buf));
	assert(bufsize > 0);

#if DO_FILE_SAFETY_CHECKS
	if (!POINTER_IS_VALID(buf) || (bufsize <= 0)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_fd) || !FD_IS_VALID(dest_fd)) {
		return -EBADF;
	}
	if (!COPY_CALLBACK_IS_VALID(copy_callback)) {
		return -EINVAL;
	}
#endif

	while ((max_bytes == (size_t )-1) || (bread < max_bytes)) {
		if (max_bytes == (size_t )-1) {
			todo = bufsize;
		} else {
			todo = max_bytes - bread;
			todo = MIN(todo, bufsize);
		}

		sbytes = v_read(src_fd, buf, todo);
		if (sbytes < 0) {
			ret = -errno;
			goto END;
		}
		if (sbytes == 0) {
			goto END;
		}
		bytes = (size_t )sbytes;
		bread += bytes;

		if (copy_callback != NULL) {
			if ((tmp = copy_callback->block_callback(buf, bufsize, &bytes, copy_callback->extra)) != 0) {
				SET_ERRNO_RET(ret, tmp);
				if (tmp < 0) {
					goto END;
				}
			}
		}

		expected = bytes;
		sbytes = v_write(dest_fd, buf, bytes);
		if (sbytes < 0) {
			ret = -errno;
			goto END;
		}
		bytes = (size_t )sbytes;
		bwrote += bytes;
		if (expected != bytes) {
			ret = -EIO;
			goto END;
		}
	}

END:
	if (copy_callback != NULL) {
		if ((tmp = copy_callback->block_callback(buf, bufsize, NULL, copy_callback->extra)) != 0) {
			SET_ERRNO_RET(ret, tmp);
		}
	}
	if (BIT_IS_SET(flags, FILE_FSYNC) && (v_fdatasync(dest_fd) < 0)) {
		tmp = -errno;
		SET_ERRNO_RET(ret, tmp);
	}

	if (ret_bread != NULL) {
		*ret_bread = bread;
	}
	if (ret_bwrote != NULL) {
		*ret_bwrote = bwrote;
	}

	return ret;
}

int file_copy_file_fd_to_fd(int src_fd, int dest_fd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int ret = 0, tmp;
	struct stat st;

	assert(FD_IS_VALID(src_fd));
	assert(FD_IS_VALID(dest_fd));

#if DO_FILE_SAFETY_CHECKS
	if (!FD_IS_VALID(src_fd) || !FD_IS_VALID(dest_fd)) {
		return -EBADF;
	}
#endif

	// Mask the FILE_FSYNC flag because we're going to change some of the metadata
	// after the copy.
	if ((tmp = file_copy_bytes_fd_to_fd(src_fd, dest_fd, (size_t )-1, NULL, NULL, buf, bufsize, copy_callback, MASK_BITS(flags, FILE_FSYNC))) != 0) {
		SET_ERRNO_RET(ret, tmp);
		if (tmp < 0) {
			goto END;
		}
	}

	if (fstat(src_fd, &st) < 0) {
		ret = -errno;
	} else if ((tmp = file_copy_stat_to_fd(&st, dest_fd, flags)) != 0) {
		tmp = ABS(tmp);
		SET_ERRNO_RET(ret, tmp);
	}

	if (BIT_IS_SET(flags, FILE_FSYNC) && (v_fdatasync(dest_fd) < 0)) {
		tmp = -errno;
		SET_ERRNO_RET(ret, tmp);
	}

END:
	return ret;
}
int file_copy_file_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int ret = 0;
	int src_fd = -1, dest_fd = -1;
	int read_flags = O_READ_FLAGS;
	int write_flags = O_WRITE_FLAGS;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	if (try_unlink(dest, dest_atfd, flags) < 0) {
		return -errno;
	}

	if ((src_fd = v_openat(src_atfd, src, read_flags, 0)) < 0) {
		ret = -errno;
		goto END;
	}
	if ((dest_fd = v_openat(dest_atfd, dest, write_flags, 0700)) < 0) {
		ret = -errno;
		goto END;
	}

	ret = file_copy_file_fd_to_fd(src_fd, dest_fd, buf, bufsize, copy_callback, flags);

END:
	v_close(src_fd);
	v_close(dest_fd);
	return ret;
}
int file_copy_file_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	return file_copy_file_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, buf, bufsize, copy_callback, flags);
}

#if _XOPEN_SOURCE >= 500
int file_copy_special_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, file_flag_t flags) {
	struct stat st;
	int sflags;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	sflags = at_flags_from_file_flags(flags);
	if (fstatat(src_atfd, src, &st, sflags) < 0) {
		return -errno;
	}

	if (try_unlink(dest, dest_atfd, flags) < 0) {
		return -errno;
	}

	switch (file_get_type_stat(&st, flags)) {
		case FILE_FT_CHR:
		case FILE_FT_BLK:
		case FILE_FT_FIFO:
		case FILE_FT_SOCK:
			if (mknodat(dest_atfd, dest, st.st_mode, st.st_rdev) < 0) {
				return -errno;
			} else {
				int tmp = file_copy_stat_to_pathat(&st, dest, dest_atfd, flags);
				return ABS(tmp);
			}
			break;
		default:
			return -EINVAL;
			break;
	}

	return -ENOTSUP;
}
int file_copy_special_path_to_path(const char *src, const char *dest, file_flag_t flags) {
	return file_copy_special_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, flags);
}
#endif // _XOPEN_SOURCE >= 500
int file_copy_symlink_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_flag_t flags) {
	int ret = 0;
	ssize_t ls = 0;
	struct stat st;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));
#ifdef FILE_PROVIDED_BUF
	if (buf == NULL) {
		buf = FILE_PROVIDED_BUF;
		bufsize = FILE_PROVIDED_BUF_SIZE;
	}
#endif
	assert(POINTER_IS_VALID(buf));
	assert(bufsize > 0);

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest) || !POINTER_IS_VALID(buf) || (bufsize <= 0)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	if (try_unlink(dest, dest_atfd, flags) < 0) {
		return -errno;
	}

	ls = readlinkat(src_atfd, src, (char *)buf, bufsize-1);
	if (ls < 0) {
		return -errno;
	}
	if ((size_t )ls < bufsize) {
		buf[ls] = 0;
	} else {
		if (BIT_IS_SET(flags, FILE_FORCE)) {
			buf[bufsize-1] = 0;
		} else {
			return -ENAMETOOLONG;
		}
	}

	if (symlinkat((char *)buf, dest_atfd, dest) < 0) {
		return -errno;
	}

	// There wouldn't be any reason to allow dereferencing the link here.
	if (fstatat(src_atfd, src, &st, AT_SYMLINK_NOFOLLOW) < 0) {
		return -errno;
	}
	ret = file_copy_stat_to_pathat(&st, dest, dest_atfd, 0);
	ret = ABS(ret);

	return ret;
}
int file_copy_symlink_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_flag_t flags) {
	return file_copy_symlink_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, buf, bufsize, flags);
}

static int file_copy_bare_dir(const char *src, int src_atfd, struct stat *src_st, const char *dest, int dest_atfd, file_flag_t flags) {
	int ret = 0;
	int tmp;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));
	assert(STAT_IS_VALID(src_st));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest) || !STAT_IS_VALID(src_st)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	if (!S_ISDIR(src_st->st_mode)) {
		return -ENOTDIR;
	}

	if (try_unlink(dest, dest_atfd, flags) < 0) {
		if ((errno != ENOTEMPTY) || !BIT_IS_SET(flags, FILE_MERGE_CONTENTS)) {
			return -errno;
		}
	}

	if (v_mkdirat(dest_atfd, dest, 0700) < 0) {
		return -errno;
	}
	if ((tmp = file_copy_stat_to_pathat(src_st, dest, dest_atfd, flags)) != 0) {
		ret = ABS(tmp);
	}

	return ret;
}
static int file_copy_dir_recursive(const char *src, int src_atfd, struct stat *src_st, const char *dest, int dest_atfd, uint16_t depth, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int ret = 0, tmp;
	int csrc_atfd = -1, cdest_atfd = -1, tfd;
	DIR* dir = NULL;
	struct dirent* ent = NULL;
	file_flag_t cflags;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif
	if (depth < 1) {
		depth = 1;
	}
	if ((FILE_MAX_RECURSION > 0) && (depth > FILE_MAX_RECURSION)) {
		return -ELOOP;
	}

	if ((tmp = file_copy_bare_dir(src, src_atfd, src_st, dest, dest_atfd, flags)) != 0) {
		if (tmp < 0) {
			return tmp;
		}
		ret = tmp;
	}

	if ((cdest_atfd = v_openat(dest_atfd, dest, O_ATFD_FLAGS, 0)) < 0) {
		ret = -errno;
		goto END;
	}
	if ((csrc_atfd = v_openat(src_atfd, src, O_READDIR_FLAGS, 0)) < 0) {
		ret = -errno;
		goto END;
	}
	// This is done because the man page for fdopendir() says not to
	// use the fd passed to it afterwards; it may not be necessary.
	if ((tfd = dup(csrc_atfd)) < 0) {
		ret = -errno;
		goto END;
	}
	if ((dir = fdopendir(tfd)) == NULL) {
		ret = -errno;
		goto END;
	}

	errno = 0;
	// Don't dereference the child, we don't support that kind of recursive
	// copying.
	cflags = MASK_BITS(flags, FILE_DEREF);
	while ((ent = readdir(dir)) != NULL) {
		struct stat st;

		if (is_self_link(ent->d_name)) {
			continue;
		}
		// FIXME: Should this check for FILE_FORCE and return a non-error value
		// when set?
		if (fstatat(csrc_atfd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
			SET_ERRNO_RET(ret, -errno);
			continue;
		}
		if (BIT_IS_SET(flags, FILE_NOXVOL) && (st.st_dev != src_st->st_dev)) {
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			if ((tmp = file_copy_dir_recursive(ent->d_name, csrc_atfd, &st, ent->d_name, cdest_atfd, depth+1, buf, bufsize, copy_callback, cflags)) != 0) {
				SET_ERRNO_RET(ret, tmp);
				/*
				if ((tmp < 0) && !BIT_IS_SET(flags, FILE_FORCE)) {
					goto END;
				}
				*/
			}
		} else {
			if ((tmp = file_copy_pathat_to_pathat(ent->d_name, csrc_atfd, ent->d_name, cdest_atfd, buf, bufsize, copy_callback, cflags)) != 0) {
				SET_ERRNO_RET(ret, tmp);
				/*
				if ((tmp < 0) && !BIT_IS_SET(flags, FILE_FORCE)) {
					goto END;
				}
				*/
			}
		}
		errno = 0;
	}
	if ((errno != 0) && (ret >= 0)) {
		tmp = -errno;
		SET_ERRNO_RET(ret, tmp);
	}

	// The metadata was copied in file_copy_bare_dir() but the modification
	// time would have been updated during the copy so we need to set it again.
	if ((tmp = file_copy_stat_to_pathat(src_st, dest, dest_atfd, flags)) != 0) {
		tmp = ABS(tmp);
		SET_ERRNO_RET(ret, tmp);
	}

END:
	v_closedir(dir);
	v_close(csrc_atfd);
	v_close(cdest_atfd);

	return ret;
}
int file_copy_dir_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int sflags = 0;
	struct stat src_st;

	assert(PATH_IS_VALID(src));
	assert(FD_IS_VALID(src_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd)) {
		return -EBADF;
	}
#endif

	sflags = at_flags_from_file_flags(flags);
	if (fstatat(src_atfd, src, &src_st, sflags) < 0) {
		return -errno;
	}

	if (BIT_IS_SET(flags, FILE_RECURSIVE)) {
		return file_copy_dir_recursive(src, src_atfd, &src_st, dest, dest_atfd, 1, buf, bufsize, copy_callback, flags);
	} else {
		return file_copy_bare_dir(src, src_atfd, &src_st, dest, dest_atfd, flags);
	}

	return 0;
}
int file_copy_dir_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	return file_copy_dir_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, buf, bufsize, copy_callback, flags);
}

int file_copy_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int sflags = 0;
	struct stat sst, dst;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	// This is handled in the specific functions
	/*
	if (try_unlink(dest, dest_atfd, flags) < 0) {
		return -errno;
	}
	*/

	sflags = at_flags_from_file_flags(flags);
	if (fstatat(src_atfd, src, &sst, sflags) >= 0) {
		if (fstatat(dest_atfd, dest, &dst, sflags) >= 0) {
			if (file_same_stat(&sst, &dst, flags)) {
				return -EINVAL;
			}
		}
	} else {
		return -errno;
	}

	switch (file_get_type_stat(&sst, flags)) {
		case FILE_FT_REG:
			return file_copy_file_pathat_to_pathat(src, src_atfd, dest, dest_atfd, buf, bufsize, copy_callback, flags);
			break;
		case FILE_FT_DIR:
			return file_copy_dir_pathat_to_pathat(src, src_atfd, dest, dest_atfd, buf, bufsize, copy_callback, flags);
			break;
		case FILE_FT_BLK:
		case FILE_FT_CHR:
		case FILE_FT_FIFO:
		case FILE_FT_SOCK:
			if (BIT_IS_SET(flags, FILE_COPY_CONTENTS)) {
				return file_copy_file_pathat_to_pathat(src, src_atfd, dest, dest_atfd, buf, bufsize, copy_callback, flags);
			}
#if _XOPEN_SOURCE >= 500
			else {
				return file_copy_special_pathat_to_pathat(src, src_atfd, dest, dest_atfd, flags);
			}
#endif // _XOPEN_SOURCE >= 500
			break;
		case FILE_FT_LNK:
			return file_copy_symlink_pathat_to_pathat(src, src_atfd, dest, dest_atfd, buf, bufsize, flags);
			break;
		case FILE_FT_NONE:
			return -ENOENT;
			break;
		case FILE_FT_UNKNOWN:
			break;
	}

	return -ENOTSUP;
}
int file_copy_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	return file_copy_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, buf, bufsize, copy_callback, flags);
}

int file_move_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int ret = 0, tmp;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	if (try_unlink(dest, dest_atfd, flags) < 0) {
		return -errno;
	}

	if (renameat(src_atfd, src, dest_atfd, dest) < 0) {
		file_flag_t pflags = flags|FILE_RECURSIVE;

		if (BIT_IS_SET(flags, FILE_FALLBACK)) {
			if ((ret = file_copy_pathat_to_pathat(src, src_atfd, dest, dest_atfd, buf, bufsize, copy_callback, pflags)) >= 0) {
				if ((tmp = file_remove_pathat(src, src_atfd, pflags)) != 0) {
					SET_ERRNO_RET(ret, tmp);
				}
			}
		} else {
			ret = -errno;
		}
	}

	return ret;
}
int file_move_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	return file_move_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, buf, bufsize, copy_callback, flags);
}

int file_hlink_pathat_to_pathat(const char *src, int src_atfd, const char *dest, int dest_atfd, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	int ret = 0;
	int sflags = 0;

	assert(PATH_IS_VALID(src));
	assert(PATH_IS_VALID(dest));
	assert(FD_IS_VALID(src_atfd));
	assert(FD_IS_VALID(dest_atfd));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(src) || !PATH_IS_VALID(dest)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(src_atfd) || !FD_IS_VALID(dest_atfd)) {
		return -EBADF;
	}
#endif

	sflags = at_flags_from_file_flags(flags);

	if (try_unlink(dest, dest_atfd, flags) < 0) {
		return -errno;
	}

	if (linkat(src_atfd, src, dest_atfd, dest, sflags) < 0) {
		if ((errno == EXDEV) || (errno == EMLINK) || (errno == EPERM)) {
			if (BIT_IS_SET(flags, FILE_FALLBACK)) {
				ret = file_copy_file_pathat_to_pathat(src, src_atfd, dest, dest_atfd, buf, bufsize, copy_callback, flags);
			} else {
				ret = -errno;
			}
		} else {
			ret = -errno;
		}
	}

	return ret;
}
int file_hlink_path_to_path(const char *src, const char *dest, uint8_t *restrict buf, size_t bufsize, file_copy_callback_t *copy_callback, file_flag_t flags) {
	return file_hlink_pathat_to_pathat(src, AT_FDCWD, dest, AT_FDCWD, buf, bufsize, copy_callback, flags);
}

int file_fsync_fd(int fd, file_flag_t flags) {
	int ret = 0;

	assert(FD_IS_VALID(fd));

#if DO_FILE_SAFETY_CHECKS
	if (!FD_IS_VALID(fd)) {
		return -EBADF;
	}
#endif

	UNUSED(flags);

	if (v_fdatasync(fd) < 0) {
		ret = -errno;
	}

	return ret;
}
int file_fsync_pathat(const char *path, int atfd, file_flag_t flags) {
	int fd;
	int ret = 0;
	int oflags = O_SYNCFD_FLAGS;

	assert(FD_IS_VALID(atfd));
	assert(PATH_IS_VALID(path));

#if DO_FILE_SAFETY_CHECKS
	if (!PATH_IS_VALID(path)) {
		return -EINVAL;
	}
	if (!FD_IS_VALID(atfd)) {
		return -EBADF;
	}
#endif

	if ((fd = v_openat(atfd, path, oflags, 0)) < 0) {
		return -errno;
	}

	ret = file_fsync_fd(fd, flags);

	v_close(fd);

	return ret;
}
int file_fsync_path(const char *path, file_flag_t flags) {
	return file_fsync_pathat(path, AT_FDCWD, flags);
}


#else
	// ISO C forbids empty translation units, this makes it happy.
	typedef int make_iso_compilers_happy;
#endif // ULIB_ENABLE_FILES
#ifdef __cplusplus
 }
#endif
