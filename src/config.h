//
// config.h
// Configuration file for cpsum
//
//
// Size of read/write buffer.
#ifndef IO_BUF_SIZE
# define IO_BUF_SIZE (4U * 1024U * 1024U)
#endif
//
// Maximum depth of directory trees.
#ifndef RECURSION_MAX
# define RECURSION_MAX 64
#endif
//
// Permissions on newly-created directories. Affected by the process umask
// in the normal way.
#ifndef NEWDIR_PERMS
# define NEWDIR_PERMS 0755
#endif
//
// The base character used when printing hex digits. Use 'a' for lowercase
// and 'A' for uppercase.
#ifndef HEX_BASECHAR
# define HEX_BASECHAR 'a'
#endif
