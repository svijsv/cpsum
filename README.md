**cpsum** is a command-line utility for copying files while simultaneously
generating and/or verifying checksums for those files. The only benefit it
has over separate copy/generate/verify steps is that the file is only read
from and written to disk once which is often useful with slower media.

### Building
Build using `make [release|debug]` from the root of the repository. The
resulting executable is `out/cpsum`.

### Usage
```
cpsum [options] source [source2 [...]] destination
cpsum [options] -t destination source [source2 [...]]

Recognized options:
   -b[ARG], --backup[=ARG]
       Backup existing destination files. Use [ARG] as the suffix if supplied.

   --copy-contents
       Copy the contents of special files instead of the file itself.

   -F ARG, --source ARG
       Interpret source paths relative to directory.
       Source files beginning with '/' ignore this.

   --fsync-after
       Call fdatasync() on each destination file after copying.

   -h, --help
       Show program help.

   -H, --dereference-initial
       Follow symbolic links in sources named on the command line.

   -i, --interactive
       Ask before overwriting existing destination files.

   --incr-backup
       When backing up existing destination files, append a number if the backup file also exists.
       Implies --backup.

   -L, --dereference
       Always follow symbolic links when encountered.

   --max-errors ARG
       Abort if more than this many errors are encountered.
       Set to '-1' to disable (default).

   --max-failed ARG
       Abort if more than this many files fail verification.
       Set to '-1' to disable (default).

   --max-warnings ARG
       Abort if more than this many warnings+errors are encountered.
       Set to '-1' to disable (default).

   -n, --no-clobber
       Don't replace existing destination files.

   -o ARG, --output-file ARG
       Print checksums to file. Can be specified multiple times.
       '-' is treated as stdout and names of the form '&<N>' are treated as open file descriptors.
       Existing files are appended to.

   -O ARG, --output-format ARG
       Specify output format. Only applies to output files specified after it with -o.

   --parents
       Use full source file name under destination.

   -q, --quiet
       Print less information to stdout. Can be given multiple times.

   --set-temp-ext ARG
       Set the temporary file extension. Set to "" to write directly to destination files.

   -t ARG, --target ARG
       Copy into specified directory.

   -u[ARG], --update[=ARG]
       Only replace files if the source is newer than the destination.
       Use a fudge factor of [ARG] seconds if supplied when comparing times, otherwise use 2 seconds.

   -v, --verbose
       Print more information to stdout. Can be given multiple times.

   -x, --one-file-system
       Don't cross into other file systems.

   --md5 ARG
       Output md5 checksums to file.

   --sha1 ARG
       Output sha1 checksums to file.

   --sha224 ARG
       Output sha224 checksums to file.

   --sha256 ARG
       Output sha256 checksums to file.

   --sha384 ARG
       Output sha384 checksums to file.

   --sha512 ARG
       Output sha512 checksums to file.

   --verify-md5 ARG
       Verify md5 checksums from file.

   --verify-sha1 ARG
       Verify sha1 checksums from file.

   --verify-sha224 ARG
       Verify sha224 checksums from file.

   --verify-sha256 ARG
       Verify sha256 checksums from file.

   --verify-sha384 ARG
       Verify sha384 checksums from file.

   --verify-sha512 ARG
       Verify sha512 checksums from file.

Format specifiers for output lines are:
   %md5: The MD5 checksum of the file
   %sha1: The SHA1 checksum of the file
   %sha224: The SHA224 checksum of the file
   %sha256: The SHA256 checksum of the file
   %sha384: The SHA384 checksum of the file
   %sha512: The SHA512 checksum of the file
   %S: The full source path
   %s: The part of the source path after the source root
   %D: The full destination path
   %d: The part of the destination path after the destination root
   %n: The base name of the destination file
   %%: A literal '%'

Notes:
   When verifying, a search is made for the source file using both the full path
   and non-root part of the path. Only the first match found is used.
```
