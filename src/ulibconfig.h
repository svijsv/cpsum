//
// config.h
// Configuration file for the ulib modules
//
// This file should only be included by configify.h

/*
* Global configuration
*/
// Default value for module enablement.
//#define ULIB_ENABLE_DEFAULT 1
#define ULIB_ENABLE_DEFAULT 0
//
// If non-zero, include an ID field in exported structs to make some debugging
// easier. Not all structs currently support this.
//#define ULIB_USE_STRUCT_ID DEBUG
#define ULIB_USE_STRUCT_ID 0
//
// If non-zero, modules with USE_MALLOC options default to using malloc.
#define ULIB_USE_MALLOC 1
//
// If non-zero, default to doing additional safety checks in all modules.
#define ULIB_DO_SAFETY_CHECKS 1
//
// If non-zero, use elm-chan's xprintf from http://elm-chan.org/fsw/strf/xprintf.html
// to provide printf_va(). There's currently no backup provider.
// The source isn't included in this library; it will have to be built separately
// and linked into the program at the same time as ulib.
// The declaration of xv[f]printf() in xprintf.c is normally static and needs
// to be changed so that it's available here.
//#define HAVE_XPRINTF 1
#define HAVE_XPRINTF 0


/*
* Alternate namespace module configuration
*/
// Enable this module
#define ULIB_ENABLE_FMEM ULIB_ENABLE_DEFAULT
//
// If non-zero, enable the use of an alternate namespace for storing static
// data.
#define HAVE_FMEM_NAMESPACE 0
//
// The size of the static array(s) used to return strings from FROM_STR()
#define FMEM_STR_BYTES 128U
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_FMEM_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Array module configuration
*/
// Enable this module
//#define ULIB_ENABLE_ARRAYS ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_ARRAYS 1
//
// The size of arlen_t is based on the size of ARRAY_MAX_OBJECTS+1, so using
// one less than the max of an unsigned int type will result in less used
// space than using the max value itself.
#define ARRAY_MAX_OBJECTS (0xFFFFFFFFU - 1U)
//
// Allocated size of an array when first created.
#define ARRAY_INITIAL_SIZE 4
//
// Factor by which to grow an array by when it would otherwise overflow.
#define ARRAY_GROW_FACTOR 4
//
// Method of array growth.
//    ARRAY_GROW_NONE: The array is never grown - if an overflow would occur,
//                     excess objects are simply not added.
//    ARRAY_GROW_FRAC: The increase is by allocated/factor - e.g. if
//                     ARRAY_GROW_FACTOR is 2, the new size is 1.5 times the
//                     previous one (with an error margin on account of integer
//                     division).
//    ARRAY_GROW_ADD: Add ARRAY_GROW_FACTOR to the allocated size.
//    ARRAY_GROW_MUL: Multiply the allocated size by ARRAY_GROW_FACTOR.
#define ARRAY_GROW_METHOD ARRAY_GROW_MUL
//
// If non-zero, the array bank is grown as needed. Otherwise the bank always
// contains ARRAY_MAX_OBJECTS entries and the ARRAY_GROW_* values are ignored.
#define ARRAYS_USE_MALLOC ULIB_USE_MALLOC
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_ARRAY_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Bitwise operation module configuration
*/
// The width of the unsigned integer used in the type-checked bit operation
// functions.
#define BITOP_WIDTH 32


/*
* Byte buffer module configuration
*/
// Enable this module
// Needed for message module
//#define ULIB_ENABLE_BUFFERS ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_BUFFERS 1
//
// The size of buflen_t is based on the size of BUFFER_MAX_BYTES+1, so using
// one less than the max of an unsigned int type will result in less used
// space than using the max value itself.
//
#define BUFFER_MAX_BYTES (0xFFFFU - 1U)
//
// Size of a buffer when first created.
#define BUFFER_INITIAL_SIZE 32
//
// Factor by which to grow the buffer by when it would otherwise overflow.
#define BUFFER_GROW_FACTOR 2
//
// Method of buffer growth. See the description for ARRAY_GROW_METHOD for
// details.
#define BUFFER_GROW_METHOD BUFFER_GROW_MUL
//
// If non-zero, the buffer bank is grown as needed. Otherwise the bank is
// always BUFFER_MAX_BYTES in size and BUFFER_GROW_* values are ignored.
#define BUFFERS_USE_MALLOC ULIB_USE_MALLOC
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_BUFFER_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* C-style string module configuration
*/
// Enable this module
// Needed for getopt module.
//#define ULIB_ENABLE_CSTRINGS ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_CSTRINGS 1
//
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_CSTRING_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Debugging module configuration
*/
// Use the assert() function defined in debug.h instead of pulling in assert.h
// when NDEBUG is undefined.
// If this is enabled and NDEBUG is undefined, the function _assert_failed()
// must be defined somewhere. See debug.h for the prototype.
//#define USE_ULIB_ASSERT 1
#define USE_ULIB_ASSERT 0


/*
* File module configuration
*/
// Enable this module
//#define ULIB_ENABLE_FILES ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_FILES 1
//
// The maximum number of levels to descend in recursive operations.
#define FILE_MAX_RECURSION 255U
//
// An optional externally-defined buffer used for file operations that require
// one. Used when functions are passed NULL as their buffer.
// If defined, it must be uint8_t*.
//#define FILE_PROVIDED_BUF g_byte_buffer
//#define FILE_PROVIDED_BUF_SIZE 16384
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_FILE_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS
//
// These are additional checks for the internal helper functions.
//#define DO_FILE_EXTRA_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS
#define DO_FILE_EXTRA_SAFETY_CHECKS 0


/*
* Linked-list module configuration
*/
// Enable this module
//#define ULIB_ENABLE_LISTS ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_LISTS 1
//
// The size of listlen_t is based on the size of LIST_MAX_OBJECTS+1, so using
// one less than the max of an unsigned int type will result in less used
// space than using the max value itself.
#define LIST_MAX_OBJECTS (0xFFFFFFFFU - 1U)
//
// If non-zero, new entries are created with malloc. Otherwise a pointer to
// a list_entry_t struct will need to be supplied when adding to the list.
#define LISTS_USE_MALLOC ULIB_USE_MALLOC
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_LIST_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Math module configuration
*/
// Enable this module
// Needed for files.c
//#define ULIB_ENABLE_MATH ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_MATH 1
//
// The number of bits used in fixed-point representations. This includes the
// sign bit.
#define FIXED_PNT_BITS 32
//
// The number of bits of a fixed-point representation devoted to the fraction.
#define FIXED_PNT_FRACT_BITS 8
//
// If non-zero, perform additional checks to handle common problems like
// division by 0.
#define DO_MATH_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS
//
// If set, override the macro used to divide fixed-point integers. Useful
// because a certain platform doesn't have native support for 64 bit division
// and using libc adds a full Kb to the .data section of the binary...
//#define _FIXED_PNT_DIV_PRIM(_n, _d) (div_s64_s64((_n), (_d)))


/*
* Message module configuration
*/
// Enable this module
//#define ULIB_ENABLE_MSG ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_MSG 1
//
// Maximum size of short printed strings like line prefixes and log file
// names.
#define MSG_STR_BYTES 16U
//
// If non-zero, the msg subsystem will use malloc() to allocate memory. Otherwise
// all memory is statically-allocated.
#define MSG_USE_MALLOC 1
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_MSG_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Option parsing module configuration
*/
// Enable this module
//#define ULIB_ENABLE_GETOPT ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_GETOPT 1
//
// The maximum number of supported arguments and the maximum size of strings
// in argv is OPT_LEN_MAX. The type used to store the values is determined by
// OPT_LEN_MAX+1.
#define OPT_LEN_MAX (0xFFFFU - 1U)
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_OPT_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Formatted printing module configuration
*/
// Enable this module
#define ULIB_ENABLE_PRINTF ULIB_ENABLE_DEFAULT
//
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_PRINTF_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* String module configuration
*/
// Enable this module
//#define ULIB_ENABLE_STRINGS ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_STRINGS 1
//
// Max length of a string, excluding the terminal NUL. Keep at 255 or less
// if the total length including NUL needs to fit in a uint8_t. The type
// of strlen_t is determined by strings.h based on this value.
#define STRING_MAX_BYTES (0xFFFFU - 1U)
//
// If non-zero, use malloc() to re-size strings as needed. They still won't
// exceed STRING_MAX_BYTES in length excluding the NUL.
#define STRINGS_USE_MALLOC ULIB_USE_MALLOC
//
// When STRINGS_USE_MALLOC is set, grow the string in blocks of this size.
#define STRING_ALLOC_BLOCK_BYTES 16U
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_STRING_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS


/*
* Time module configuration
*/
// Enable this module
#define ULIB_ENABLE_TIME ULIB_ENABLE_DEFAULT
//
// Year 0 of the internal calendar. This shouldn't be a leap year.
#define TIME_YEAR_0 2015U
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_TIME_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS
//
// A macro or function used to get the current value of the systick timer.
// Only needed when SET_TIMEOUT_MS() is used. This can be set in the calling
// code (and redefined as needed) because it's only used in a macro.
//#define GET_SYSTICKS_MS()
//
// Like GET_SYSTICKS_MS but used by SET_RTC_TIMEOUT_S().
//#define GET_RTCTICKS_S() (time(null))


/*
* Utility module configuration
*/
// Enable this module
//#define ULIB_ENABLE_UTIL ULIB_ENABLE_DEFAULT
#define ULIB_ENABLE_UTIL 1
//
// If non-zero, perform additional checks to handle common problems like being
// passed NULL inputs.
#define DO_UTIL_SAFETY_CHECKS ULIB_DO_SAFETY_CHECKS
