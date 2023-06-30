NAME := cpsum
VERSION_MAJOR := 0
VERSION_MINOR := 8
VERSION_PATCH := 0
VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)

TMP_BASE := out
ULIB_SUBDIR := ulib
GNULIB_SUBDIR := gnulib
EXEFILE := $(TMP_BASE)/$(NAME)

CC ?= cc
_CFLAGS        := -std=c99 -fstrict-aliasing -fno-common -fshort-enums \
                  -ffunction-sections -fdata-sections \
                  -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=500 \
                  -Isrc
_DEBUG_CFLAGS  := -Werror -Wall -Wextra -pedantic \
                  -Wstrict-prototypes -Wconversion -Winit-self -Wunreachable-code \
                  -Wdouble-promotion -Wformat-security \
                  -Wnull-dereference -Wstrict-aliasing -Wshadow \
                  -fstack-usage -ggdb \
                  -DDEBUG=1 -UNDEBUG
# These are separate from the rest to make it easier to remove because clang
# doesn't support them.
#_DEBUG_CFLAGS += -Wformat-overflow -Wformat-truncation -Wformat-signedness -Wstrict-aliasing=3
_RELEASE_CFLAGS := -UDEBUG -DNDEBUG=1
_STATIC_CFLAGS := -static -static-libgcc
_LDFLAGS       :=

_CPSUM_CFLAGS  :=
C_FILES := $(wildcard src/*.c)
O_NAMES := $(patsubst src/%.c, %.o, $(C_FILES))
O_FILES := $(addprefix $(TMP_BASE)/, $(O_NAMES))

_ULIB_CFLAGS :=
_ULIB_DEBUG_CFLAGS := -Wundef
ULIB_C_FILES := $(wildcard src/$(ULIB_SUBDIR)/*.c)
ULIB_O_NAMES := $(patsubst src/$(ULIB_SUBDIR)/%.c, ul_%.o, $(ULIB_C_FILES))
ULIB_O_FILES := $(addprefix $(TMP_BASE)/, $(ULIB_O_NAMES))

_GNULIB_CFLAGS := -Wno-unused-parameter -Wno-conversion -Wno-sign-conversion -Wno-undef --std=gnu11
_GNULIB_DEBUG_CFLAGS :=
GNULIB_C_FILES := $(wildcard src/$(GNULIB_SUBDIR)/*.c)
GNULIB_O_NAMES := $(patsubst src/$(GNULIB_SUBDIR)/%.c, gnul_%.o, $(GNULIB_C_FILES))
GNULIB_O_FILES := $(addprefix $(TMP_BASE)/, $(GNULIB_O_NAMES))

SU_FILES := $(patsubst %.o, %.su, $(O_FILES) $(ULIB_O_FILES) $(GNULIB_O_FILES))

#
# Misc Rules
#
all: clean cpsum-release
debug: clean cpsum-debug
release: clean cpsum-release
static: clean cpsum-static

$(TMP_BASE):
	mkdir -p $(TMP_BASE)

clean:
	rm -f $(O_FILES) $(ULIB_O_FILES) $(GNULIB_O_FILES) $(SU_FILES) $(EXEFILE)

#
# Build cpsum
#
cpsum: $(TMP_BASE) $(O_FILES) $(ULIB_O_FILES) $(GNULIB_O_FILES)
	$(CC) $(_CFLAGS) $(CFLAGS) $(O_FILES) $(ULIB_O_FILES) $(GNULIB_O_FILES) -o $(EXEFILE) $(_LDFLAGS) $(LDFLAGS)

cpsum-debug: _CFLAGS += $(_DEBUG_CFLAGS)
cpsum-debug: _ULIB_CFLAGS += $(_ULIB_DEBUG_CFLAGS)
cpsum-debug: _GNULIB_CFLAGS += $(_GNULIB_DEBUG_CFLAGS)
cpsum-debug: cpsum

cpsum-release: _CFLAGS += $(_RELEASE_CFLAGS)
cpsum-release: cpsum

cpsum-static: _CFLAGS += $(_STATIC_CFLAGS)
cpsum-static: cpsum-release

$(O_FILES):
	$(CC) $(_CFLAGS) $(_CPSUM_CFLAGS) $(CFLAGS) -o $@ -c $(patsubst $(TMP_BASE)/%.o, src/%.c, $@);
$(ULIB_O_FILES):
	$(CC) $(_CFLAGS) $(_ULIB_CFLAGS) $(CFLAGS) -o $@ -c $(patsubst $(TMP_BASE)/ul_%.o, src/$(ULIB_SUBDIR)/%.c, $@);
$(GNULIB_O_FILES):
	$(CC) $(_CFLAGS) $(_GNULIB_CFLAGS) $(CFLAGS) -o $@ -c $(patsubst $(TMP_BASE)/gnul_%.o, src/$(GNULIB_SUBDIR)/%.c, $@);

#
# Packaging
#
tarfiles: tarfile-gz tarfile-xz tarfile-lz
tarfile-gz:
	git archive --format=tar --prefix=$(NAME)-$(VERSION)/ HEAD | gzip >$(NAME)-$(VERSION).tar.gz
tarfile-xz:
	git archive --format=tar --prefix=$(NAME)-$(VERSION)/ HEAD | xz >$(NAME)-$(VERSION).tar.xz
tarfile-lz:
	git archive --format=tar --prefix=$(NAME)-$(VERSION)/ HEAD | lzip >$(NAME)-$(VERSION).tar.lz
