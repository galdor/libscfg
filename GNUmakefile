
# Common
prefix= /usr/local
libdir= $(prefix)/lib
incdir= $(prefix)/include

CC=   clang

CFLAGS=  -std=c99
CFLAGS+= -Wall -Wextra -Werror -Wsign-conversion
CFLAGS+= -Wno-unused-parameter -Wno-unused-function
CFLAGS+= -g

LDFLAGS=

# Platform specific
platform= $(shell uname -s)

ifeq ($(platform), Linux)
	CFLAGS+=  -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE
endif

# Target: libscfg
libscfg_LIB= libscfg.a
libscfg_SRC= $(wildcard src/*.c)
libscfg_INC= src/scfg.h
libscfg_OBJ= $(subst .c,.o,$(libscfg_SRC))

$(libscfg_LIB): CFLAGS+=

# Target: utils
utils_SRC= $(wildcard utils/*.c)
utils_OBJ= $(subst .c,.o,$(utils_SRC))
utils_BIN= $(subst .o,,$(utils_OBJ))

$(utils_BIN): CFLAGS+=  -Isrc
$(utils_BIN): LDFLAGS+=
$(utils_BIN): LDLIBS+=

# Rules
all: $(libscfg_LIB) $(utils_BIN)

$(libscfg_LIB): $(libscfg_OBJ)
	$(AR) cr $@ $(libscfg_OBJ)

utils/%: utils/%.o $(libscfg_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(RM) $(libscfg_LIB) $(libscfg_OBJ)
	$(RM) $(utils_BIN) $(utils_OBJ)

install: all
	mkdir -p $(libdir) $(incdir)
	install -m 644 $(libscfg_LIB) $(libdir)
	install -m 644 $(libscfg_INC) $(incdir)

uninstall:
	$(RM) $(addprefix $(libdir)/,$(libscfg_LIB))
	$(RM) $(addprefix $(incdir)/,$(libscfg_INC))

tags:
	ctags -o .tags -a $(wildcard src/*.[hc])

.PHONY: all clean install uninstall tags
