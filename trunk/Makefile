# $Id$

# Installation prefixes.  Change to install elsewhere.

PREFIX=/usr/local
BIN_PREFIX=$(PREFIX)/bin
DOC_PREFIX=$(PREFIX)/share/doc/reglookup
MAN_PREFIX=$(PREFIX)/man

################################################################################

CC=gcc
#OPTS=-std=gnu89 -pedantic -Wall -ggdb
OPTS=-std=gnu89 -pedantic -Wall
INC=-I/usr/local/include
LIB=-L/usr/local/lib -lm
BIN_EXT=
EXTRA_OBJ=

UNAME := $(shell uname)
ifneq ($(UNAME),Linux) 	
  LIB:=$(LIB) -liconv
endif

ifdef BUILD_MINGW
CC=i586-mingw32msvc-cc
BIN_EXT=.exe
LIBICONV_PATH=/usr/local/src/libiconv-1.9.2-1-lib
INC:=$(INC) -I$(LIBICONV_PATH)/include
EXTRA_OBJ=$(LIBICONV_PATH)/lib/libiconv.dll.a
endif

BUILD=$(CURDIR)/build
BUILD_BIN=$(BUILD)/bin
BUILD_DOC=$(BUILD)/doc

BUILD_TREE=$(BUILD_BIN) $(BUILD_DOC)
SUB_DIRS=lib src doc bin

FILES=$(REGLOOKUP)
.PHONY: $(SUB_DIRS) clean
export


all: $(BUILD_TREE) $(SUB_DIRS)

#XXX: This should be more generalized.
install: all
	mkdir -p $(BIN_PREFIX)
	mkdir -p $(DOC_PREFIX)
	mkdir -p $(MAN_PREFIX)/man1
	$(MAKE) -C bin install
	$(MAKE) -C src install
	$(MAKE) -C doc install


$(SUB_DIRS):
	$(MAKE) -C $@

$(BUILD_TREE):
	mkdir -p $@

clean:
	$(MAKE) -C src clean
	$(MAKE) -C lib clean
	rm -rf $(BUILD)/*
