# $Id$

# Installation prefixes.  Change to install elsewhere.

PREFIX=/usr/local
BIN_PREFIX=$(PREFIX)/bin
DOC_PREFIX=$(PREFIX)/share/doc/reglookup
MAN_PREFIX=$(PREFIX)/man

################################################################################

CC=gcc
OPTS=-std=gnu89 -pedantic -Wall

BUILD=$(CURDIR)/build
BUILD_BIN=$(BUILD)/bin
BUILD_DOC=$(BUILD)/doc

BUILD_TREE=$(BUILD_BIN) $(BUILD_DOC)
SUB_DIRS=src doc

FILES=$(REGLOOKUP)
.PHONY: $(SUB_DIRS) clean
export


all: $(BUILD_TREE) $(SUB_DIRS)

#XXX: This should be more generalized.
install: all
	mkdir -p $(BIN_PREFIX)
	mkdir -p $(DOC_PREFIX)
	mkdir -p $(MAN_PREFIX)/man1
	cp -r $(BUILD_BIN)/* $(BIN_PREFIX)
	cp -r $(BUILD_DOC)/* $(DOC_PREFIX)
	$(MAKE) -C doc install


$(SUB_DIRS):
	$(MAKE) -C $@

$(BUILD_TREE):
	mkdir -p $@

clean:
	rm -rf $(BUILD)/*

