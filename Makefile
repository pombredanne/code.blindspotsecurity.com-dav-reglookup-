# $Id: Makefile 3 2005-02-18 03:59:23Z tim $

# Installation prefix.  Change to install elsewhere
#  XXX: installation not yet implemented

PREFIX=/usr/local

################################################################################

CC=gcc
OPTS=-ggdb -std=gnu89 -pedantic -Wall
#OPTS=-std=gnu89 -pedantic -Wall

BUILD=$(CURDIR)/build
BUILD_BIN=$(BUILD)/bin
BUILD_ETC=$(BUILD)/etc
BUILD_DOC=$(BUILD)/doc

BUILD_TREE=$(BUILD_BIN) $(BUILD_ETC) $(BUILD_DOC)
SUB_DIRS=src doc

FILES=$(REGLOOKUP)
.PHONY: $(SUB_DIRS) clean
export


all: $(BUILD_TREE) $(SUB_DIRS)

$(SUB_DIRS):
	$(MAKE) -C $@

$(BUILD_TREE):
	mkdir -p $@

clean:
	rm -rf $(BUILD)/*
