# $Id$

# Installation prefix.  Change to install elsewhere
#  XXX: installation not yet implemented

PREFIX=/usr/local

################################################################################

CC=gcc
OPTS=-ggdb -std=gnu89 -pedantic -Wall
#OPTS=-std=gnu89 -pedantic -Wall

BUILD=../build
BUILD_BIN=$(BUILD)/bin
BUILD_ETC=$(BUILD)/etc
BUILD_DIRS=$(BUILD_BIN) $(BUILD_ETC)

REGLOOKUP=$(BUILD)/bin/reglookup
FILES=$(REGLOOKUP)

all: $(BUILD_DIRS) $(FILES)

$(BUILD_DIRS):
	mkdir -p $@

$(REGLOOKUP): reglookup.c
	$(CC) $(OPTS) -o $@ reglookup.c

clean:
	rm -rf $(BUILD)/*
