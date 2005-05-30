# $Id: Makefile 3 2005-02-18 03:59:23Z tim $

# Installation prefix.  Change to install elsewhere

PREFIX=/usr/local

################################################################################

CC=gcc
OPTS=-ggdb -std=gnu89 -pedantic -Wall
#OPTS=-std=gnu89 -pedantic -Wall

BUILD=$(CURDIR)/build
BUILD_BIN=$(BUILD)/bin
BUILD_DOC=$(BUILD)/doc

BUILD_TREE=$(BUILD_BIN) $(BUILD_ETC) $(BUILD_DOC)
SUB_DIRS=src doc

FILES=$(REGLOOKUP)
.PHONY: $(SUB_DIRS) clean
export


all: $(BUILD_TREE) $(SUB_DIRS)

install: all
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/share/doc/reglookup
	cp -r build/bin/* $(PREFIX)/bin/
	cp -r build/doc/* $(PREFIX)/share/doc/reglookup/

$(SUB_DIRS):
	$(MAKE) -C $@

$(BUILD_TREE):
	mkdir -p $@

clean:
	rm -rf $(BUILD)/*


# For developer use only
RELEASE_VER=0.1
RELEASE_DEST=.
.release:
	rm -rf .release
	mkdir .release
	# XXX: checkout version should be based on RELEASE_VER
	svn export svn+ssh://pascal/home/projects/subversion/reglookup/\
		.release/reglookup-$(RELEASE_VER)
	cd .release/reglookup-$(RELEASE_VER)/doc && make generate
	cd .release\
		&& tar cf reglookup-$(RELEASE_VER).tar reglookup-$(RELEASE_VER)\
		&& gzip -9 reglookup-$(RELEASE_VER).tar
	mv .release/reglookup-$(RELEASE_VER).tar.gz $(RELEASE_DEST)
	rm -rf .release
