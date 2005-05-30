# $Id$

# Installation prefixes.  Change to install elsewhere.

PREFIX=/usr/local
BIN_PREFIX=$(PREFIX)/bin
DOC_PREFIX=$(PREFIX)/share/doc/reglookup
MAN_PREFIX=$(PREFIX)/man

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
	mkdir -p $(BIN_PREFIX)
	mkdir -p $(DOC_PREFIX)
	cp -r $(BUILD_BIN)/* $(BIN_PREFIX)
	cp -r $(BUILD_DOC)/* $(DOC_PREFIX)
	#XXX: This should be more generalized.  
	#     Possibly move it to doc/Makefile
	cp -s $(DOC_PREFIX)/man/man1/*  $(MAN_PREFIX)/man1


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
