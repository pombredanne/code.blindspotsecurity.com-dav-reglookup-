# $Id$

default:
	mkdir -p $(BUILD_DOC)/man/man1

#XXX: Used during release only
generate:
	txt2tags --mask-email -t man -o man/man1/reglookup.1 reglookup.txt
	cd man/man1 && gzip -9 reglookup.1

build: generate default

install:
	ln -sf $(DOC_PREFIX)/man/man1/*  $(MAN_PREFIX)/man1
