# $Id$

default:
	mkdir -p $(BUILD_DOC)/man/man1
	cp man/man1/reglookup.1.gz $(BUILD_DOC)/man/man1/reglookup.1.gz

install:
	cp -r $(BUILD_DOC)/* $(DOC_PREFIX)
	ln -sf $(DOC_PREFIX)/man/man1/*  $(MAN_PREFIX)/man1


#XXX: Used during release only
generate:
	txt2tags --mask-email -t man -o man/man1/reglookup.1 reglookup.1.t2t
	cd man/man1 && gzip -9 reglookup.1
