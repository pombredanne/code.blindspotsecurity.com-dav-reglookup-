# $Id$

BUILD_FILES=$(BUILD_DOC)/man/man1/reglookup.1.gz\
	$(BUILD_DOC)/man/man1/reglookup-timeline.1.gz\
	$(BUILD_DOC)/man/man1/reglookup-recover.1.gz

default: $(BUILD_FILES)

$(BUILD_DOC)/man/man1:
	mkdir -p $(BUILD_DOC)/man/man1

$(BUILD_DOC)/man/man1/reglookup.1.gz: man/man1/reglookup.1.gz $(BUILD_DOC)/man/man1
	cp man/man1/reglookup.1.gz $@

$(BUILD_DOC)/man/man1/reglookup-timeline.1.gz: man/man1/reglookup-timeline.1.gz $(BUILD_DOC)/man/man1
	cp man/man1/reglookup-timeline.1.gz $@

$(BUILD_DOC)/man/man1/reglookup-recover.1.gz: man/man1/reglookup-recover.1.gz $(BUILD_DOC)/man/man1
	cp man/man1/reglookup-recover.1.gz $@

install:
	cp -r $(BUILD_DOC)/* $(DOC_PREFIX)
	ln -sf $(DOC_PREFIX)/man/man1/*  $(MAN_PREFIX)/man1


#XXX: Used during release only
release:
	#XXX: The sed filter is a temporary hack to work around a bug in docbook2x-man
	#     See: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=516165
	docbook2x-man --to-stdout reglookup.1.docbook | sed 's/.SH DESCRIPTION/\n.SH DESCRIPTION/' > man/man1/reglookup.1
	docbook2x-man --to-stdout reglookup-timeline.1.docbook | sed 's/.SH DESCRIPTION/\n.SH DESCRIPTION/' > man/man1/reglookup-timeline.1
	docbook2x-man --to-stdout reglookup-recover.1.docbook | sed 's/.SH DESCRIPTION/\n.SH DESCRIPTION/' > man/man1/reglookup-recover.1
	cd man/man1 && gzip -9 -f reglookup.1
	cd man/man1 && gzip -9 -f reglookup-timeline.1
	cd man/man1 && gzip -9 -f reglookup-recover.1
