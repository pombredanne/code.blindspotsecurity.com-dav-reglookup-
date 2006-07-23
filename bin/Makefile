# $Id$

################################################################################

TIMELINE=$(BUILD_BIN)/reglookup-timeline
FILES=$(TIMELINE)

all: $(FILES)

$(TIMELINE):
	cp reglookup-timeline $@

install:
	cp -r $(FILES) $(BIN_PREFIX)

clean:
	rm -f *~
