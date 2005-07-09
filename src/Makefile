# $Id$

################################################################################

REGLOOKUP=$(BUILD_BIN)/reglookup
FILES=$(REGLOOKUP)

all: $(FILES)

$(REGLOOKUP): reglookup.c
	$(CC) $(CFLAGS) $(OPTS) -o $@ reglookup.c

install:
	cp -r $(BUILD_BIN)/* $(BIN_PREFIX)
