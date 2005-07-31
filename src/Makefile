# $Id$

################################################################################

REGLOOKUP=$(BUILD_BIN)/reglookup
LIBS=$(wildcard ../lib/*.o)
FILES=$(REGLOOKUP)

all: $(FILES)

$(REGLOOKUP): reglookup.o $(LIBS)
	$(CC) $(CFLAGS) $(OPTS) -o $@ reglookup.o $(LIBS)

reglookup.o: reglookup.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ reglookup.c

install:
	cp -r $(BUILD_BIN)/* $(BIN_PREFIX)

clean:
	rm -f *.o
