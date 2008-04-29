# $Id$

################################################################################

REGLOOKUP=$(BUILD_BIN)/reglookup
REGLOOKUP_RECOVER=$(BUILD_BIN)/reglookup-recover
OBJ=$(wildcard ../lib/*.o)
FILES=$(REGLOOKUP) $(REGLOOKUP_RECOVER)

all: $(FILES)

$(REGLOOKUP): reglookup.o $(OBJ)
	$(CC) $(CFLAGS) $(OPTS) $(LIB) -o $@ reglookup.o $(OBJ)

$(REGLOOKUP_RECOVER): reglookup-recover.o $(OBJ)
	$(CC) $(CFLAGS) $(OPTS) $(LIB) -o $@ reglookup-recover.o $(OBJ)

reglookup.o: reglookup.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ reglookup.c

reglookup-recover.o: reglookup-recover.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ reglookup-recover.c

install:
	install -m 0755 $(FILES) $(BIN_PREFIX)

clean:
	rm -f *.o
