# $Id: Makefile 143 2009-02-13 03:24:27Z tim $

################################################################################
CC=gcc
OPTS=-std=gnu99 -pedantic -Wall -ggdb
INC:=-I../trunk/include -I../trunk/src -I/usr/local/include 
LIB=-L/usr/local/lib -lm -lpthread -ltalloc

REGFI_THREADTEST=regfi-threadtest
OBJ=$(wildcard ../trunk/lib/*.o)
FILES=$(REGFI_THREADTEST)

all: deps $(FILES)

deps:
	cd ../trunk && scons libregfi

$(REGFI_THREADTEST): regfi-threadtest.o
	$(CC) $(CFLAGS) $(OPTS) $(LIB) -o $@ regfi-threadtest.o $(OBJ) $(EXTRA_OBJ)

regfi-threadtest.o: regfi-threadtest.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ regfi-threadtest.c

clean:
	rm -f *.o $(FILES)
