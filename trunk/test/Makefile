# $Id$

################################################################################

CC=gcc
OPTS=-ggdb -std=gnu89 -pedantic -Wall

REGFIO_O=../lib/regfio.o
LIB_REGFIO_O=lib-regfio.o
LIB_REGFIO=lib-regfio
FILES=$(LIB_REGFIO) $(LIB_REGFIO_O)

all: $(FILES)

$(LIB_REGFIO_O): lib-regfio.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ lib-regfio.c

$(LIB_REGFIO): 	$(LIB_REGFIO_O) $(REGFIO_O) ../lib/smb_deps.o ../lib/void_stack.o
	$(CC) $(CFLAGS) $(OPTS) -o $@ $(LIB_REGFIO_O) $(REGFIO_O) ../lib/smb_deps.o ../lib/void_stack.o


clean:
	rm -f $(FILES)
