# $Id: Makefile 30 2005-07-16 14:31:27Z tim $

################################################################################

CC=gcc
OPTS=-ggdb -std=gnu89 -pedantic -Wall
FILES=regfio.o smb_deps.o void_stack.o

all: $(FILES)

regfio.o: regfio.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ regfio.c

smb_deps.o: smb_deps.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ smb_deps.c

void_stack.o: void_stack.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ void_stack.c

clean:
	rm -f $(FILES)
