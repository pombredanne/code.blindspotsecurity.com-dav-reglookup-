# $Id: Makefile 30 2005-07-16 14:31:27Z tim $

################################################################################

FILES=regfi.o smb_deps.o void_stack.o range_list.o lru_cache.o

all: $(FILES)

regfi.o: regfi.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ regfi.c

smb_deps.o: smb_deps.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ smb_deps.c

void_stack.o: void_stack.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ void_stack.c

range_list.o: range_list.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ range_list.c

lru_cache.o: lru_cache.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ lru_cache.c

clean:
	rm -f $(FILES)
