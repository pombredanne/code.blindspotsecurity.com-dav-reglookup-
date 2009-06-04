# $Id: Makefile 30 2005-07-16 14:31:27Z tim $

################################################################################

FILES=regfi.o smb_deps.o winsec.o void_stack.o range_list.o lru_cache.o talloc.o

all: $(FILES)

regfi.o: regfi.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ regfi.c

smb_deps.o: smb_deps.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ smb_deps.c

winsec.o: winsec.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ winsec.c

void_stack.o: void_stack.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ void_stack.c

range_list.o: range_list.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ range_list.c

lru_cache.o: lru_cache.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ lru_cache.c

talloc.o: talloc.c
	$(CC) $(CFLAGS) $(OPTS) $(INC) -c -o $@ talloc.c

clean:
	rm -f $(FILES)
