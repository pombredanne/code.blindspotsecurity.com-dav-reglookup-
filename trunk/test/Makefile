# $Id$

################################################################################

REGFIO_O=../lib/regfio.o
LIB_REGFIO_O=lib-regfio.o
LIB_REGFIO=lib-regfio
FILES=$(LIB_REGFIO) $(REGFIO_O)

all: $(FILES)

$(REGFIO_O): ../lib/regfio.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ ../lib/regfio.c

$(LIB_REGFIO_O): lib-regfio.c
	$(CC) $(CFLAGS) $(OPTS) -c -o $@ lib-regfio.c

$(LIB_REGFIO): 	$(LIB_REGFIO_O) $(REGFIO_O)
	$(CC) $(CFLAGS) $(OPTS) -o $@ $(LIB_REGFIO_O) $(REGFIO_O) ../lib/smb_deps.c
