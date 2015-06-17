NFLCFLAGS+=-Wall -lcrypto

all: nflc

nflc: nflc.o nflc_utils.o nflc_conf.o
	$(CC) nflc.o nflc_utils.o nflc_conf.o -o nflc $(NFLCFLAGS)

nflc.o: nflc.c
	$(CC) $(CFLAGS) -c nflc.c nflc.h nflc_utils.h nflc_conf.h $(NFLCFLAGS)

nflc_utils.o: nflc_utils.c
	$(CC) $(CFLAGS) -c nflc_utils.c nflc.h nflc_utils.h $(NFLCFLAGS)

nflc_conf.o: nflc_conf.c
	$(CC) $(CFLAGS) -c nflc_conf.c nflc_conf.h $(NFLCFLAGS)

# remove object files and executable when user executes "make clean"
clean:
	rm *.o nflc