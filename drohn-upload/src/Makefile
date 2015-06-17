CURLPUTFLAGS+=-Wall -lcurl

all: curlput

curlput: curlput.o
	$(CC) curlput.o -o curlput $(CURLPUTFLAGS)

curlput.o: curlput.c
	$(CC) $(CFLAGS) -c curlput.c $(CURLPUTFLAGS) 

# remove object files and executable when user executes "make clean"
clean:
	rm *.o curlput