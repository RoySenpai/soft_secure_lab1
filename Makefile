CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -shared -ldl

all: secret server .so.6

secret: secret.o
	$(CC) $(CFLAGS) -o $@ $^

server: server.o
	$(CC) $(CFLAGS) -o $@ $^

.so.6: dymlib_hacked.o
	$(CC) $(LDFLAGS) -o $@ $^

dymlib_hacked.o: dymlib_hacked.c
	$(CC) $(CFLAGS) -fPIC -c $^

%.o: %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f *.o secret server .so.6
