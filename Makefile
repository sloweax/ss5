CC=cc
CFLAGS=-Wall -O2

all: socks5-server

%.o: %.c
	$(CC) $(CFLAGS) $^ -c -o $@

socks5-server: socks5-server.o util.o rfc1928.o ll.o
	$(CC) $(CFLAGS) $^ -o $@

debug: CFLAGS+=-g -DS5DEBUG
debug: all

clean:
	rm -f *.o socks5-server

.PHONY: clean debug all
