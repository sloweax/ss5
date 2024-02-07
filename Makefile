CC=cc
CFLAGS=-Wall -Wextra -O2

all: socks5-server

%.o: %.c
	$(CC) $(CFLAGS) $^ -c -o $@

socks5-server: socks5-server.o util.o socks5.o ll.o
	$(CC) $(CFLAGS) $^ -o $@

debug: CFLAGS+=-g -DS5DEBUG
debug: all

clean:
	rm -f *.o socks5-server

.PHONY: clean debug all
