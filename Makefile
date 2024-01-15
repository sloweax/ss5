CC=cc
CFLAGS=-Wall -O2

%.o: %.c
	$(CC) $(CFLAGS) $^ -c -o $@

socks5-server: socks5-server.o util.o rfc1928.o ll.o
	$(CC) $(CFLAGS) $^ -o $@

debug: CFLAGS+=-g -DDEBUG
debug: socks5-server

clean:
	rm -f *.o socks5-server

.PHONY: clean debug
