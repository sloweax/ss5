CC=cc
CFLAGS=-Wall -Wextra -O2
BINDSTPATH=/usr/local/bin

all: socks5-server

%.o: %.c
	$(CC) $(CFLAGS) $^ -c -o $@

socks5-server: socks5-server.o util.o socks5.o ll.o
	$(CC) $(CFLAGS) $^ -o $@

debug: CFLAGS+=-g -DS5DEBUG
debug: all

clean:
	rm -f *.o socks5-server

install: all
	mkdir -p $(BINDSTPATH)
	cp socks5-server $(BINDSTPATH)

uninstall:
	rm -f $(BINDSTPATH)/socks5-server

.PHONY: clean debug all install uninstall
