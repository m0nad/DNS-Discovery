CC=gcc
CFLAGS=-Wall -Wextra
BINDIR=/usr/local/bin

dns-disovery: dns-discovery.c dns-discovery.h
	$(CC) $(CFLAGS) -c *.c
	$(CC) $(CFLAGS) -o dns-discovery *.o -lpthread -O3
	rm *.o

clean:
	rm dns-discovery
