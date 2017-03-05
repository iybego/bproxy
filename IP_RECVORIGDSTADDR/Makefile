CC=gcc
CFLAGS=-c -Wall -Wextra -Wpedantic -O3 -std=gnu99

LD=gcc
LDFLAGS=-s -flto

.PHONY: test

all: test

ip_recvorigdstaddr: obj/test.o
	$(LD) $(LDFLAGS) obj/test.o -o ip_recvorigdstaddr

test: ip_recvorigdstaddr
	./ip_recvorigdstaddr

obj/test.o: src/test.c
	mkdir -p obj
	$(CC) $(CFLAGS) src/test.c -o obj/test.o

clean:
	rm -rf obj
	rm -f ip_recvorigdstaddr
