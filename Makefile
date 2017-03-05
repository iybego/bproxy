BINARY=bproxy

SYSTEMD=/etc/systemd/system

BINDIR=/usr/local/bin
ETCDIR=/etc/bproxy

CC=gcc
CFLAGS=-c -Wall -Wextra -Wpedantic -O3 -std=gnu99 -mtune=native -march=native

LD=gcc
LDFLAGS=-flto -s -mtune=native -march=native

.PHONY: bproxy

all: bproxy

OBJECTS=obj/bproxy.o obj/configuration.o obj/log.o obj/hashmap.o obj/socket.o obj/poll.o obj/rtlink.o obj/source.o obj/timer.o obj/ipv4.o obj/ipv4-option.o obj/sysctl.o

bproxy: objects
	$(LD) $(LDFLAGS) $(OBJECTS) -o $(BINARY)

objects-directory:
	mkdir -p obj/src

objects: objects-directory $(OBJECTS)
	

obj/log.o: src/log.c src/log.h
	$(CC) $(CFLAGS) src/log.c -o obj/log.o

obj/bproxy.o: src/bproxy.c src/bproxy.h
	$(CC) $(CFLAGS) src/bproxy.c -o obj/bproxy.o

obj/configuration.o: src/configuration.c src/configuration.h
	$(CC) $(CFLAGS) src/configuration.c -o obj/configuration.o

obj/hashmap.o: src/hashmap.c src/hashmap.h
	$(CC) $(CFLAGS) src/hashmap.c -o obj/hashmap.o

obj/socket.o: src/socket.c src/socket.h
	$(CC) $(CFLAGS) src/socket.c -o obj/socket.o

obj/poll.o: src/poll.c src/poll.h
	$(CC) $(CFLAGS) src/poll.c -o obj/poll.o

obj/rtlink.o: src/rtlink.c src/rtlink.h
	$(CC) $(CFLAGS) src/rtlink.c -o obj/rtlink.o

obj/source.o: src/source.c src/source.h
	$(CC) $(CFLAGS) src/source.c -o obj/source.o

obj/timer.o: src/timer.c src/timer.h
	$(CC) $(CFLAGS) src/timer.c -o obj/timer.o

obj/ipv4.o: src/ipv4.c src/ipv4.h
	$(CC) $(CFLAGS) src/ipv4.c -o obj/ipv4.o

obj/ipv4-option.o: src/ipv4-option.h src/ipv4-option.c
	$(CC) $(CFLAGS) src/ipv4-option.c -o obj/ipv4-option.o

obj/sysctl.o: src/sysctl.c src/sysctl.h
	$(CC) $(CFLAGS) src/sysctl.c -o obj/sysctl.o

clean:
	rm -rf obj
	rm -f $(BINARY)

install: bproxy
	install -m 0755 bproxy $(BINDIR)
	install -m 0644 contrib/bproxy@.service $(SYSTEMD)/$(BINARY)@.service
	install -m 0644 contrib/sample-join.cfg $(ETCDIR)
	install -m 0644 contrib/sample-simple.cfg $(ETCDIR)

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(SYSTEMD)/$(BINARY)@.service
