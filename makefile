OBJS = logger.o iptables.o util.o config.o data.o logparser.o abuseipdb.o main.o
TOBJS = logger.o iptables.o util.o config.o data.o logparser.o abuseipdb.o test.o
# https://curl.haxx.se/libcurl/
# https://github.com/open-source-parsers/jsoncpp
LIBS = -lcurl -ljsoncpp
CC = g++
DEBUG = -g
CFLAGS = -std=c++14 -Wall -c $(DEBUG)
LFLAGS = -std=c++14 -Wall $(DEBUG)

prefix = /usr/local

hostblock: $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) $(LIBS) -pthread -o hostblock

main.o: hb/src/main.cpp
	$(CC) $(CFLAGS) hb/src/main.cpp

logparser.o: util.o config.o iptables.o data.o hb/src/logparser.h hb/src/logparser.cpp
	$(CC) $(CFLAGS) hb/src/logparser.cpp

data.o: util.o config.o iptables.o hb/src/data.h hb/src/data.cpp
	$(CC) $(CFLAGS) hb/src/data.cpp

config.o: util.o hb/src/config.h hb/src/config.cpp
	$(CC) $(CFLAGS) hb/src/config.cpp

iptables.o: hb/src/iptables.h hb/src/iptables.cpp
	$(CC) $(CFLAGS) hb/src/iptables.cpp

logger.o: hb/src/logger.h hb/src/logger.cpp
	$(CC) $(CFLAGS) hb/src/logger.cpp

util.o: hb/src/util.h hb/src/util.cpp
	$(CC) $(CFLAGS) hb/src/util.cpp

abuseipdb.o: hb/src/abuseipdb.h hb/src/abuseipdb.cpp
	$(CC) $(CFLAGS) hb/src/abuseipdb.cpp

.PHONY: install clean

install: hostblock
	install -m 0755 hostblock $(prefix)/bin
	test -e /etc/hostblock.conf || install -m 0644 config/hostblock.conf /etc/hostblock.conf
	test -d $(prefix)/share || mkdir $(prefix)/share
	test -d $(prefix)/share/hostblock || mkdir $(prefix)/share/hostblock
	test -d /usr/lib/systemd/system && install -m 0644 init/systemd /usr/lib/systemd/system/hostblock.service || true
	test -d /lib/systemd/system && install -m 0644 init/systemd /lib/systemd/system/hostblock.service || true
	test -d /usr/share/upstart && install -m 0644 init/upstart /etc/init/hostblock.conf || true

test: $(TOBJS)
	$(CC) $(LFLAGS) $(TOBJS) $(LIBS) -o test

test.o: hb/test/test.cpp
	$(CC) $(CFLAGS) hb/test/test.cpp

clean:
	rm -f *.o hostblock test
