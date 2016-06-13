OBJS = logger.o iptables.o util.o config.o data.o logparser.o main.o
TOBJS = logger.o iptables.o util.o config.o data.o logparser.o test.o
CC = g++
DEBUG = -g
CFLAGS = -std=c++11 -Wall -c $(DEBUG)
LFLAGS = -std=c++11 -Wall $(DEBUG)

prefix = /usr/local

hostblock: $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o hostblock

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

.PHONY: install clean

install: hostblock
	install -m 0755 hostblock $(prefix)/bin
	test /etc/hostblock.conf || install -m 0640 config/hostblock.conf /etc/hostblock.conf
	test -d $(prefix)/share/hostblock || mkdir $(prefix)/share/hostblock

test: $(TOBJS)
	$(CC) $(LFLAGS) $(TOBJS) -o test

test.o: hb/test/test.cpp
	$(CC) $(CFLAGS) hb/test/test.cpp

clean:
	rm -f *.o hostblock test
