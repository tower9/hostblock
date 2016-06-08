OBJS = logger.o iptables.o
TOBJS = test.o
CC = g++
DEBUG = -g
CFLAGS = -std=c++11 -Wall -c $(DEBUG)
LFLAGS = -std=c++11 -Wall $(DEBUG)

iptables.o: hb/src/iptables.h hb/src/iptables.cpp
	$(CC) $(CFLAGS) hb/src/iptables.cpp

logger.o: hb/src/logger.h hb/src/logger.cpp
	$(CC) $(CFLAGS) hb/src/logger.cpp

test: $(OBJS) $(TOBJS)
	$(CC) $(LFLAGS) $(OBJS) $(TOBJS) -o test

test.o: hb/test/test.cpp
	$(CC) $(CFLAGS) hb/test/test.cpp

clean:
	rm -f *.o hostblock test
