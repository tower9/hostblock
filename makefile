OBJS = 
CC = g++
DEBUG = -g
CFLAGS = -std=c++11 -Wall -c $(DEBUG)
LFLAGS = -std=c++11 -Wall $(DEBUG)

logger.o : hb/src/logger.h hb/src/logger.cpp
	$(CC) $(CFLAGS) hb/src/logger.cpp

#test:


clean:
	rm -f *.o hostblock
