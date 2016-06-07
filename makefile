OBJS = 
CC = g++-4.9
DEBUG = -g
CFLAGS = -std=c++11 -Wall -c $(DEBUG)
LFLAGS = -std=c++11 -Wall $(DEBUG)

logger.o : logger.h logger.cpp
	$(CC) $(CFLAGS) logger.cpp

#test:


clean:
	rm -f *.o hostblock
