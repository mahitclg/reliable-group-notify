CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDFLAGS = -lpthread -lm

all: server

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)
	@echo "Built: server"

client: client.c
	$(CC) $(CFLAGS) -o client client.c
	@echo "Built: client"

clean:
	rm -f server client *.o

.PHONY: all clean
