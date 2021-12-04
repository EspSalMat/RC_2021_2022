CC=gcc
CFLAGS=-Wall

.PHONY: all clean

all: User DS
User: client/main.c client/args.o
DS: server/main.c

User DS:
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	@rm -rf */*.o User DS
