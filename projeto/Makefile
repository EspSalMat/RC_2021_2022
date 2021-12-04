CC=gcc
CFLAGS=-Wall

.PHONY: all clean

all: User DS
User: client/main.c
DS: server/main.c

User DS:
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $^

clean:
	rm *.o User DS
