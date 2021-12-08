CC=gcc
CFLAGS=-Wall

.PHONY: all clean

all: User DS
User: client/main.c common/common.o
DS: server/main.c common/common.o

User DS:
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	@rm -rf */*.o User DS
