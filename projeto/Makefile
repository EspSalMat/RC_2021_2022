CC=gcc
CFLAGS=-Wall

.PHONY: all clean

all: User DS
User: client/main.c client/commands.c common/common.o
DS: server/main.c common/common.o

proj_54.zip: clean
	mkdir tmp
	cp -r client tmp/client
	cp -r server tmp/server
	cp -r common tmp/common
	cp Makefile tmp/Makefile
	cd tmp && zip -r ../proj_54.zip .
	rm -rf tmp

User DS:
	$(CC) $(CFLAGS) $^ -g -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	@rm -rf */*.o User DS
