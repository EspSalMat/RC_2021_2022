CC=gcc
CFLAGS=-Wall

.PHONY: all clean

all: User DS
User: client/main.c client/commands.o utils/sockets.o utils/validate.o
DS: server/main.c server/commands.o server/requests.o utils/sockets.o utils/validate.o

proj_54.zip: clean
	mkdir tmp
	cp -r client tmp/client
	cp -r server tmp/server
	cp -r utils tmp/utils
	sed '10,18d' Makefile > tmp/Makefile
	cd tmp && zip -r ../proj_54.zip .
	rm -rf tmp

User DS:
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	@rm -rf */*.o User DS
