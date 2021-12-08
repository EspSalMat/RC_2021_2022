#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>

#include "../common/common.h"

#define DEFAULT_PORT "58054"
#define MAX_MESSAGE 128

typedef struct {
    char *port;
    bool verbose;
} args_t;

args_t parse_args(int argc, char **argv) {
    args_t args;
    args.port = DEFAULT_PORT;
    args.verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            args.verbose = true;
        } else if (strcmp(argv[i], "-p") == 0 && i < argc - 1) {
            args.port = argv[i + 1];
            i++;
        }
    }

    return args;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    int fd;
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;
    char buffer[MAX_MESSAGE];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(EXIT_FAILURE);

    struct addrinfo *res = get_server_address(NULL, args.port, SOCK_DGRAM);

    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) exit(EXIT_FAILURE);

    while (true) {
        n = udp_receive(fd, buffer, &addr, &addrlen);
        write(1, "received: ", 10);
        write(1, buffer, n);
        udp_send(fd, buffer, (struct sockaddr *) &addr, addrlen);
    }

    freeaddrinfo(res);
    close(fd);

    return 0;
}
