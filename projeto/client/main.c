#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#include "../common/common.h"

#define DEFAULT_PORT "58054"

typedef struct {
    char *port;
    char *ip;
} args_t;

args_t parse_args(int argc, char **argv) {
    args_t args;
    args.port = DEFAULT_PORT;
    args.ip = NULL;

    for (int i = 1; i < argc - 1; i += 2) {
        if (strcmp(argv[i], "-n") == 0) {
            args.ip = argv[i + 1];
        } else if (strcmp(argv[i], "-p") == 0) {
            args.port = argv[i + 1];
        }
    }

    return args;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(EXIT_FAILURE);
    struct addrinfo *res = get_server_address(args.ip, args.port, SOCK_DGRAM);
    
    ssize_t n = udp_client_send(fd, "REG 54323 password\n", res);
    printf("%zd\n", n);
    
    char buffer[128];
    n = udp_client_receive(fd, buffer);

    write(1, "echo: ", 6);
    write(1, buffer, n);

    udp_client_send(fd, "UNR 54323 password\n", res);
    n = udp_client_receive(fd, buffer);

    write(1, "echo: ", 6);
    write(1, buffer, n);

    freeaddrinfo(res);
    close(fd);
    
    return 0;
}
