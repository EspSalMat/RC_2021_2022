#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "args.h"

struct addrinfo *get_server_address(const args_t *args, int socktype) {
    struct addrinfo hints, *res;
    int errcode;

    // Set the hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;        
    hints.ai_socktype = socktype;

    errcode = getaddrinfo(args->ip, args->port, &hints, &res);
    if (errcode != 0) exit(EXIT_FAILURE);

    return res;
}

void udp_send(int fd, const char *buffer, const struct addrinfo *addr) {
    ssize_t n = sendto(fd, buffer, sizeof buffer, 0, addr->ai_addr, addr->ai_addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);
}

ssize_t udp_receive(int fd, char *buffer) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof addr;

    ssize_t n = recvfrom(fd, buffer, sizeof buffer, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);
    
    return n;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(EXIT_FAILURE);
    struct addrinfo *res = get_server_address(&args, SOCK_DGRAM);
    
    udp_send(fd, "Hello!\n", res);
    
    char buffer[128];
    ssize_t n = udp_receive(fd, buffer);

    write(1, "echo: ", 6);
    write(1, buffer, n);

    freeaddrinfo(res);
    close(fd);
    
    return 0;
}
