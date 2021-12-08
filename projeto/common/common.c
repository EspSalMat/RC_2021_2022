#include <sys/socket.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

struct addrinfo *get_server_address(const char *ip, const char *port, int socktype) {
    struct addrinfo hints, *res;
    int errcode;

    // Set the hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;    
    hints.ai_socktype = socktype;

    errcode = getaddrinfo(ip, port, &hints, &res);
    if (errcode != 0) exit(EXIT_FAILURE);

    return res;
}

ssize_t udp_send(int fd, const char *buffer, const struct sockaddr* addr, const socklen_t addrlen) {
    ssize_t n = sendto(fd, buffer, strlen(buffer), 0, addr, addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);

    return n;
}

ssize_t udp_client_send(int fd, const char *buffer, const struct addrinfo *addr) {
    return udp_send(fd, buffer, addr->ai_addr, addr->ai_addrlen);
}

ssize_t udp_receive(int fd, char *buffer, struct sockaddr_in* addr, socklen_t *addrlen) {
    *addrlen = sizeof addr;

    ssize_t n = recvfrom(fd, buffer, sizeof buffer, 0, (struct sockaddr*) addr, addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);
    
    return n;
}

ssize_t udp_client_receive(int fd, char *buffer) {
    struct sockaddr_in addr;
    socklen_t addrlen;
    return udp_receive(fd, buffer, &addr, &addrlen);
}
