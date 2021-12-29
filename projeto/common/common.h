#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>

typedef struct {
    bool timeout;
    ssize_t bytes;
} response_t;

ssize_t udp_send(int fd, const char *buffer, const struct sockaddr *addr, const socklen_t addrlen);
ssize_t udp_client_send(int fd, const char *buffer, const struct addrinfo *addr);
response_t udp_receive(int fd, char *buffer, int size, struct sockaddr_in *addr, socklen_t *addrlen);
response_t udp_client_receive(int fd, char *buffer, int size);
struct addrinfo *get_server_address(const char *ip, const char *port, int socktype);

#endif /* COMMON_H */