#ifndef UTILS_SOCKETS_H
#define UTILS_SOCKETS_H

#include <netinet/in.h>
#include <stdbool.h>

typedef struct {
    char *data;
    size_t size;
} buffer_t;

#define create_buffer(buffer, N)                                                                   \
    char buffer##_data[N];                                                                         \
    buffer.size = N;                                                                            \
    buffer.data = buffer##_data

struct addrinfo *get_server_address(const char *ip, const char *port, int socktype);

// UDP functions
ssize_t send_udp(int fd, buffer_t buffer, const struct sockaddr *addr, const socklen_t addrlen);
ssize_t receive_udp(int fd, buffer_t buffer, struct sockaddr_in *addr, socklen_t *addrlen);

// TCP functions
bool send_tcp(int fd, buffer_t buffer);
bool send_file_tcp(int fd, char *filename, size_t size);
ssize_t receive_tcp(int fd, buffer_t buffer);

#endif /* UTILS_SOCKETS_H */