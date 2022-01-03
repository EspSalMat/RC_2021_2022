#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

struct addrinfo *get_server_address(const char *ip, const char *port, int socktype) {
    struct addrinfo hints, *res;
    int errcode;

    // Set the hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = socktype;

    errcode = getaddrinfo(ip, port, &hints, &res);
    if (errcode != 0)
        exit(EXIT_FAILURE);

    return res;
}

ssize_t send_udp(int fd, const char *buffer, const struct sockaddr *addr, const socklen_t addrlen) {
    ssize_t n = sendto(fd, buffer, strlen(buffer), 0, addr, addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);
    return n;
}

bool receive_udp(int fd, char *buffer, int size, struct sockaddr_in *addr, socklen_t *addrlen) {
    *addrlen = sizeof addr;

    ssize_t n = recvfrom(fd, buffer, size, 0, (struct sockaddr *)addr, addrlen);
    if (errno == EWOULDBLOCK)
        return true;

    if (n == -1)
        exit(EXIT_FAILURE);

    if (n < size)
        buffer[n] = '\0';

    return false;
}

void send_tcp(int fd, char *message, size_t size) {
    char *write_ptr = message;
    while (size > 0) {
        ssize_t bytes_written = write(fd, write_ptr, size);
        if (bytes_written <= 0)
            exit(1);
        size -= bytes_written;
        write_ptr += bytes_written;
    }
}


void send_file_tcp(int fd, char *filename, size_t size) {
    char buffer[1024];
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
        exit(EXIT_FAILURE);
    while (size > 0) {
        size_t bytes = 1024;
        if (size < 1024)
            bytes = size;
        ssize_t bytes_read = fread(buffer, 1, bytes, file);
        send_tcp(fd, buffer, bytes_read);
        size -= bytes_read;
    }
    fclose(file);
}

ssize_t receive_tcp(int server_fd, buffer_t buffer) {
    ssize_t bytes_to_read = buffer.size - 1;
    char *read_ptr = buffer.data;

    while (bytes_to_read > 0) {
        ssize_t bytes_read = read(server_fd, read_ptr, bytes_to_read);
        if (bytes_read == -1)
            exit(1);
        else if (bytes_read == 0)
            break;

        bytes_to_read -= bytes_read;
        read_ptr += bytes_read;
    }

    // Make sure it's null terminated
    ssize_t bytes_read = buffer.size - 1 - bytes_to_read;
    buffer.data[bytes_read] = '\0';

    return bytes_read;
}