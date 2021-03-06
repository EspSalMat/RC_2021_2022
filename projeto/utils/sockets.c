#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sockets.h"

/* Sets a timeout for input operations on a sockets */
void set_timeout(int fd, int sec) {
    struct timeval timeout;
    memset((char *)&timeout, 0, sizeof(timeout));
    timeout.tv_sec = sec;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);
}

/* Helper function go get the server's address data */
struct addrinfo *get_server_address(const char *ip, const char *port, int socktype) {
    struct addrinfo hints, *res;
    int errcode;

    // Set the hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = socktype;

    // If ip is NULL, gets the address of the local machine
    errcode = getaddrinfo(ip, port, &hints, &res);
    if (errcode != 0)
        return NULL;

    return res;
}

/* Sends a UDP message contained in a buffer and with the size of it */
ssize_t send_udp(int fd, buffer_t buffer, const struct sockaddr *addr, const socklen_t addrlen) {
    return sendto(fd, buffer.data, buffer.size, 0, addr, addrlen);
}

/* Receives a UDP reply and stores it in a buffer, making it null terminated */
ssize_t receive_udp(int fd, buffer_t buffer, struct sockaddr_in *addr, socklen_t *addrlen) {
    *addrlen = sizeof addr;

    // Can only receive messages with size up to buffer.size - 1 to ensure null-termination
    ssize_t n = recvfrom(fd, buffer.data, buffer.size - 1, 0, (struct sockaddr *)addr, addrlen);

    if (n == -1)
        return n;

    if (n < buffer.size)
        buffer.data[n] = '\0';

    return n;
}

/* Sends a TCP message with the size of the buffer that contains it */
bool send_tcp(int fd, buffer_t buffer) {
    char *write_ptr = buffer.data;
    size_t size = buffer.size;

    while (size > 0) {
        ssize_t bytes_written = write(fd, write_ptr, size);
        if (bytes_written <= 0)
            return true;
        size -= bytes_written;
        write_ptr += bytes_written;
    }

    return false;
}

/* Sends a file using TCP */
bool send_file_tcp(int fd, char *filename, size_t file_size) {
    buffer_t buffer;
    create_buffer(buffer, 1024);
    
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
        return true;
    
    while (file_size > 0) {
        size_t bytes = file_size < buffer.size ? file_size : buffer.size;
        bytes = fread(buffer.data, 1, bytes, file);
        if (bytes <= 0) {
            fclose(file);
            return true;
        }

        // Sends the number of bytes read from the buffer
        buffer_t tmp;
        tmp.data = buffer.data;
        tmp.size = bytes;
        if (send_tcp(fd, tmp))
            return true;

        file_size -= bytes;
    }

    if (fclose(file) < 0)
        return true;

    return false;
}

/* Receives a TCP reply and stores it in a buffer, making it null terminated */
ssize_t receive_tcp(int fd, buffer_t buffer) {
    // Can only receive messages with size up to buffer.size - 1 to ensure null-termination
    ssize_t bytes_to_read = buffer.size - 1;
    char *read_ptr = buffer.data;

    while (bytes_to_read > 0) {
        ssize_t bytes_read = read(fd, read_ptr, bytes_to_read);
        if (bytes_read == -1)
            return -1;
        else if (bytes_read == 0)
            break;

        bytes_to_read -= bytes_read;
        read_ptr += bytes_read;
        if (*(read_ptr - 1) == '\n')
            break;
    }

    // Make sure it's null terminated
    ssize_t bytes_read = buffer.size - 1 - bytes_to_read;
    buffer.data[bytes_read] = '\0';

    return bytes_read;
}
