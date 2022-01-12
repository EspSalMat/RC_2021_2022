#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../utils/sockets.h"
#include "../utils/validate.h"
#include "commands.h"
#include "requests.h"

#define DEFAULT_PORT "58054"
#define MAX_MESSAGE 129
#define MAX_RESPONSE 3275

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

bool handle_udp_request(int fd, args_t args) {
    buffer_t request;
    create_buffer(request, 39);

    // Client address
    struct sockaddr_in addr;
    socklen_t addrlen;

    ssize_t n = receive_udp(fd, request, &addr, &addrlen);
    if (n <= 0)
        return true;

    buffer_t res_err = {.data = "ERR\n", .size = 4};

    if (strncmp(request.data, "REG ", 4) == 0)
        return register_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "UNR ", 4) == 0)
        return unregister_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "LOG ", 4) == 0)
        return login_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "OUT ", 4) == 0)
        return logout_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "GLS\n", 4) == 0)
        return list_groups_request(fd, args, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "GSR ", 4) == 0)
        return subscribe_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "GUR ", 4) == 0)
        return unsubscribe_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "GLM ", 4) == 0)
        return list_subscribed_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else
        return send_udp(fd, res_err, (struct sockaddr *)&addr, addrlen) <= 0;

    return false;
}

bool handle_tcp_request(int fd, args_t args) {
    struct sockaddr_in addr;
    socklen_t addrlen;

    int client_fd = accept(fd, (struct sockaddr *)&addr, &addrlen);
    if (client_fd == -1)
        return true;

    buffer_t res_err = {.data = "ERR\n", .size = 4};
    buffer_t prefix;
    create_buffer(prefix, 5);

    // Read the request's prefix
    ssize_t bytes_read = receive_tcp(client_fd, prefix);
    if (bytes_read <= 0) {
        close(client_fd);
        return true;
    }

    bool error = false;

    if (strncmp(prefix.data, "ULS ", 4) == 0)
        error = subscribed_users(client_fd, args);
    else if (strncmp(prefix.data, "PST ", 4) == 0)
        error = post_request(client_fd, args);
    else if (strncmp(prefix.data, "RTV ", 4) == 0)
        error = retrieve_request(client_fd, args);
    else
        error = send_tcp(client_fd, res_err);

    close(client_fd);

    return error;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    int udp_fd, tcp_fd;

    // UDP
    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd == -1)
        exit(EXIT_FAILURE);

    struct addrinfo *udp_addr = get_server_address(NULL, args.port, SOCK_DGRAM);
    if (udp_addr == NULL) {
        close(udp_fd);
        exit(EXIT_FAILURE);
    }

    if (bind(udp_fd, udp_addr->ai_addr, udp_addr->ai_addrlen) == -1) {
        freeaddrinfo(udp_addr);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(udp_addr);

    // TCP
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        close(udp_fd);
        exit(EXIT_FAILURE);
    }

    struct addrinfo *tcp_addr = get_server_address(NULL, args.port, SOCK_DGRAM);
    if (tcp_addr == NULL) {
        close(udp_fd);
        close(tcp_fd);
        exit(EXIT_FAILURE);
    }

    if (bind(tcp_fd, tcp_addr->ai_addr, tcp_addr->ai_addrlen) == -1) {
        close(udp_fd);
        close(tcp_fd);
        freeaddrinfo(tcp_addr);
        exit(EXIT_FAILURE);
    }

    if (listen(tcp_fd, 5) == -1) {
        close(udp_fd);
        close(tcp_fd);
        freeaddrinfo(tcp_addr);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(tcp_addr);

    fd_set current_sockets, ready_sockets;
    FD_ZERO(&current_sockets);
    FD_SET(udp_fd, &current_sockets);
    FD_SET(tcp_fd, &current_sockets);
    int maxfd = (udp_fd > tcp_fd) ? udp_fd : tcp_fd;

    bool should_exit = false;

    while (!should_exit) {
        ready_sockets = current_sockets;
        if (select(maxfd + 1, &ready_sockets, NULL, NULL, NULL) < 0)
            exit(EXIT_FAILURE);

        if (FD_ISSET(udp_fd, &ready_sockets)) {
            if (handle_udp_request(udp_fd, args))
                should_exit = true;
        }

        if (FD_ISSET(tcp_fd, &ready_sockets)) {
            if (handle_tcp_request(tcp_fd, args))
                should_exit = true;
        }
    }

    close(tcp_fd);
    close(udp_fd);

    return 0;
}
