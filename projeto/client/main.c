#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "../common/common.h"
#include "commands.h"

#define DEFAULT_PORT "58054"
#define MAX_COMMAND 12
#define MAX_LINE 273

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

command_type_t process_command(sockets_t sockets) {
    char raw_input[MAX_LINE];
    char command[MAX_COMMAND];
    int command_length;

    if (fgets(raw_input, sizeof raw_input, stdin) == NULL) {
        exit(EXIT_FAILURE);
    }
    sscanf(raw_input, "%11s%n", command, &command_length);

    command_type_t command_type = LOCAL;

    if (strcmp(command, "exit") == 0)
        command_type = EXIT;
    else if (strcmp(command, "su") == 0 || strcmp(command, "showuid") == 0)
        command_type = show_uid();
    else if (strcmp(command, "reg") == 0)
        command_type = register_user(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "unr") == 0 || strcmp(command, "unregister") == 0)
        command_type = unregister_user(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "login") == 0)
        command_type = login(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "logout") == 0)
        command_type = logout(sockets);
    else if (strcmp(command, "gl") == 0 || strcmp(command, "groups") == 0)
        command_type = list_groups(sockets);
    else if (strcmp(command, "subscribe") == 0 || strcmp(command, "s") == 0)
        command_type = subscribe_group(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "unsubscribe") == 0 || strcmp(command, "u") == 0)
        command_type = unsubscribe_group(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "my_groups") == 0 || strcmp(command, "mgl") == 0)
        command_type = list_user_groups(sockets);
    else if (strcmp(command, "select") == 0 || strcmp(command, "sag") == 0)
        command_type = select_group(raw_input + command_length + 1);
    else if (strcmp(command, "showgid") == 0 || strcmp(command, "sg") == 0)
        command_type = show_gid();
    else if (strcmp(command, "ulist") == 0 || strcmp(command, "ul") == 0)
        command_type = list_group_users(sockets);
    else if (strcmp(command, "post") == 0)
        command_type = post(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "retrieve") == 0)
        command_type = retrieve(sockets, raw_input + command_length + 1);
    return command_type;
}

void set_timeout(int fd, int sec) {
    struct timeval timeout;
    memset((char *)&timeout, 0, sizeof(timeout));
    timeout.tv_sec = 2;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    sockets_t sockets;

    sockets.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockets.udp_fd == -1)
        exit(EXIT_FAILURE);
    set_timeout(sockets.udp_fd, 10);

    sockets.udp_addr = get_server_address(args.ip, args.port, SOCK_DGRAM);
    sockets.tcp_addr = get_server_address(args.ip, args.port, SOCK_STREAM);

    while (true) {
        printf("> ");
        command_type_t type = process_command(sockets);
        if (type == EXIT)
            break;
    }

    freeaddrinfo(sockets.udp_addr);
    freeaddrinfo(sockets.tcp_addr);
    close(sockets.udp_fd);

    return 0;
}
