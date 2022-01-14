#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>

#include "../utils/sockets.h"
#include "commands.h"

#define DEFAULT_PORT "58054"
#define MAX_COMMAND 12
#define MAX_LINE 273

/* Sructure that stores the command line argumnents */
typedef struct {
    char *port;
    char *ip;
} args_t;

/* Parse the command line argumnents into the args_t structure */
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

/* Reads and proccesses a command and returns true if the client should exit */
bool process_command(sockets_t sockets) {
    char raw_input[MAX_LINE];
    if (fgets(raw_input, sizeof raw_input, stdin) == NULL) {
        return true;
    }

    int command_length;
    char command[MAX_COMMAND] = {0};
    sscanf(raw_input, "%11s%n", command, &command_length);

    errno = 0;
    if (strcmp(command, "exit") == 0)
        return logout_on_exit(sockets);
    else if (strcmp(command, "su") == 0 || strcmp(command, "showuid") == 0)
        return show_uid();
    else if (strcmp(command, "reg") == 0)
        return register_user(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "unr") == 0 || strcmp(command, "unregister") == 0)
        return unregister_user(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "login") == 0)
        return login(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "logout") == 0)
        return logout(sockets);
    else if (strcmp(command, "gl") == 0 || strcmp(command, "groups") == 0)
        return list_groups(sockets);
    else if (strcmp(command, "subscribe") == 0 || strcmp(command, "s") == 0)
        return subscribe_group(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "unsubscribe") == 0 || strcmp(command, "u") == 0)
        return unsubscribe_group(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "my_groups") == 0 || strcmp(command, "mgl") == 0)
        return list_user_groups(sockets);
    else if (strcmp(command, "select") == 0 || strcmp(command, "sag") == 0)
        return select_group(raw_input + command_length + 1);
    else if (strcmp(command, "showgid") == 0 || strcmp(command, "sg") == 0)
        return show_gid();
    else if (strcmp(command, "ulist") == 0 || strcmp(command, "ul") == 0)
        return list_group_users(sockets);
    else if (strcmp(command, "post") == 0)
        return post(sockets, raw_input + command_length + 1);
    else if (strcmp(command, "retrieve") == 0)
        return retrieve(sockets, raw_input + command_length + 1);
    else
        return unknown_command();
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    sockets_t sockets;

    sockets.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockets.udp_fd == -1)
        exit(EXIT_FAILURE);
    set_timeout(sockets.udp_fd, 10);

    sockets.udp_addr = get_server_address(args.ip, args.port, SOCK_DGRAM);
    if (sockets.udp_addr == NULL) {
        close(sockets.udp_fd);
        exit(EXIT_FAILURE);
    }

    sockets.tcp_addr = get_server_address(args.ip, args.port, SOCK_STREAM);
    if (sockets.udp_addr == NULL) {
        close(sockets.udp_fd);
        freeaddrinfo(sockets.udp_addr);
        exit(EXIT_FAILURE);
    }

    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &act, NULL) == -1) {
        close(sockets.udp_fd);
        freeaddrinfo(sockets.udp_addr);
        exit(EXIT_FAILURE);
    }

    bool should_exit = false;
    while (!should_exit) {
        printf("> ");
        should_exit = process_command(sockets);
    }

    /* Prints a message if an error occured */
    int exit_code = EXIT_SUCCESS;
    if (errno != 0) {
        perror("Error");
        exit_code = EXIT_FAILURE;
    }

    freeaddrinfo(sockets.udp_addr);
    freeaddrinfo(sockets.tcp_addr);
    close(sockets.udp_fd);

    return exit_code;
}
