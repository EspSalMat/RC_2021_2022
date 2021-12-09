#include <stdio.h>
#include <stdbool.h>
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
    
    char buffer[128];
    char command[3][128];
    char response[2][128];

    char uid[6] = {0};
    char pass[9] = {0};

    while (true) {
        write(1, "> ", 2);
        if (fgets(buffer, sizeof buffer, stdin) == NULL)
            exit(EXIT_FAILURE);

        if (sscanf(buffer, "%s%s%s", command[0], command[1], command[2]) <= 0)
            exit(EXIT_FAILURE);
        
        char message[128];
        if (strcmp(command[0], "reg") == 0) {
            sprintf(message, "REG %s %s\n", command[1], command[2]);
        } else if (strcmp(command[0], "unr") == 0 || strcmp(command[0], "unregister") == 0) {
            sprintf(message, "UNR %s %s\n", command[1], command[2]);
        } else if (strcmp(command[0], "login") == 0) {
            sprintf(message, "LOG %s %s\n", command[1], command[2]);
        } else if (strcmp(command[0], "logout") == 0) {
            sprintf(message, "OUT %s %s\n", uid, pass);
            memset(uid, 0, sizeof uid);
            memset(pass, 0, sizeof pass);
        } else if (strcmp(command[0], "su") == 0 || strcmp(command[0], "showuid") == 0) {
            printf("%s\n", uid);
            continue;
        } else if (strcmp(command[0], "gl") == 0 || strcmp(command[0], "groups") == 0) {
            strcpy(message, "GLS\n");
        } else if (strcmp(command[0], "exit") == 0) {
            break;
        }

        ssize_t n = udp_client_send(fd, message, res);
        n = udp_client_receive(fd, buffer);
        write(1, buffer, n);

        if (sscanf(buffer, "%s%s", response[0], response[1]) <= 0)
            exit(EXIT_FAILURE);

        if (strcmp(response[0], "RLO") == 0 && strcmp(response[1], "OK") == 0) {
            strncpy(uid, command[1], 5);
            strncpy(pass, command[2], 8);
        } else if (strcmp(response[0], "RGL") == 0) {
            int n = atoi(response[1]);
            for (size_t i = 0; i < n; i++) {
                char groups[3][128];
                sscanf(buffer, "%s%s%s", groups[0], groups[1], groups[2]);
                printf("%s %s %s\n", groups[0], groups[1], groups[2]);
            }
        }
    }

    /*
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
    */

    freeaddrinfo(res);
    close(fd);
    
    return 0;
}
