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

#include "../common/common.h"

#define DEFAULT_PORT "58054"
#define MAX_MESSAGE 128
#define MAX_RESPONSE 3275

typedef struct {
    char *port;
    bool verbose;
} args_t;

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

bool register_user(const char *uid, const char *pass) {
    char user_dirname[20];
    char user_pass[34];
    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    // Make sure the USERS directory exists
    mkdir("USERS", 0700);

    if (mkdir(user_dirname, 0700) == -1)
        return false;

    FILE *pass_file = fopen(user_pass, "w");
    if (!pass_file)
        return false;

    fputs(pass, pass_file);
    fclose(pass_file);

    return true;
}

bool unregister_user(const char *uid, const char *pass) {
    char user_dirname[20];
    char user_pass[34];
    char realpass[9];

    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    FILE *pass_file = fopen(user_pass, "r");
    if (!pass_file)
        return false;

    fscanf(pass_file, "%8s", realpass);
    fclose(pass_file);
    realpass[8] = '\n';

    printf("%s vs %s\n", pass, realpass);

    if (strcmp(pass, realpass) != 0)
        return false;

    if (rmdir(user_dirname) == 0)
        return true;

    return false;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    int fd;
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;
    char buffer[MAX_MESSAGE];
    char response[MAX_RESPONSE];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
        exit(EXIT_FAILURE);

    struct addrinfo *res = get_server_address(NULL, args.port, SOCK_DGRAM);

    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);

    fd_set current_sockets, ready_sockets;
    FD_ZERO(&current_sockets);
    FD_SET(fd, &current_sockets);

    while (true) {
        ready_sockets = current_sockets;
        if (select(FD_SETSIZE, &ready_sockets, NULL, NULL, NULL) < 0)
            exit(EXIT_FAILURE);

        if (FD_ISSET(fd, &ready_sockets)) {
            char command[4];
            n = udp_receive(fd, buffer, sizeof buffer, &addr, &addrlen);
            sscanf(buffer, "%3s", command);

            if (strcmp(command, "REG") == 0) {
                char uid[6] = {0};
                char pass[9] = {0};
                sscanf(buffer + 4, "%5s%8s", uid, pass);

                if (register_user(uid, pass)) {
                    if (args.verbose)
                        printf("UID=%s: new user\n", uid);
                    sprintf(response, "RRG OK\n");
                } else {
                    sprintf(response, "RRG NOK\n");
                }
            } else if (strcmp(command, "UNR") == 0) {
                char uid[6] = {0};
                char pass[9] = {0};
                sscanf(buffer + 4, "%5s%8s", uid, pass);

                if (unregister_user(uid, pass)) {
                    sprintf(response, "RUN OK\n");
                } else {
                    sprintf(response, "RUN NOK\n");
                }
            } else if (strcmp(command, "UNR") == 0) {
                char uid[6] = {0};
                char pass[9] = {0};
                sscanf(buffer + 4, "%5s%8s", uid, pass);
                sprintf(response, "RUN NOK\n");
            }

            udp_send(fd, response, (struct sockaddr *)&addr, addrlen);
        }
    }

    freeaddrinfo(res);
    close(fd);

    return 0;
}
