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
#define MAX_COMMAND 12
#define MAX_LINE 273
#define MAX_MESSAGE 39
#define MAX_RESPONSE 3275

typedef enum {
    EXIT,
    LOCAL,
    REMOTE
} command_type_t;

typedef struct {
    char *port;
    char *ip;
} args_t;

char uid[6] = {0};
char pass[9] = {0};
bool logged_in = false;

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

command_type_t process_command(int fd, struct addrinfo *res_udp, char *response) {
    char raw_input[MAX_LINE];
    char command[MAX_COMMAND];
    int inc;

    if (fgets(raw_input, sizeof raw_input, stdin) == NULL) {
        exit(EXIT_FAILURE);
    }
    
    sscanf(raw_input, "%11s%n", command, &inc);
    
    if (strcmp(command, "exit") == 0)
        return EXIT;
    if (strcmp(command, "su") == 0 || strcmp(command, "showuid") == 0) {
        if (logged_in)
            printf("Your UID is %s\n", uid);
        return LOCAL;
    }
    
    char message[MAX_MESSAGE];
    if (strcmp(command, "reg") == 0) {
        char arg1[6], arg2[9];
        sscanf(raw_input + inc, "%5s%8s", arg1, arg2);
        sprintf(message, "REG %s %s\n", arg1, arg2);
    } else if (strcmp(command, "unr") == 0 || strcmp(command, "unregister") == 0) {
        char arg1[6], arg2[9];
        sscanf(raw_input + inc, "%5s%8s", arg1, arg2);
        sprintf(message, "UNR %s %s\n", arg1, arg2);
    } else if (strcmp(command, "login") == 0) {
        char arg1[5], arg2[8];
        sscanf(raw_input + inc, "%5s%8s", arg1, arg2);
        strncpy(uid, arg1, 5);
        strncpy(pass, arg2, 8);
        sprintf(message, "LOG %s %s\n", arg1, arg2);
    } else if (strcmp(command, "logout") == 0) {
        sprintf(message, "OUT %s %s\n", uid, pass);
        memset(uid, 0, sizeof uid);
        memset(pass, 0, sizeof pass);
    } else if (strcmp(command, "gl") == 0 || strcmp(command, "groups") == 0) {
        strcpy(message, "GLS\n");
    } else if (strcmp(command, "subscribe") == 0 || strcmp(command, "s") == 0) {
        char gid[3], name[25];
        sscanf(raw_input + inc, "%2s%24s", gid, name);
        if (!logged_in)
            return LOCAL;
            
        sprintf(message, "GSR %s %s %s\n", uid, gid, name);
    } else if (strcmp(command, "unsubscribe") == 0) {
        char gid[3];
        sscanf(raw_input + inc, "%2s", gid);
        if (!logged_in)
            return LOCAL;
        sprintf(message, "GUR %s %s\n", uid, gid);
    } else if (strcmp(command, "my_groups") == 0 || strcmp(command, "mgl") == 0) {
        if (!logged_in)
            return LOCAL;
        sprintf(message, "GLM %s\n", uid);
    }
    
    ssize_t n = udp_client_send(fd, message, res_udp);
    n = udp_client_receive(fd, response, MAX_RESPONSE);

    return REMOTE;
}

void process_reply(char *reply) {
    char prefix[4];
    sscanf(reply, "%3s", prefix);
    //printf("%s\n", reply);
    if (strcmp(prefix, "RRG") == 0) {
        char status[4];
        sscanf(reply + 4, "%3s", status);
        if (strcmp(status, "OK") == 0)
            printf("User successfully registered\n");
        else if (strcmp(status, "DUP") == 0)
            printf("User already registered\n");
        else if (strcmp(status, "NOK") == 0)
            printf("User registration failed\n");
    } else if (strcmp(prefix, "RUN") == 0) {
        char status[4];
        sscanf(reply + 4, "%3s", status);
        if (strcmp(status, "OK") == 0)
            printf("User successfully unregistered\n");
        else if (strcmp(status, "NOK") == 0)
            printf("User unregistration failed\n");
    } else if (strcmp(prefix, "RLO") == 0) {
        char status[4];
        sscanf(reply + 4, "%3s", status);
        if (strcmp(status, "OK") == 0) {
            printf("You are now logged in\n");
            logged_in = true;
        }
        else if (strcmp(status, "NOK") == 0) {
            printf("Login failed\n");
            logged_in = false;
        }
    } else if (strcmp(prefix, "ROU") == 0) {
        char status[4];
        sscanf(reply + 4, "%3s", status);
        if (strcmp(status, "OK") == 0) {
            printf("You are now logged out\n");
            logged_in = false;
        }
    } else if (strcmp(prefix, "RGL") == 0) {
        int n;
        char *cursor = reply + 4;
        int inc;
        sscanf(reply + 4, "%d%n", &n, &inc);
        cursor += inc + 1;
        for (size_t i = 0; i < n; i++) {
            char gid[3], name[25], mid[5];
            sscanf(cursor, "%2s%24s%4s%n", gid, name, mid, &inc);
            cursor += inc;
            printf("Group %s - \"%s\"\n", gid, name);
        }
    } else if (strcmp(prefix, "RGS") == 0) {
        char status[8];
        sscanf(reply + 4, "%7s", status);
        if (strcmp(status, "OK") == 0) {
            printf("You are now subscribed\n");
        }
        printf("%s", reply);
    } else if (strcmp(prefix, "RGU") == 0) {
        char status[5];
        sscanf(reply + 4, "%4s", status);
        if (strcmp(status, "OK") == 0) {
            printf("Group successfully unsubscribed\n");
        }
        printf("%s", reply);
    } else if (strcmp(prefix, "RGM") == 0) {
        int n;
        char *cursor = reply + 4;
        int inc;
        sscanf(reply + 4, "%d%n", &n, &inc);
        cursor += inc + 1;
        for (size_t i = 0; i < n; i++) {
            char gid[3], name[25], mid[5];
            sscanf(cursor, "%2s%24s%4s%n", gid, name, mid, &inc);
            cursor += inc;
            printf("Group %s - \"%s\"\n", gid, name);
        }
    }
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) exit(EXIT_FAILURE);
    struct addrinfo *res = get_server_address(args.ip, args.port, SOCK_DGRAM);

    while (true) {
        printf("> ");
        char reply[MAX_RESPONSE];
        command_type_t type = process_command(fd, res, reply);

        if (type == EXIT)
            break;
        else if (type == REMOTE)
            process_reply(reply);
    }

    freeaddrinfo(res);
    close(fd);
    return 0;
}
