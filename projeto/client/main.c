#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/common.h"

#define DEFAULT_PORT "58054"
#define MAX_COMMAND 12
#define MAX_LINE 273
#define MAX_MESSAGE 39
#define MAX_REPLY 3275

typedef enum { EXIT, LOCAL, UDP, TCP } command_type_t;

typedef struct {
    char *port;
    char *ip;
} args_t;

typedef struct {
    int udp_fd;
    struct addrinfo *udp_addr;
    struct addrinfo *tcp_addr;
} sockets_t;

char uid[6] = {0};
char pass[9] = {0};
bool logged_in = false;
char active_group[3] = {0};
bool group_selected = false;

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

command_type_t show_uid() {
    if (logged_in)
        printf("%s\n", uid);
    else
        printf("You are not logged in\n");
    return LOCAL;
}

command_type_t register_user(char *args, char *message) {
    char id[6], password[9];
    sscanf(args, "%s%s", id, password);
    sprintf(message, "REG %s %s\n", id, password);
    return UDP;
}

command_type_t unregister_user(char *args, char *message) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);
    sprintf(message, "UNR %s %s\n", id, password);
    return UDP;
}

command_type_t login(char *args, char *message) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);
    strncpy(uid, id, 5);
    strncpy(pass, password, 8);
    sprintf(message, "LOG %s %s\n", id, password);
    return UDP;
}

command_type_t logout(char *args, char *message) {
    sprintf(message, "OUT %s %s\n", uid, pass);
    memset(uid, 0, sizeof uid);
    memset(pass, 0, sizeof pass);
    return UDP;
}

command_type_t list_groups(char *message) {
    strcpy(message, "GLS\n");
    return UDP;
}

command_type_t subscribe_group(char *args, char *message) {
    char name[25];
    int gid;
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    }
    sscanf(args, "%2d%24s", &gid, name);
    sprintf(message, "GSR %s %02d %s\n", uid, gid, name);
    return UDP;
}

command_type_t unsubscribe_group(char *args, char *message) {
    int gid;
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    }
    sscanf(args, "%2d", &gid);
    sprintf(message, "GUR %s %02d\n", uid, gid);
    return UDP;
}

command_type_t list_user_groups(char *message) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    }
    sprintf(message, "GLM %s\n", uid);
    return UDP;
}

command_type_t select_group(char *args) {
    if (!logged_in)
        printf("You are not logged in\n");
    else {
        int gid;
        sscanf(args, "%2d", &gid);
        sprintf(active_group, "%02d", gid);
        group_selected = true;
        printf("Group %s selected\n", active_group);
    }
    return LOCAL;
}

command_type_t show_gid() {
    if (!logged_in)
        printf("You are not logged in\n");
    else {
        if (group_selected)
            printf("%s\n", active_group);
        else
            printf("You don't have a group selected\n");
    }

    return LOCAL;
}

command_type_t group_users_list(char *message) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    } else if (!group_selected) {
        printf("You don't have a group selected\n");
        return LOCAL;
    }

    sprintf(message, "ULS %s\n", active_group);

    return TCP;
}

command_type_t process_command(sockets_t sockets, char *reply) {
    char raw_input[MAX_LINE];
    char command[MAX_COMMAND];
    int command_length;

    if (fgets(raw_input, sizeof raw_input, stdin) == NULL) {
        exit(EXIT_FAILURE);
    }
    sscanf(raw_input, "%11s%n", command, &command_length);

    char message[MAX_MESSAGE];
    command_type_t command_type = LOCAL;

    if (strcmp(command, "exit") == 0)
        command_type = EXIT;
    else if (strcmp(command, "su") == 0 || strcmp(command, "showuid") == 0)
        command_type = show_uid();
    else if (strcmp(command, "reg") == 0)
        command_type = register_user(raw_input + command_length + 1, message);
    else if (strcmp(command, "unr") == 0 || strcmp(command, "unregister") == 0)
        command_type = unregister_user(raw_input + command_length + 1, message);
    else if (strcmp(command, "login") == 0)
        command_type = login(raw_input + command_length + 1, message);
    else if (strcmp(command, "logout") == 0)
        command_type = logout(raw_input + command_length + 1, message);
    else if (strcmp(command, "gl") == 0 || strcmp(command, "groups") == 0)
        command_type = list_groups(message);
    else if (strcmp(command, "subscribe") == 0 || strcmp(command, "s") == 0)
        command_type = subscribe_group(raw_input + command_length + 1, message);
    else if (strcmp(command, "unsubscribe") == 0)
        command_type = unsubscribe_group(raw_input + command_length + 1, message);
    else if (strcmp(command, "my_groups") == 0 || strcmp(command, "mgl") == 0)
        command_type = list_user_groups(message);
    else if (strcmp(command, "select") == 0 || strcmp(command, "sag") == 0)
        command_type = select_group(raw_input + command_length + 1);
    else if (strcmp(command, "showgid") == 0 || strcmp(command, "sg") == 0)
        command_type = show_gid();
    else if (strcmp(command, "ulist") == 0 || strcmp(command, "ul") == 0)
        command_type = group_users_list(message);

    if (command_type == UDP) {
        ssize_t n;
        response_t res;
        unsigned int attempts = 0;

        do {
            n = udp_client_send(sockets.udp_fd, message, sockets.udp_addr);
            res = udp_client_receive(sockets.udp_fd, reply, MAX_REPLY);
        } while (res.timeout && (++attempts) < 3);
    } else if (command_type == TCP) {
        // TODO: make sure the "buffer" is empty (unlink first)
        FILE *tcp_buffer = fopen("tcp_buffer.txt", "w+");
        if (tcp_buffer == NULL)
            exit(EXIT_FAILURE);

        int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_fd == -1)
            exit(EXIT_FAILURE);

        int n = connect(tcp_fd, sockets.tcp_addr->ai_addr, sockets.tcp_addr->ai_addrlen);
        if (n == -1)
            exit(EXIT_FAILURE);

        ssize_t nbytes, nleft, nwritten, nread;
        char *ptr = message;
        for (nbytes = 0; ptr[nbytes - 1] != '\n'; nbytes++)
            ;
        nleft = nbytes;

        while (nleft > 0) {
            nwritten = write(tcp_fd, ptr, nleft);
            if (nwritten <= 0)
                exit(1);
            nleft -= nwritten;
            ptr += nwritten;
        }

        // Read
        ptr = reply;
        nread = 0;

        while (reply[nread] != '\n') {
            ssize_t n = read(tcp_fd, ptr, MAX_REPLY);

            if (n == -1)
                exit(1);
            else if (n == 0)
                break;

            fwrite(ptr, n, 1, tcp_buffer);
            ptr += n;
            nread += n;
        }

        fflush(tcp_buffer);
        fseek(tcp_buffer, 0, SEEK_SET);
        char prefix[4], status[4];
        fscanf(tcp_buffer, "%3s%3s", prefix, status);
        if (strcmp(prefix, "RUL") == 0) {
            if (strcmp(status, "OK") == 0) {
                char group_name[25];
                char user_id[6];
                fscanf(tcp_buffer, "%24s", group_name);
                printf("%s\n", group_name);
                while(fscanf(tcp_buffer, "%5s", user_id) > 0)
                    printf("%s\n", user_id);
            } else if (strcmp(status, "NOK") == 0) {
                printf("Failed to list subscribed users\n");
            }
        }



        fclose(tcp_buffer);
        close(tcp_fd);
    }

    return command_type;
}

void register_user_status(char *reply) {
    char status[4];
    sscanf(reply + 4, "%3s", status);
    if (strcmp(status, "OK") == 0)
        printf("User successfully registered\n");
    else if (strcmp(status, "DUP") == 0)
        printf("User already registered\n");
    else if (strcmp(status, "NOK") == 0)
        printf("User registration failed\n");
}

void unregister_user_status(char *reply) {
    char status[4];
    sscanf(reply + 4, "%3s", status);
    if (strcmp(status, "OK") == 0)
        printf("User successfully unregistered\n");
    else if (strcmp(status, "NOK") == 0)
        printf("User unregistration failed\n");
}

void login_status(char *reply) {
    char status[4];
    sscanf(reply + 4, "%3s", status);
    if (strcmp(status, "OK") == 0) {
        printf("You are now logged in\n");
        logged_in = true;
    } else if (strcmp(status, "NOK") == 0) {
        printf("Login failed\n");
        logged_in = false;
    }
}

void logout_status(char *reply) {
    char status[4];
    sscanf(reply + 4, "%3s", status);
    if (strcmp(status, "OK") == 0) {
        printf("You are now logged out\n");
        logged_in = false;
        group_selected = false;

    } else if (strcmp(status, "NOK") == 0) {
        printf("Logout failed\n");
    }
}

void show_groups(char *reply) {
    int n;
    char *cursor = reply + 4;
    int inc;
    sscanf(reply + 4, "%d%n", &n, &inc);
    if (n == 0)
        printf("No groups to list\n");

    cursor += inc + 1;
    for (size_t i = 0; i < n; i++) {
        char gid[3], name[25], mid[5];
        sscanf(cursor, "%2s%24s%4s%n", gid, name, mid, &inc);
        cursor += inc;
        printf("Group %s - \"%s\"\n", gid, name);
    }
}

void subscribe_group_status(char *reply) {
    char status[8];
    sscanf(reply + 4, "%7s", status);
    if (strcmp(status, "OK") == 0)
        printf("You are now subscribed\n");
    else if (strcmp(status, "NEW") == 0) {
        int gid;
        sscanf(reply + 8, "%d", &gid);
        printf("New group created with ID %02d\n", gid);
    } else if (strcmp(status, "E_USR") == 0)
        printf("Invalid user id\n");
    else if (strcmp(status, "E_GRP") == 0)
        printf("Invalid group id\n");
    else if (strcmp(status, "E_GNAME") == 0)
        printf("Invalid group name\n");
    else if (strcmp(status, "E_FULL") == 0)
        printf("Group could not be created\n");
    else if (strcmp(status, "NOK") == 0)
        printf("Subscription failed\n");
}

void unsubscribe_group_status(char *reply) {
    char status[5];
    sscanf(reply + 4, "%4s", status);
    if (strcmp(status, "OK") == 0)
        printf("Group successfully unsubscribed\n");
    else if (strcmp(status, "NOK") == 0)
        printf("Unsubscription failed\n");
}

void show_subscribed_groups(char *reply) {
    char status[6];
    if (strcmp(status, "E_USR") == 0)
        printf("Invalid user ID\n");
    else
        show_groups(reply);
}

void process_udp_reply(char *reply) {
    char prefix[4];
    sscanf(reply, "%3s", prefix);
    if (strcmp(prefix, "RRG") == 0)
        register_user_status(reply);
    else if (strcmp(prefix, "RUN") == 0)
        unregister_user_status(reply);
    else if (strcmp(prefix, "RLO") == 0)
        login_status(reply);
    else if (strcmp(prefix, "ROU") == 0)
        logout_status(reply);
    else if (strcmp(prefix, "RGL") == 0)
        show_groups(reply);
    else if (strcmp(prefix, "RGS") == 0)
        subscribe_group_status(reply);
    else if (strcmp(prefix, "RGU") == 0)
        unsubscribe_group_status(reply);
    else if (strcmp(prefix, "RGM") == 0)
        show_subscribed_groups(reply);
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
        char reply[MAX_REPLY];
        command_type_t type = process_command(sockets, reply);

        if (type == EXIT)
            break;
        else if (type == UDP)
            process_udp_reply(reply);
    }

    freeaddrinfo(sockets.udp_addr);
    freeaddrinfo(sockets.tcp_addr);
    close(sockets.udp_fd);

    unlink("tcp_buffer.txt");

    return 0;
}
