#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>

#include "commands.h"

char uid[6] = {0};
char pass[9] = {0};
bool logged_in = false;
char active_group[3] = {0};
bool group_selected = false;

void get_udp_reply(char *udp_reply, int size, int server_fd, struct addrinfo *server_addr,
                   char *message) {
    ssize_t n;
    response_t res;
    unsigned int attempts = 0;

    do {
        n = udp_client_send(server_fd, message, server_addr);
        res = udp_client_receive(server_fd, udp_reply, size);
    } while (res.timeout && (++attempts) < 3);
}

command_type_t show_uid() {
    if (logged_in)
        printf("%s\n", uid);
    else
        printf("You are not logged in\n");
    return LOCAL;
}

command_type_t register_user(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%s%s", id, password);

    char message[20];
    sprintf(message, "REG %s %s\n", id, password);

    char reply[8];
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[4];
    sscanf(reply, "%3s%3s", prefix, status);
    if (strcmp(prefix, "RRG") == 0) {
        if (strcmp(status, "OK") == 0)
            printf("User successfully registered\n");
        else if (strcmp(status, "DUP") == 0)
            printf("User already registered\n");
        else if (strcmp(status, "NOK") == 0)
            printf("User registration failed\n");
    }

    return UDP;
}

command_type_t unregister_user(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);

    char message[20];
    sprintf(message, "UNR %s %s\n", id, password);

    char reply[8];
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[4];
    sscanf(reply, "%3s%3s", prefix, status);
    if (strcmp(prefix, "RUN") == 0) {
        if (strcmp(status, "OK") == 0)
            printf("User successfully unregistered\n");
        else if (strcmp(status, "NOK") == 0)
            printf("User unregistration failed\n");
    }

    return UDP;
}

command_type_t login(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);

    char message[20];
    sprintf(message, "LOG %s %s\n", id, password);

    strncpy(uid, id, 5);
    strncpy(pass, password, 8);

    char reply[8];
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[4];
    sscanf(reply, "%3s%3s", prefix, status);
    if (strcmp(prefix, "RLO") == 0) {
        if (strcmp(status, "OK") == 0) {
            printf("You are now logged in\n");
            logged_in = true;
        } else if (strcmp(status, "NOK") == 0) {
            printf("Login failed\n");
            logged_in = false;
        }
    }

    return UDP;
}

command_type_t logout(sockets_t sockets) {
    char message[20];
    sprintf(message, "OUT %s %s\n", uid, pass);

    memset(uid, 0, sizeof uid);
    memset(pass, 0, sizeof pass);

    char reply[8];
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[4];
    sscanf(reply, "%3s%3s", prefix, status);
    if (strcmp(prefix, "ROU") == 0) {
        if (strcmp(status, "OK") == 0) {
            printf("You are now logged out\n");
            logged_in = false;
            group_selected = false;
        } else if (strcmp(status, "NOK") == 0) {
            printf("Logout failed\n");
        }
    }

    return UDP;
}

void show_groups(char *reply, int offset, int n) {
    char *cursor = reply + offset;
    for (size_t i = 0; i < n; i++) {
        char gid[3], name[25], mid[5];
        int inc;
        sscanf(cursor, "%2s%24s%4s%n", gid, name, mid, &inc);
        cursor += inc;
        printf("Group %s - \"%s\"\n", gid, name);
    }
}

command_type_t list_groups(sockets_t sockets) {
    char message[5];
    strcpy(message, "GLS\n");

    char reply[3274];
    get_udp_reply(reply, 3274, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4];
    int n, offset;
    sscanf(reply, "%3s%d%n", prefix, &n, &offset);
    if (strcmp(prefix, "RGL") == 0) {
        if (n == 0)
            printf("No groups to list\n");
        else
            show_groups(reply, offset, n);
    }

    return UDP;
}

command_type_t subscribe_group(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    }

    char name[25];
    int gid;
    sscanf(args, "%2d%24s", &gid, name);

    char message[29];
    sprintf(message, "GSR %s %02d %s\n", uid, gid, name);

    char reply[11];
    get_udp_reply(reply, 11, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[8];
    sscanf(reply, "%3s%7s", prefix, status);
    if (strcmp(prefix, "RGS") == 0) {
        if (strcmp(status, "OK") == 0)
            printf("You are now subscribed\n");
        else if (strcmp(status, "NEW") == 0) {
            int new_gid;
            sscanf(reply + 8, "%d", &new_gid);
            printf("New group created with ID %02d\n", new_gid);
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

    return UDP;
}

command_type_t unsubscribe_group(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    }

    int gid;
    sscanf(args, "%2d", &gid);

    char message[14];
    sprintf(message, "GUR %s %02d\n", uid, gid);

    char reply[10];
    get_udp_reply(reply, 10, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[6];
    sscanf(reply, "%3s%5s", prefix, status);
    if (strcmp(prefix, "RGU") == 0) {
        if (strcmp(status, "OK") == 0)
            printf("Group successfully unsubscribed\n");
        else if (strcmp(status, "NOK") == 0)
            printf("Unsubscription failed\n");
    }

    return UDP;
}

command_type_t list_user_groups(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    }

    char message[11];
    sprintf(message, "GLM %s\n", uid);

    char reply[3274];
    get_udp_reply(reply, 3274, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[6];
    int offset;
    sscanf(reply, "%3s%5s%n", prefix, status, &offset);
    if (strcmp(prefix, "RGM") == 0) {
        if (strcmp(status, "E_USR") == 0)
            printf("Invalid user ID\n");
        else {
            int n = atoi(status);
            if (n == 0)
                printf("No groups subscribed\n");
            else
                show_groups(reply, offset, n);
        }
    }

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

int read_tcp(int server_fd, char *buffer, size_t size) {
    ssize_t bytes_to_read = size;
    char *read_ptr = buffer;
    while (bytes_to_read > 0) {
        ssize_t bytes_read = read(server_fd, read_ptr, bytes_to_read);
        if (bytes_read == -1)
            exit(1);
        bytes_to_read -= bytes_read;
        read_ptr += bytes_read;
        if (*(read_ptr - 1) == '\n')
            return size - bytes_to_read;
    }
    return size;
}

void show_group_subscribers(int fd, char *buffer, int size, int bytes_read, int offset) {
    int offset_inc;
    char group_name[25], user_id[6];
    sscanf(buffer + offset, "%24s%n", group_name, &offset_inc);
    offset += offset_inc;
    if (buffer[offset] == '\n') {
        printf("%s has no subscribers\n", group_name);
    } else {
        printf("%s\n", group_name);
        bool incomplete_uid = false;
        while (buffer[offset] != '\n') {
            if (offset == bytes_read || offset == bytes_read - 1 || incomplete_uid) {
                bytes_read = read_tcp(fd, buffer, size);
                offset = 0;
            }
            if (buffer[offset] == '\n')
                break;

            if (!incomplete_uid) {
                sscanf(buffer + offset, " %5s%n", user_id, &offset_inc);
                if (offset + 5 > bytes_read - 1)
                    incomplete_uid = true;
            } else {
                char uid_fragment[5];
                sscanf(buffer, "%4s%n", uid_fragment, &offset_inc);
                strcpy(user_id + 5 - offset_inc, uid_fragment);
                incomplete_uid = false;
            }
            offset += offset_inc;

            if (!incomplete_uid)
                printf("%s\n", user_id);
        }
    }
}

command_type_t list_group_users(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    } else if (!group_selected) {
        printf("You don't have a group selected\n");
        return LOCAL;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        exit(EXIT_FAILURE);

    int n = connect(fd, sockets.tcp_addr->ai_addr, sockets.tcp_addr->ai_addrlen);
    if (n == -1)
        exit(EXIT_FAILURE);

    char message[7];
    sprintf(message, "ULS %s\n", active_group);
    send_tcp(fd, message, 7);

    char buffer[1025]; // must contain group name
    buffer[1024] = '\0';
    int bytes_read = read_tcp(fd, buffer, 1024);

    int offset;
    char prefix[4], status[4];
    sscanf(buffer, "%3s%3s%n", prefix, status, &offset);

    if (strcmp(status, "OK") == 0) {
        show_group_subscribers(fd, buffer, 1024, bytes_read, offset);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Failed to list subscribed users\n");
    }

    close(fd);

    return TCP;
}

void send_file_tcp(int fd, char *filename, size_t size) {
    char buffer[1024];
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
        exit(EXIT_FAILURE);
    while (size > 0) {
        ssize_t bytes_read = fread(buffer, 1, 1024, file);
        send_tcp(fd, buffer, bytes_read);
        size -= bytes_read;
    }
    fclose(file);
}

command_type_t post(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return LOCAL;
    } else if (!group_selected) {
        printf("You don't have a group selected\n");
        return LOCAL;
    }

    char text[241], name[25];
    text[240] = '\0';
    int text_size;
    int ret = sscanf(args, "\"%[^\"]\"%n %s", text, &text_size, name);
    if (ret == -1)
        exit(EXIT_FAILURE);
    else if (ret >= 1) {
        text_size -= 2;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
            exit(EXIT_FAILURE);

        int n = connect(fd, sockets.tcp_addr->ai_addr, sockets.tcp_addr->ai_addrlen);
        if (n == -1)
            exit(EXIT_FAILURE);

        char message[158];
        sprintf(message, "PST %s %s %d %s", uid, active_group, text_size, text);
        int message_size = strlen(message);
        send_tcp(fd, message, message_size);

        if (ret == 2) {
            struct stat st;
            if (stat(name, &st) != 0)
                exit(EXIT_FAILURE);
            size_t file_size = st.st_size;
            //TODO: check file size
            sprintf(message, " %s %ld ", name, file_size);
            message_size = strlen(message);
            send_tcp(fd, message, message_size);
            send_file_tcp(fd, name, file_size);
        }
        send_tcp(fd, "\n", 1);

        close(fd);
    }

    return TCP;
}
