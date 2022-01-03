#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/common.h"
#include "commands.h"

char uid[6];
char pass[9];
bool logged_in = false;
char active_group[3];
bool group_selected = false;

void get_udp_reply(char *udp_reply, int size, int server_fd, struct addrinfo *server_addr,
                   char *message) {
    bool res;
    unsigned int attempts = 0;

    do {
        struct sockaddr_in addr;
        socklen_t addrlen;
        send_udp(server_fd, message, server_addr->ai_addr, server_addr->ai_addrlen);
        res = receive_udp(server_fd, udp_reply, size, &addr, &addrlen);
    } while (res && (++attempts) < 3);
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

    if (strcmp(reply, "RRG OK\n") == 0)
        printf("User successfully registered\n");
    else if (strcmp(reply, "RRG DUP\n") == 0)
        printf("User already registered\n");
    else if (strcmp(reply, "RRG NOK\n") == 0)
        printf("User registration failed\n");
    else
        return EXIT;

    return UDP;
}

command_type_t unregister_user(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);

    char message[20];
    sprintf(message, "UNR %s %s\n", id, password);

    char reply[8];
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "RUN OK\n") == 0)
        printf("User successfully unregistered\n");
    else if (strcmp(reply, "RUN NOK\n") == 0)
        printf("User unregistration failed\n");
    else
        return EXIT;

    return UDP;
}

command_type_t login(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);

    char message[20];
    sprintf(message, "LOG %s %s\n", id, password);

    strncpy(uid, id, 5);
    strncpy(pass, password, 8);

    char reply[8] = {0};
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "RLO OK\n") == 0) {
        printf("You are now logged in\n");
        logged_in = true;
    } else if (strcmp(reply, "RLO NOK\n") == 0) {
        printf("Login failed\n");
        logged_in = false;
    } else {
        return EXIT;
    }

    return UDP;
}

command_type_t logout(sockets_t sockets) {
    char message[20];
    sprintf(message, "OUT %s %s\n", uid, pass);

    memset(uid, 0, sizeof uid);
    memset(pass, 0, sizeof pass);

    char reply[8] = {0};
    get_udp_reply(reply, 8, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "ROU OK\n") == 0) {
        printf("You are now logged out\n");
        logged_in = false;
        group_selected = false;
    } else if (strcmp(reply, "ROU NOK\n") == 0) {
        printf("Logout failed\n");
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
            printf("New group created and subscribed: %02d – \"%s\"\n", new_gid, name);
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

    if (strcmp(reply, "RGU OK\n") == 0)
        printf("Group successfully unsubscribed\n");
    else if (strcmp(reply, "RGU NOK\n") == 0)
        printf("Unsubscription failed\n");

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
        printf("Group %s – \"%s\" is now the active group\n", active_group);
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

void show_group_subscribers(int fd, buffer_t buffer, int bytes_read, int offset) {
    int offset_inc;
    char group_name[25];
    char user_id[6];

    sscanf(buffer.data + offset, "%24s%n", group_name, &offset_inc);
    offset += offset_inc;

    if (buffer.data[offset] == '\n') {
        printf("%s has no subscribers\n", group_name);
        return;
    }

    printf("%s\n", group_name);

    while (buffer.data[offset] != '\n') {
        // Check if all of the buffer has been read
        if (offset == bytes_read || offset == bytes_read - 1) {
            bytes_read = receive_tcp(fd, buffer);
            offset = 0;
        }

        sscanf(buffer.data + offset, " %5s%n", user_id, &offset_inc);

        // Check if the buffer ended with an incomplete user id
        if (offset + offset_inc == bytes_read) {
            memcpy(buffer.data, buffer.data + offset, offset_inc);

            // Buffer object that points to the main buffer
            buffer_t tmp;
            tmp.data = buffer.data + offset_inc;
            tmp.size = buffer.size - offset_inc;

            bytes_read = receive_tcp(fd, tmp);
            offset = 0;
        } else {
            offset += offset_inc;
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

    buffer_t buffer;
    create_buffer(buffer, 1025);

    char message[7];
    sprintf(message, "ULS %s\n", active_group);
    send_tcp(fd, message, 7);

    int bytes_read = receive_tcp(fd, buffer);

    int offset;
    char prefix[4], status[4];
    sscanf(buffer.data, "%3s%3s%n", prefix, status, &offset);

    if (strcmp(status, "OK") == 0) {
        show_group_subscribers(fd, buffer, bytes_read, offset);
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
        size_t bytes = 1024;
        if (size < 1024)
            bytes = size;
        ssize_t bytes_read = fread(buffer, 1, bytes, file);
        send_tcp(fd, buffer, bytes_read);
        size -= bytes_read;
    }
    fclose(file);
}

bool is_mid(char *status) { return strlen(status) == 4; }
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
    int args_count = sscanf(args, "\"%[^\"]\"%n %s", text, &text_size, name);
    if (args_count == -1)
        exit(EXIT_FAILURE);
    else if (args_count >= 1) {
        text_size -= 2;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1)
            exit(EXIT_FAILURE);

        int n = connect(fd, sockets.tcp_addr->ai_addr, sockets.tcp_addr->ai_addrlen);
        if (n == -1)
            exit(EXIT_FAILURE);

        buffer_t buffer;
        create_buffer(buffer, 158);

        sprintf(buffer.data, "PST %s %s %d %s", uid, active_group, text_size, text);
        int message_size = strlen(buffer.data);
        send_tcp(fd, buffer.data, message_size);

        if (args_count == 2) {
            struct stat st;
            if (stat(name, &st) != 0)
                exit(EXIT_FAILURE);
            size_t file_size = st.st_size;
            // TODO: check file size
            sprintf(buffer.data, " %s %ld ", name, file_size);
            message_size = strlen(buffer.data);
            send_tcp(fd, buffer.data, message_size);
            send_file_tcp(fd, name, file_size);
        }
        send_tcp(fd, "\n", 1);

        receive_tcp(fd, buffer);

        char prefix[4], status[5];
        sscanf(buffer.data, "%3s%4s", prefix, status);

        if (strcmp(prefix, "RPT") == 0) {
            if (strcmp(status, "NOK") == 0) {
                printf("Failed t post message\n");
            } else if (is_mid(status)) {
                printf("Posted message number %s to group %s - \"(group_name)\"\n", status,
                       active_group);
            }
        } else {
            return EXIT;
        }

        close(fd);
    }

    return TCP;
}

void retrieve_messages(int fd, buffer_t buffer, int bytes_read, int offset, int message_count) {
    char mid[5], user_id[6], text[241], slash[2], file_name[25], max_entry[300];
    int args_count, offset_inc, text_size, messages_read = 0;
    size_t file_size;
    bool incomplete_entry = false, text_read = false, has_file = false;
    printf("%d message(s) retrieved:\n", message_count);

    while (messages_read < message_count) {
        if (offset == bytes_read || offset == bytes_read - 1) {
            bytes_read = receive_tcp(fd, buffer);
            offset = 0;
        }
        if (buffer.data[offset] == '\n' && messages_read == message_count)
            break;

        if (!incomplete_entry && !text_read) {
            args_count = sscanf(buffer.data + offset, "%4s%n%5s%n%3d%n", mid, &offset_inc, user_id,
                                &offset_inc, &text_size, &offset_inc);
            if (args_count < 3 || offset + offset_inc == bytes_read ||
                offset + offset_inc == bytes_read - 1) {
                strncpy(max_entry, buffer.data + offset, offset_inc);
                max_entry[offset_inc] = '\0';
                incomplete_entry = true;
                offset += offset_inc;
            } else {
                offset += offset_inc + 1;
                text[text_size] = '\0';
                char *read_ptr = text;
                while (text_size > 0) {
                    size_t bytes = 1024 - offset;
                    if (text_size < bytes)
                        bytes = text_size;

                    strncpy(read_ptr, buffer.data + offset, bytes);
                    read_ptr += bytes;
                    text_size -= bytes;
                    offset += bytes;
                    if (offset == 1024) {
                        bytes_read = receive_tcp(fd, buffer);
                        offset = 0;
                    }
                }
                text_read = true;
            }
        }
        if (!incomplete_entry && text_read) {
            args_count = sscanf(buffer.data + offset, "%1s%n%24s%n%10lu%n", slash, &offset_inc,
                                file_name, &offset_inc, &file_size, &offset_inc);
            if (args_count >= 1 && strcmp(slash, "/") == 0) {
                if (args_count < 3 || offset + offset_inc == bytes_read ||
                    offset + offset_inc == bytes_read - 1) {
                    strncpy(max_entry, buffer.data + offset, offset_inc);
                    max_entry[offset_inc] = '\0';
                    incomplete_entry = true;
                } else {
                    has_file = true;
                }
                offset += offset_inc;
            }
        }
        if (incomplete_entry) {
            int total_offset;
            strncpy(max_entry + offset_inc, buffer.data, 300 - offset_inc);
            max_entry[299] = '\0';
            if (!text_read) {
                args_count = sscanf(max_entry, "%4s%n%5s%n%3d%n", mid, &total_offset, user_id,
                                    &total_offset, &text_size, &total_offset);

                text[text_size] = '\0';
                char *read_ptr = text;
                while (text_size > 0) {
                    size_t bytes = 1024 - offset;
                    if (text_size < bytes)
                        bytes = text_size;

                    strncpy(read_ptr, buffer.data + offset, bytes);
                    read_ptr += bytes;
                    text_size -= bytes;
                    offset += bytes;
                    if (offset == 1024) {
                        bytes_read = receive_tcp(fd, buffer);
                        offset = 0;
                    }
                }
                text_read = true;
                text_read = true;
            } else {
                args_count =
                    sscanf(buffer.data + offset, "%1s%n%24s%n%10lu%n", slash, &total_offset,
                           file_name, &total_offset, &file_size, &total_offset);
            }
            offset += total_offset - offset_inc;
        }

        if (!incomplete_entry && text_read) {
            printf("%s - \"%s\";", mid, text);
            text_read = false;
            if (has_file) {
                has_file = false;
                FILE *file = fopen(file_name, "wb");
                // Write file;
                offset += 1;
                while (file_size > 0) {
                    size_t bytes = 1024 - offset;
                    if (file_size < bytes)
                        bytes = file_size;

                    ssize_t bytes_written = fwrite(buffer.data + offset, 1, bytes, file);
                    file_size -= bytes_written;
                    offset += bytes_written;
                    if (offset == 1024) {
                        bytes_read = receive_tcp(fd, buffer);
                        offset = 0;
                    }
                }
                printf(" file stored: %s", file_name);
                fclose(file);
            }
            printf("\n");
            messages_read++;
        }
    }
}

command_type_t retrieve(sockets_t sockets, char *args) {
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

    buffer_t buffer;
    create_buffer(buffer, 1025);

    int mid;
    if (sscanf(args, "%4d", &mid) != -1) {
        sprintf(buffer.data, "RTV %s %s %04d\n", uid, active_group, mid);
    }

    send_tcp(fd, buffer.data, 18);

    int bytes_read = receive_tcp(fd, buffer);

    int offset, message_count;
    char prefix[4], status[4];
    sscanf(buffer.data, "%3s%3s%2d%n", prefix, status, &message_count, &offset);

    if (strcmp(prefix, "RRT") == 0) {
        if (strcmp(status, "OK") == 0) {
            retrieve_messages(fd, buffer, bytes_read, offset, message_count);
        } else if (strcmp(status, "NOK") == 0) {
            printf("Failed to retrieve messages\n");
        }
    } else {
        return EXIT;
    }

    close(fd);

    return TCP;
}
