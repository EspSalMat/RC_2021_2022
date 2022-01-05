#include <netdb.h>
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

char uid[6];
char pass[9];
bool logged_in = false;
char active_group[3];
bool group_selected = false;

int tcp_connect(sockets_t sockets) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return fd;

    int n = connect(fd, sockets.tcp_addr->ai_addr, sockets.tcp_addr->ai_addrlen);
    if (n == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

ssize_t shift_buffer(int fd, buffer_t buffer, int offset, int offset_inc) {
    memcpy(buffer.data, buffer.data + offset, offset_inc);

    // Buffer object that points to the main buffer
    buffer_t tmp;
    tmp.data = buffer.data + offset_inc;
    tmp.size = buffer.size - offset_inc;

    return receive_tcp(fd, tmp);
}

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

bool show_uid() {
    if (!logged_in)
        printf("You are not logged in\n");
    else
        printf("%s\n", uid);

    return false;
}

bool register_user(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%s%s", id, password);

    char message[20];
    sprintf(message, "REG %s %s\n", id, password);

    char reply[9];
    get_udp_reply(reply, 9, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "RRG OK\n") == 0)
        printf("User successfully registered\n");
    else if (strcmp(reply, "RRG DUP\n") == 0)
        printf("User already registered\n");
    else if (strcmp(reply, "RRG NOK\n") == 0)
        printf("User registration failed\n");
    else
        return true;

    return false;
}

bool unregister_user(sockets_t sockets, char *args) {
    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);

    char message[20];
    sprintf(message, "UNR %s %s\n", id, password);

    char reply[9];
    get_udp_reply(reply, 9, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "RUN OK\n") == 0)
        printf("User successfully unregistered\n");
    else if (strcmp(reply, "RUN NOK\n") == 0)
        printf("User unregistration failed\n");
    else
        return true;

    return false;
}

bool login(sockets_t sockets, char *args) {
    if (logged_in) {
        printf("You are already logged in\n");
        return false;
    }

    char id[6], password[9];
    sscanf(args, "%5s%8s", id, password);

    char message[20];
    sprintf(message, "LOG %s %s\n", id, password);

    strncpy(uid, id, 5);
    strncpy(pass, password, 8);

    char reply[9] = {0};
    get_udp_reply(reply, 9, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "RLO OK\n") == 0) {
        printf("You are now logged in\n");
        logged_in = true;
    } else if (strcmp(reply, "RLO NOK\n") == 0) {
        printf("Login failed\n");
        logged_in = false;
    } else {
        return true;
    }

    return false;
}

bool logout(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    char message[20];
    sprintf(message, "OUT %s %s\n", uid, pass);

    memset(uid, 0, sizeof uid);
    memset(pass, 0, sizeof pass);

    char reply[9] = {0};
    get_udp_reply(reply, 9, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "ROU OK\n") == 0) {
        printf("You are now logged out\n");
        logged_in = false;
        group_selected = false;
    } else if (strcmp(reply, "ROU NOK\n") == 0) {
        printf("Logout failed\n");
    }

    return false;
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

bool list_groups(sockets_t sockets) {
    char message[5];
    strcpy(message, "GLS\n");

    char reply[3275];
    get_udp_reply(reply, 3275, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4];
    int n, offset;
    sscanf(reply, "%3s%d%n", prefix, &n, &offset);
    if (strcmp(prefix, "RGL") == 0) {
        if (n == 0)
            printf("No groups to list\n");
        else
            show_groups(reply, offset, n);
    }

    return false;
}

bool subscribe_group(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    char name[25];
    int gid;
    sscanf(args, "%2d%24s", &gid, name);

    char message[39];
    sprintf(message, "GSR %s %02d %s\n", uid, gid, name);

    char reply[12];
    get_udp_reply(reply, 12, sockets.udp_fd, sockets.udp_addr, message);

    char prefix[4], status[8];
    sscanf(reply, "%3s%7s", prefix, status);
    if (strcmp(prefix, "RGS") == 0) {
        if (strcmp(status, "OK") == 0)
            printf("You are now subscribed\n");
        else if (strcmp(status, "NEW") == 0) {
            int new_gid;
            sscanf(reply + 8, "%d", &new_gid);
            printf("New group created and subscribed: %02d - \"%s\"\n", new_gid, name);
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

    return false;
}

bool unsubscribe_group(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    int gid;
    sscanf(args, "%2d", &gid);

    char message[14];
    sprintf(message, "GUR %s %02d\n", uid, gid);

    char reply[11];
    get_udp_reply(reply, 11, sockets.udp_fd, sockets.udp_addr, message);

    if (strcmp(reply, "RGU OK\n") == 0)
        printf("Group successfully unsubscribed\n");
    else if (strcmp(reply, "RGU NOK\n") == 0)
        printf("Unsubscription failed\n");

    return false;
}

bool list_user_groups(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    char message[11];
    sprintf(message, "GLM %s\n", uid);

    char reply[3275];
    get_udp_reply(reply, 3275, sockets.udp_fd, sockets.udp_addr, message);

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

    return false;
}

bool select_group(char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    sscanf(args, "%2s", active_group);
    group_selected = true;
    printf("Group %s - \"%s\" is now the active group\n", active_group);

    return false;
}

bool show_gid() {
    if (!logged_in)
        printf("You are not logged in\n");
    else {
        if (group_selected)
            printf("%s\n", active_group);
        else
            printf("You don't have a group selected\n");
    }

    return false;
}

bool show_group_subscribers(int fd, buffer_t buffer, int bytes_read, int offset) {
    int offset_inc;
    char group_name[25];
    char user_id[6];

    sscanf(buffer.data + offset, "%24s%n", group_name, &offset_inc);
    offset += offset_inc;

    if (buffer.data[offset] == '\n') {
        printf("%s has no subscribers\n", group_name);
        return false;
    }

    printf("%s\n", group_name);

    while (buffer.data[offset] != '\n') {
        // Check if all of the buffer has been read
        if (offset == bytes_read || offset == bytes_read - 1) {
            bytes_read = receive_tcp(fd, buffer);
            if (bytes_read < 0)
                return true;
            offset = 0;
        }

        sscanf(buffer.data + offset, " %5s%n", user_id, &offset_inc);

        // Check if the buffer ended with an incomplete user id
        if (offset + offset_inc == bytes_read) {
            bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
            if (bytes_read < 0)
                return true;
            offset = 0;
        } else {
            offset += offset_inc;
            printf("%s\n", user_id);
        }
    }

    return false;
}

bool list_group_users(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    } else if (!group_selected) {
        printf("You don't have a group selected\n");
        return false;
    }

    int fd = tcp_connect(sockets);
    if (fd == -1)
        return true;

    buffer_t buffer;
    create_buffer(buffer, 1025);

    buffer_t message;
    create_buffer(message, 8);
    message.size = 7;
    sprintf(message.data, "ULS %s\n", active_group);
    if (send_tcp(fd, message)) {
        close(fd);
        return true;
    }

    int bytes_read = receive_tcp(fd, buffer);
    if (bytes_read < 0) {
        close(fd);
        return true;
    }

    int offset;
    char prefix[4], status[4];
    sscanf(buffer.data, "%3s%3s%n", prefix, status, &offset);

    if (strcmp(prefix, "RUL") == 0) {
        if (strcmp(status, "OK") == 0) {
            if (show_group_subscribers(fd, buffer, bytes_read, offset)) {
                close(fd);
                return true;
            }
        } else if (strcmp(status, "NOK") == 0) {
            printf("Failed to list subscribed users\n");
        }
    } else {
        close(fd);
        return true;
    }

    if (close(fd) == -1)
        return true;
    
    return false;
}

bool post(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    } else if (!group_selected) {
        printf("You don't have a group selected\n");
        return false;
    }

    char text[241], name[25];
    text[240] = '\0';
    int text_size;
    int args_count = sscanf(args, "\"%[^\"]\"%n %s", text, &text_size, name);
    if (args_count == -1)
        return true;
    else if (args_count >= 1) {
        text_size -= 2;

        int fd = tcp_connect(sockets);
        if (fd == -1)
            return true;

        buffer_t buffer;
        create_buffer(buffer, 158);

        sprintf(buffer.data, "PST %s %s %d %s", uid, active_group, text_size, text);

        buffer_t message;
        message.data = buffer.data;
        message.size = strlen(buffer.data);
        if (send_tcp(fd, message)) {
            close(fd);
            return true;
        }

        if (args_count == 2) {
            struct stat st;
            if (stat(name, &st) != 0)
                return true;
            size_t file_size = st.st_size;
            // TODO: check file size
            sprintf(buffer.data, " %s %ld ", name, file_size);
            message.size = strlen(buffer.data);

            if (send_tcp(fd, message)) {
                close(fd);
                return true;
            }
            if (send_file_tcp(fd, name, file_size)) {
                close(fd);
                return true;
            }
        }

        message.data = "\n";
        message.size = 1;
        if (send_tcp(fd, message)) {
            close(fd);
            return true;
        }

        ssize_t bytes_read = receive_tcp(fd, buffer);
        if (close(fd) == -1)
            return true;
        if (bytes_read < 0)
            return true;

        char prefix[4], status[5];
        sscanf(buffer.data, "%3s%4s", prefix, status);

        if (strcmp(prefix, "RPT") == 0) {
            if (strcmp(status, "NOK") == 0) {
                printf("Failed to post message\n");
            } else if (is_mid(status)) {
                printf("Posted message number %s to group %s - \"(group_name)\"\n", status,
                       active_group);
            }
        } else {
            return true;
        }
    }

    return false;
}

bool retrieve_messages(int fd, buffer_t buffer, ssize_t bytes_read, int offset, int message_count) {
    char mid[5], user_id[6], text[241], slash[2], file_name[25];
    int offset_inc, text_size, messages_read = 0;
    size_t file_size;
    FILE *file;

    printf("%d message(s) retrieved:\n", message_count);

    enum { MID, UID, TSIZE, TEXT, FILE_CHECK, FNAME, FSIZE, FDATA } current_state;

    while (messages_read < message_count) {
        switch (current_state) {
        case MID:
            sscanf(buffer.data + offset, "%4s%n", mid, &offset_inc);
            if (offset + offset_inc >= bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                offset = 0;
            } else {
                current_state = UID;
                offset += offset_inc;
            }
            break;

        case UID:
            sscanf(buffer.data + offset, "%5s%n", user_id, &offset_inc);
            if (offset + offset_inc >= bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                offset = 0;
            } else {
                current_state = TSIZE;
                offset += offset_inc;
            }
            break;

        case TSIZE:
            sscanf(buffer.data + offset, "%3d%n", &text_size, &offset_inc);
            if (offset + offset_inc >= bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                offset = 0;
            } else {
                current_state = TEXT;
                offset += offset_inc + 1;
            }
            break;

        case TEXT:
            text[text_size] = '\0';
            char *cursor = text;

            while (text_size > 0) {
                size_t bytes = buffer.size - offset - 1;
                if (text_size < bytes)
                    bytes = text_size;

                memcpy(cursor, buffer.data + offset, bytes);

                // Move cursor and offset
                cursor += bytes;
                text_size -= bytes;
                offset += bytes;

                if (offset >= bytes_read) {
                    bytes_read = receive_tcp(fd, buffer);
                    if (bytes_read < 0)
                        return true;
                    offset = 0;
                }
            }

            cursor--;
            if (*cursor == '\n')
                *cursor = '\0';

            current_state = FILE_CHECK;
            break;

        case FILE_CHECK:
            slash[0] = '\0';
            sscanf(buffer.data + offset, "%1s%n", slash, &offset_inc);
            printf("%s - \"%s\";", mid, text);

            if (slash[0] == '/') {
                current_state = FNAME;
                offset += offset_inc;
            } else {
                printf("\n");
                current_state = MID;
                messages_read++;
            }
            break;

        case FNAME:
            sscanf(buffer.data + offset, "%24s%n", file_name, &offset_inc);
            if (offset + offset_inc >= bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                offset = 0;
            } else {
                current_state = FSIZE;
                offset += offset_inc;
            }
            break;

        case FSIZE:
            sscanf(buffer.data + offset, "%lu%n", &file_size, &offset_inc);
            if (offset + offset_inc >= bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                offset = 0;
            } else {
                current_state = FDATA;
                offset += offset_inc + 1;
            }
            break;

        case FDATA:
            // printf("FDATA\n");
            file = fopen(file_name, "wb");
            if (file != NULL)
                return true;

            // Write file
            while (file_size > 0) {
                size_t bytes = buffer.size - offset - 1;
                if (file_size < bytes)
                    bytes = file_size;
                ssize_t bytes_written = fwrite(buffer.data + offset, 1, bytes, file);
                file_size -= bytes_written;
                offset += bytes_written;

                if (offset >= bytes_read) {
                    bytes_read = receive_tcp(fd, buffer);
                    if (bytes_read < 0) {
                        fclose(file);
                        return true;
                    }
                    offset = 0;
                }
            }

            printf(" file stored: %s\n", file_name);
            if (fclose(file) == EOF)
                return true;

            current_state = MID;
            messages_read++;
            break;

        default:
            break;
        }

        if (offset >= bytes_read - 1) {
            bytes_read = receive_tcp(fd, buffer);
            if (bytes_read < 0)
                return true;
            offset = 0;
        }
    }

    return false;
}

bool retrieve(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    } else if (!group_selected) {
        printf("You don't have a group selected\n");
        return false;
    }

    int fd = tcp_connect(sockets);
    if (fd == -1)
        return true;

    buffer_t buffer;
    create_buffer(buffer, 1025);

    int mid;
    if (sscanf(args, "%4d", &mid) != -1) {
        sprintf(buffer.data, "RTV %s %s %04d\n", uid, active_group, mid);
    }

    buffer_t message;
    message.data = buffer.data;
    message.size = 18;
    if (send_tcp(fd, message)) {
        close(fd);
        return true;
    }

    int bytes_read = receive_tcp(fd, buffer);
    if (bytes_read < 0) {
        close(fd);
        return true;
    }

    int offset, message_count;
    char prefix[4], status[4];
    sscanf(buffer.data, "%3s%3s%2d%n", prefix, status, &message_count, &offset);

    if (strcmp(prefix, "RRT") == 0) {
        if (strcmp(status, "OK") == 0) {
            if (retrieve_messages(fd, buffer, bytes_read, offset, message_count)) {
                close(fd);
                return true;
            }
        } else if (strcmp(status, "NOK") == 0) {
            printf("Failed to retrieve messages\n");
        }
    } else {
        close(fd);
        return true;
    }

    if (close(fd) == -1)
        return true;
    return false;
}
