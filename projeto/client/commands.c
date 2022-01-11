#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

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

bool get_udp_reply(int fd, buffer_t message, buffer_t reply, struct addrinfo *server_addr) {
    ssize_t response = -1;
    unsigned int attempts = 0;

    do {
        if (send_udp(fd, message, server_addr->ai_addr, server_addr->ai_addrlen) > 0) {
            struct sockaddr_in addr;
            socklen_t addrlen;
            response = receive_udp(fd, reply, &addr, &addrlen);
        }
    } while (response <= 0 && (++attempts) < 3);

    return response <= 0;
}

bool logout_on_exit(sockets_t sockets) {
    if (!logged_in) {
        return true;
    }

    buffer_t message;
    create_buffer(message, 20);
    int n = sprintf(message.data, "OUT %s %s\n", uid, pass);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 9);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "ROU OK\n") != 0 && strcmp(reply.data, "ROU NOK\n") != 0) {
        errno = EPROTO;
        return true;
    }

    return true;
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
    if (sscanf(args, "%5s%8s", id, password) < 0)
        return true;

    buffer_t message;
    create_buffer(message, 20);
    int n = sprintf(message.data, "REG %s %s\n", id, password);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 9);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "RRG OK\n") == 0)
        printf("User successfully registered\n");
    else if (strcmp(reply.data, "RRG DUP\n") == 0)
        printf("User already registered\n");
    else if (strcmp(reply.data, "RRG NOK\n") == 0)
        printf("User registration failed\n");
    else {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool unregister_user(sockets_t sockets, char *args) {
    char id[6], password[9];
    if (sscanf(args, "%5s%8s", id, password) < 0)
        return true;

    buffer_t message;
    create_buffer(message, 20);
    int n = sprintf(message.data, "UNR %s %s\n", id, password);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 9);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "RUN OK\n") == 0) {
        // Log out if unregistering current logged in user
        if (logged_in && strcmp(id, uid) == 0) {
            logged_in = false;
            // group_selected = false;
        }
        printf("User successfully unregistered\n");
    } else if (strcmp(reply.data, "RUN NOK\n") == 0) {
        printf("User unregistration failed\n");
    } else {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool login(sockets_t sockets, char *args) {
    if (logged_in) {
        printf("You are already logged in\n");
        return false;
    }

    char id[6], password[9];
    if (sscanf(args, "%5s%8s", id, password) < 0)
        return true;

    buffer_t message;
    create_buffer(message, 20);
    int n = sprintf(message.data, "LOG %s %s\n", id, password);
    if (n < 0)
        return true;

    strncpy(uid, id, 5);
    strncpy(pass, password, 8);

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 9);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "RLO OK\n") == 0) {
        printf("You are now logged in\n");
        logged_in = true;
    } else if (strcmp(reply.data, "RLO NOK\n") == 0) {
        printf("Login failed\n");
        logged_in = false;
    } else {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool logout(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    buffer_t message;
    create_buffer(message, 20);
    int n = sprintf(message.data, "OUT %s %s\n", uid, pass);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 9);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "ROU OK\n") == 0) {
        printf("You are now logged out\n");
        logged_in = false;
        // group_selected = false;
    } else if (strcmp(reply.data, "ROU NOK\n") == 0) {
        printf("Logout failed\n");
    } else {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool show_groups(char *reply, int n, int offset) {
    char *cursor = reply + offset;
    int showed_groups = 0;
    while (showed_groups < n && cursor[0] != '\n') {
        char gid[3], name[25], mid[5];
        int inc;
        if (sscanf(cursor, " %2s%24s%4s%n", gid, name, mid, &inc) < 0)
            return true;
        int name_size = strlen(name);
        if (!is_gid(gid) || !is_group_name(name) || !is_mid(mid) || cursor[0] != ' ' ||
            cursor[3] != ' ' || cursor[4 + name_size] != ' ') {
            errno = EPROTO;
            return true;
        }
        cursor += inc;
        printf("Group %s - \"%s\" (%s messages)\n", gid, name, mid);
        showed_groups++;
    }

    if (showed_groups != n || cursor[0] != '\n') {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool list_groups(sockets_t sockets) {
    buffer_t message;
    message.data = "GLS\n";
    message.size = 4;

    buffer_t reply;
    create_buffer(reply, 3275);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strncmp(reply.data, "RGL ", 4) == 0) {
        int n;
        int read_chars = 0;
        if (sscanf(reply.data + 4, "%2d%n", &n, &read_chars) < 0)
            return true;

        if (read_chars <= 2 && ((n != 0 && reply.data[4 + read_chars] == ' ') ||
                                (n == 0 && reply.data[4 + read_chars] == '\n'))) {
            if (n == 0)
                printf("No groups to list\n");
            else
                return show_groups(reply.data, n, 4 + read_chars);
        } else {
            errno = EPROTO;
            return true;
        }
    } else {
        errno = EPROTO;
        return true;
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
    if (sscanf(args, "%2d%24s", &gid, name) < 0)
        return true;

    buffer_t message;
    create_buffer(message, 39);
    int n = sprintf(message.data, "GSR %s %02d %s\n", uid, gid, name);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 13);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "RGS OK\n") == 0)
        printf("You are now subscribed\n");
    else if (strcmp(reply.data, "RGS E_USR\n") == 0)
        printf("Invalid user id\n");
    else if (strcmp(reply.data, "RGS E_GRP\n") == 0)
        printf("Invalid group id\n");
    else if (strcmp(reply.data, "RGS E_GNAME\n") == 0)
        printf("Invalid group name\n");
    else if (strcmp(reply.data, "RGS E_FULL\n") == 0)
        printf("Group could not be created\n");
    else if (strcmp(reply.data, "RGS NOK\n") == 0)
        printf("Subscription failed\n");
    else if (strncmp(reply.data, "RGS NEW ", 8) == 0) {
        int new_gid;
        if (sscanf(reply.data + 8, "%2d\n", &new_gid) < 0)
            return true;
        printf("New group created and subscribed: %02d - \"%s\"\n", new_gid, name);
    } else {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool unsubscribe_group(sockets_t sockets, char *args) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    int gid;
    if (sscanf(args, "%2d", &gid) < 0)
        return true;

    buffer_t message;
    create_buffer(message, 14);
    int n = sprintf(message.data, "GUR %s %02d\n", uid, gid);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 11);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "RGU OK\n") == 0)
        printf("Group successfully unsubscribed\n");
    else if (strcmp(reply.data, "RGU E_USR\n") == 0)
        printf("Invalid user id\n");
    else if (strcmp(reply.data, "RGU E_GRP\n") == 0)
        printf("Invalid group id\n");
    else if (strcmp(reply.data, "RGU NOK\n") == 0)
        printf("Unsubscription failed\n");
    else {
        errno = EPROTO;
        return true;
    }
    return false;
}

bool list_user_groups(sockets_t sockets) {
    if (!logged_in) {
        printf("You are not logged in\n");
        return false;
    }

    buffer_t message;
    create_buffer(message, 11);
    int n = sprintf(message.data, "GLM %s\n", uid);
    if (n < 0)
        return true;

    message.size = n;
    buffer_t reply;
    create_buffer(reply, 3275);
    if (get_udp_reply(sockets.udp_fd, message, reply, sockets.udp_addr))
        return true;

    if (strcmp(reply.data, "RGM E_USR\n") == 0) {
        printf("Invalid user ID\n");
    } else if (strncmp(reply.data, "RGM ", 4) == 0) {
        int n;
        int read_chars = 0;
        if (sscanf(reply.data + 4, "%2d%n", &n, &read_chars) < 0)
            return true;

        if ((n != 0 && reply.data[4 + read_chars] == ' ') ||
            (n == 0 && reply.data[4 + read_chars] == '\n')) {
            if (n == 0)
                printf("No groups to list\n");
            else
                return show_groups(reply.data, n, 4 + read_chars);
        } else {
            errno = EPROTO;
            return true;
        }
    } else {
        errno = EPROTO;
        return true;
    }

    return false;
}

bool select_group(char *args) {
    // if (!logged_in) {
    //     printf("You are not logged in\n");
    //     return false;
    // }

    if (sscanf(args, "%2s", active_group) < 0)
        return true;
    group_selected = true;
    printf("Group %s - \"%s\" is now the active group\n", active_group);

    return false;
}

bool show_gid() {
    // if (!logged_in)
    //     printf("You are not logged in\n");
    // else {
    if (group_selected)
        printf("%s\n", active_group);
    else
        printf("You don't have a group selected\n");
    // }

    return false;
}

bool show_group_subscribers(int fd, buffer_t buffer, int bytes_read) {
    int offset = 7;
    int offset_inc;
    char group_name[25];
    char user_id[6];

    if (sscanf(buffer.data + offset, "%24s%n", group_name, &offset_inc) < 0)
        return true;

    printf("%s\n", group_name);

    offset += offset_inc;
    if (buffer.data[offset] == '\n') {
        printf("%s has no subscribers\n", group_name);
        return false;
    } else if (buffer.data[offset] != ' ') {
        errno = EPROTO;
        return true;
    }
    offset += 1;

    bool followed_by_space;
    while (buffer.data[offset] != '\n') {
        followed_by_space = false;
        if (sscanf(buffer.data + offset, "%5s%n", user_id, &offset_inc) < 0)
            return true;

        // Check if the buffer ended with an incomplete user id
        if (offset + offset_inc == bytes_read) {
            bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
            if (bytes_read < 0)
                return true;
            bytes_read += offset_inc;
            offset = 0;
        } else {
            if (!is_uid(user_id)) {
                errno = EPROTO;
                return true;
            }
            offset += offset_inc;
            followed_by_space = true;
            printf("%s\n", user_id);
        }

        if (followed_by_space) {
            if (buffer.data[offset] == '\n') {
                break;
            } else if (buffer.data[offset] != ' ') {
                errno = EPROTO;
                return true;
            }
            followed_by_space = false;
            offset += 1;
        }

        // Check if all of the buffer has been read
        if (offset == bytes_read) {
            bytes_read = receive_tcp(fd, buffer);
            if (bytes_read < 0)
                return true;
            offset = 0;
        }
    }

    return false;
}

bool list_group_users(sockets_t sockets) {
    // if (!logged_in) {
    //     printf("You are not logged in\n");
    //     return false;
    // } else 
    if (!group_selected) {
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
    int n = sprintf(message.data, "ULS %s\n", active_group);
    if (n < 0) {
        close(fd);
        return true;
    }
    message.size = n;
    if (send_tcp(fd, message)) {
        close(fd);
        return true;
    }

    int bytes_read = receive_tcp(fd, buffer);
    if (bytes_read < 0) {
        close(fd);
        return true;
    }

    if (strncmp(buffer.data, "RUL OK ", 7) == 0) {
        if (show_group_subscribers(fd, buffer, bytes_read)) {
            close(fd);
            return true;
        }
    } else if (strcmp(buffer.data, "RUL NOK\n") == 0) {
        printf("Failed to list subscribed users\n");
    } else {
        close(fd);
        errno = EPROTO;
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

        int n = sprintf(buffer.data, "PST %s %s %d %s", uid, active_group, text_size, text);
        if (n < 0) {
            close(fd);
            return true;
        }

        buffer_t message;
        message.data = buffer.data;
        message.size = n;

        if (send_tcp(fd, message)) {
            close(fd);
            return true;
        }

        if (args_count == 2) {
            struct stat st;
            if (stat(name, &st) != 0) {
                close(fd);
                return true;
            }
            size_t file_size = st.st_size;

            if (file_size >= 10000000000) {
                close(fd);
                printf("File is too large.\n");
                return false;
            }

            int n = sprintf(buffer.data, " %s %ld ", name, file_size);
            if (n < 0) {
                close(fd);
                return true;
            }
            message.size = n;

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

        if (strcmp(buffer.data, "RPT NOK\n") == 0) {
            printf("Failed to post message\n");

        } else if (strncmp(buffer.data, "RPT ", 4) == 0) {
            char status[5];
            int read_chars = 0;
            if (sscanf(buffer.data + 4, "%4s\n%n", status, &read_chars) < 0)
                return true;
            if (read_chars == 5 && is_mid(status) && buffer.data[8] == '\n')
                printf("Posted message number %s to group %s - \"(group_name)\"\n", status,
                       active_group);
            else {
                errno = EPROTO;
                return true;
            }
        } else {
            errno = EPROTO;
            return true;
        }
    }

    return false;
}

bool retrieve_messages(int fd, buffer_t buffer, ssize_t bytes_read, int message_count) {
    char mid[5], user_id[6], text[241], file_name[25];
    int offset = 9, offset_inc, text_size, messages_read = 0, args_count;
    size_t file_size;
    FILE *file;

    printf("%d message(s) retrieved:\n", message_count);

    enum { MID, UID, TSIZE, TEXT, FILE_CHECK, FNAME, FSIZE, FDATA } current_state;
    current_state = MID;

    while (buffer.data[offset] != '\n' && messages_read < message_count) {
        bool followed_by_space = false;
        switch (current_state) {
        case MID:
            if (sscanf(buffer.data + offset, "%4s%n", mid, &offset_inc) < 0)
                return true;
            if (offset + offset_inc == bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                bytes_read += offset_inc;
                offset = 0;
            } else {
                if (!is_mid(mid)) {
                    errno = EPROTO;
                    return true;
                }
                current_state = UID;
                followed_by_space = true;
                offset += offset_inc;
            }
            break;

        case UID:
            if (sscanf(buffer.data + offset, "%5s%n", user_id, &offset_inc) < 0)
                return true;
            if (offset + offset_inc == bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                bytes_read += offset_inc;
                offset = 0;
            } else {
                if (!is_uid(user_id)) {
                    errno = EPROTO;
                    return true;
                }
                current_state = TSIZE;
                followed_by_space = true;
                offset += offset_inc;
            }
            break;

        case TSIZE:
            args_count = sscanf(buffer.data + offset, "%3d%n", &text_size, &offset_inc);
            if (args_count < 0)
                return true;
            if (offset + offset_inc == bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                bytes_read += offset_inc;
                offset = 0;
            } else {
                if (args_count == 0 || text_size > 240) {
                    errno = EPROTO;
                    return true;
                }
                current_state = TEXT;
                followed_by_space = true;
                offset += offset_inc;
            }
            break;

        case TEXT:
            text[text_size] = '\0';
            char *cursor = text;

            while (text_size > 0) {
                size_t bytes = bytes_read - offset;
                if (text_size < bytes)
                    bytes = text_size;

                memcpy(cursor, buffer.data + offset, bytes);

                // Move cursor and offset
                cursor += bytes;
                text_size -= bytes;
                offset += bytes;

                if (offset == bytes_read) {
                    bytes_read = receive_tcp(fd, buffer);
                    if (bytes_read < 0)
                        return true;
                    offset = 0;
                }
            }
            printf("%s - \"%s\";", mid, text);
            if (messages_read == message_count - 1 && buffer.data[offset] == '\n') {
                messages_read++;
                printf("\n");
                return false;
            }
            current_state = FILE_CHECK;
            followed_by_space = true;
            break;

        case FILE_CHECK:
            if (buffer.data[offset] == '/') {
                if (offset + 1 == bytes_read) {
                    bytes_read = shift_buffer(fd, buffer, offset, 1);
                    if (bytes_read < 0)
                        return true;
                    bytes_read++;
                    offset = 0;
                } else {
                    current_state = FNAME;
                    followed_by_space = true;
                    offset++;
                }
            } else {
                printf("\n");
                current_state = MID;
                followed_by_space = false;
                messages_read++;
            }
            break;

        case FNAME:
            if (sscanf(buffer.data + offset, "%24s%n", file_name, &offset_inc) < 0)
                return true;
            if (offset + offset_inc == bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                bytes_read += offset_inc;
                offset = 0;
            } else {
                if (!is_file_name(file_name)) {
                    errno = EPROTO;
                    return true;
                }
                current_state = FSIZE;
                followed_by_space = true;
                offset += offset_inc;
            }
            break;

        case FSIZE:
            args_count = sscanf(buffer.data + offset, "%10lu%n", &file_size, &offset_inc);
            if (args_count < 0)
                return true;
            if (offset + offset_inc == bytes_read) {
                bytes_read = shift_buffer(fd, buffer, offset, offset_inc);
                if (bytes_read < 0)
                    return true;
                bytes_read += offset_inc;
                offset = 0;
            } else {
                if (args_count == 0) {
                    errno = EPROTO;
                    return true;
                }
                current_state = FDATA;
                followed_by_space = true;
                offset += offset_inc;
            }
            break;

        case FDATA:
            file = fopen(file_name, "wb");
            if (file == NULL)
                return true;

            // Write file
            while (file_size > 0) {
                size_t bytes = bytes_read - offset;
                if (file_size < bytes)
                    bytes = file_size;
                ssize_t bytes_written = fwrite(buffer.data + offset, 1, bytes, file);
                if (bytes_written == 0)
                    return true;
                file_size -= bytes_written;
                offset += bytes_written;

                if (offset == bytes_read) {
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
            followed_by_space = true;
            messages_read++;
            break;

        default:
            break;
        }

        if (buffer.data[offset] == '\n')
            break;

        if (followed_by_space) {
            if (buffer.data[offset] != ' ') {
                errno = EPROTO;
                return true;
            }
            offset += 1;
        }
        if (offset == bytes_read) {
            bytes_read = receive_tcp(fd, buffer);
            if (bytes_read < 0)
                return true;
            offset = 0;
        }
    }
    if (messages_read != message_count || buffer.data[offset] != '\n') {
        errno = EPROTO;
        return true;
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
    create_buffer(buffer, 1025); // min 25

    int mid;
    if (sscanf(args, "%4d", &mid) < 0) {
        close(fd);
        return true;
    }
    int n = sprintf(buffer.data, "RTV %s %s %04d\n", uid, active_group, mid);
    if (n < 0) {
        close(fd);
        return true;
    }

    buffer_t message;
    message.data = buffer.data;
    message.size = n;

    if (send_tcp(fd, message)) {
        close(fd);
        return true;
    }

    int bytes_read = receive_tcp(fd, buffer);
    if (bytes_read < 0) {
        close(fd);
        return true;
    }

    if (strncmp(buffer.data, "RRT OK ", 7) == 0) {
        int message_count;
        if (sscanf(buffer.data + 7, "%2d", &message_count) < 0) {
            close(fd);
            return true;
        }

        if (retrieve_messages(fd, buffer, bytes_read, message_count)) {
            close(fd);
            return true;
        }
    } else if (strcmp(buffer.data, "RRT EOF\n") == 0) {
        printf("No messages to retrieve\n");
    } else if (strcmp(buffer.data, "RRT NOK\n") == 0) {
        printf("Failed to retrieve messages\n");
    } else {
        close(fd);
        errno = EPROTO;
        return true;
    }

    if (close(fd) == -1)
        return true;
    return false;
}
