#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../utils/sockets.h"
#include "../utils/validate.h"
#include "commands.h"
#include "requests.h"

bool register_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                      socklen_t addrlen) {
    char uid[6] = {0};
    char pass[9] = {0};

    // REG 95568 password\n
    int args_count = sscanf(request.data + 4, "%5s%8s", uid, pass);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_nok = {.data = "RRG NOK\n", .size = 8};
    buffer_t res_dup = {.data = "RRG DUP\n", .size = 8};
    buffer_t res_ok = {.data = "RRG OK\n", .size = 7};

    bool valid_uid = request.data[9] == ' ' && is_uid(uid);
    bool valid_password = request.data[18] == '\n' && is_password(pass);

    if (args_count < 2 || !valid_uid || !valid_password) {
        return send_udp(fd, res_nok, addr, addrlen) <= 0;
    }

    bool duplicate = false;
    bool error = register_user(uid, pass, &duplicate);
    if (!error && !duplicate) {
        if (args.verbose)
            printf("UID=%s: new user\n", uid);
        return send_udp(fd, res_ok, addr, addrlen) <= 0;
    } else if (!error && duplicate) {
        if (args.verbose)
            printf("UID=%s: duplicated user\n", uid);
        return send_udp(fd, res_dup, addr, addrlen) <= 0;
    }

    if (args.verbose)
        printf("UID=%s: failed to register user\n", uid);
    return (send_udp(fd, res_nok, addr, addrlen) <= 0) || error;
}

bool unregister_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                        socklen_t addrlen) {
    char uid[6] = {0};
    char pass[9] = {0};

    // UNR 95568 password\n
    int args_count = sscanf(request.data + 4, "%5s%8s", uid, pass);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_nok = {.data = "RUN NOK\n", .size = 8};
    buffer_t res_ok = {.data = "RUN OK\n", .size = 7};

    bool valid_uid = request.data[9] == ' ' && is_uid(uid);
    bool valid_password = request.data[18] == '\n' && is_password(pass);

    if (args_count < 2 || !valid_uid || !valid_password) {
        return send_udp(fd, res_nok, addr, addrlen) <= 0;
    }

    bool failed = false;
    bool error = unregister_user(uid, pass, &failed);
    if (!error && !failed) {
        if (args.verbose)
            printf("UID=%s: user deleted\n", uid);
        return send_udp(fd, res_ok, addr, addrlen) <= 0;
    }

    if (args.verbose)
        printf("UID=%s: failed to delete user\n", uid);
    return (send_udp(fd, res_nok, addr, addrlen) <= 0) || error;
}

bool login_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                   socklen_t addrlen) {
    char uid[6] = {0};
    char pass[9] = {0};

    // LOG 95568 password\n
    int args_count = sscanf(request.data + 4, "%5s%8s", uid, pass);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_nok = {.data = "RLO NOK\n", .size = 8};
    buffer_t res_ok = {.data = "RLO OK\n", .size = 7};

    bool valid_uid = request.data[9] == ' ' && is_uid(uid);
    bool valid_password = request.data[18] == '\n' && is_password(pass);

    if (args_count < 2 || !valid_uid || !valid_password) {
        return send_udp(fd, res_nok, addr, addrlen) <= 0;
    }

    bool failed = false;
    bool error = user_login(uid, pass, &failed);
    if (!error && !failed) {
        if (args.verbose)
            printf("UID=%s: login ok\n", uid);
        return send_udp(fd, res_ok, addr, addrlen) <= 0;
    }

    if (args.verbose && failed)
        printf("UID=%s: login not ok\n", uid);

    return (send_udp(fd, res_nok, addr, addrlen) <= 0) || error;
}

bool logout_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                    socklen_t addrlen) {
    char uid[6] = {0};
    char pass[9] = {0};

    // OUT 95568 password\n
    int args_count = sscanf(request.data + 4, "%5s%8s", uid, pass);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_nok = {.data = "ROU NOK\n", .size = 8};
    buffer_t res_ok = {.data = "ROU OK\n", .size = 7};

    bool valid_uid = request.data[9] == ' ' && is_uid(uid);
    bool valid_password = request.data[18] == '\n' && is_password(pass);

    if (args_count < 2 || !valid_uid || !valid_password) {
        return send_udp(fd, res_nok, addr, addrlen) <= 0;
    }

    bool failed = false;
    bool error = user_logout(uid, pass, &failed);
    if (!error && !failed) {
        if (args.verbose)
            printf("UID=%s: logout ok\n", uid);
        return send_udp(fd, res_ok, addr, addrlen) <= 0;
    }

    if (args.verbose && failed)
        printf("UID=%s: logout not ok\n", uid);

    return (send_udp(fd, res_nok, addr, addrlen) <= 0) || error;
}

bool subscribe_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                       socklen_t addrlen) {
    char uid[6] = {0};
    char gid[3] = {0};
    char gname[25] = {0};

    // GSR 12345 12 gname\n
    int args_count = sscanf(request.data + 4, "%5s%2s%24s", uid, gid, gname);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_nok = {.data = "RGS NOK\n", .size = 8};
    buffer_t res_ok = {.data = "RGS OK\n", .size = 7};
    buffer_t res_egrp = {.data = "RGS E_GRP\n", .size = 10};
    buffer_t res_eusr = {.data = "RGS E_USR\n", .size = 10};
    buffer_t res_efull = {.data = "RGS E_FULL\n", .size = 11};
    buffer_t res_gname = {.data = "RGS E_GNAME\n", .size = 12};

    buffer_t res_new;
    create_buffer(res_new, 12);
    res_new.size = 11;

    bool valid_uid = request.data[9] == ' ' && is_uid(uid);
    bool valid_gid = request.data[12] == ' ' && is_gid(gid);
    bool valid_gname = is_group_name(gname) && request.data[13 + strlen(gname)] == '\n';

    if (args_count < 3 || !valid_uid || !valid_gid || !valid_gname) {
        return send_udp(fd, res_nok, addr, addrlen) <= 0;
    }

    subscribe_t res;
    bool error = user_subscribe(uid, gid, gname, &res);
    if (!error) {
        if (res.status == SUBS_OK) {
            if (args.verbose)
                printf("UID=%s: subscribed group: %s - \"%s\"\n", uid, gid, gname);
            return send_udp(fd, res_ok, addr, addrlen) <= 0;
        } else if (res.status == SUBS_EGRP) {
            if (args.verbose)
                printf("UID=%s: subscribed failed - invalid group\n", uid);
            return send_udp(fd, res_egrp, addr, addrlen) <= 0;
        } else if (res.status == SUBS_EUSR) {
            if (args.verbose)
                printf("UID=%s: subscribed failed - invalid user\n", uid);
            return send_udp(fd, res_eusr, addr, addrlen) <= 0;
        } else if (res.status == SUBS_EFULL) {
            if (args.verbose)
                printf("UID=%s: subscribed failed - full\n", uid);
            return send_udp(fd, res_efull, addr, addrlen) <= 0;
        } else if (res.status == SUBS_EGNAME) {
            if (args.verbose)
                printf("UID=%s: subscribed failed - invalid group name\n", uid);
            return send_udp(fd, res_gname, addr, addrlen) <= 0;
        } else if (res.status == SUBS_NEW) {
            sprintf(res_new.data, "RGS NEW %02d\n", res.gid);
            if (args.verbose)
                printf("UID=%s: new group: %02d - \"%s\"\n", uid, res.gid, gname);
            return send_udp(fd, res_new, addr, addrlen) <= 0;
        }
    }

    if (args.verbose)
        printf("UID=%s: failed to subscribe\n", uid);
    return (send_udp(fd, res_nok, addr, addrlen) <= 0) || error;
}

bool unsubscribe_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                         socklen_t addrlen) {
    char uid[6] = {0};
    char gid[3] = {0};

    // GSR 12345 12 gname\n
    int args_count = sscanf(request.data + 4, "%5s%2s", uid, gid);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_nok = {.data = "RGU NOK\n", .size = 8};
    buffer_t res_ok = {.data = "RGU OK\n", .size = 7};
    buffer_t res_egrp = {.data = "RGU E_GRP\n", .size = 10};
    buffer_t res_eusr = {.data = "RGU E_USR\n", .size = 10};

    bool valid_uid = request.data[9] == ' ' && is_uid(uid);
    bool valid_gid = request.data[12] == '\n' && is_gid(gid);

    if (args_count < 2 || !valid_uid || !valid_gid) {
        return send_udp(fd, res_nok, addr, addrlen) <= 0;
    }

    unsubscribe_t res;
    bool error = user_unsubscribe(uid, gid, &res, false);

    if (!error) {
        if (res == UNS_OK) {
            if (args.verbose)
                printf("UID=%s: unsubscribed group %s\n", uid, gid);
            return send_udp(fd, res_ok, addr, addrlen) <= 0;
        } else if (res == UNS_EGRP) {
            if (args.verbose)
                printf("UID=%s: unsubscribed failed - invalid group\n", uid);
            return send_udp(fd, res_egrp, addr, addrlen) <= 0;
        } else if (res == UNS_EUSR) {
            if (args.verbose)
                printf("UID=%s: unsubscribed failed - invalid user\n", uid);
            return send_udp(fd, res_eusr, addr, addrlen) <= 0;
        }
    }

    if (args.verbose)
        printf("UID=%s: failed to unsubscribe\n", uid);
    return (send_udp(fd, res_nok, addr, addrlen) <= 0) || error;
}

bool list_groups_request(int fd, args_t args, const struct sockaddr *addr, socklen_t addrlen) {

    // Define buffers for possible responses
    buffer_t res_empty = {.data = "RGL 0\n", .size = 6};
    buffer_t res;
    create_buffer(res, 3275);

    grouplist_t list;
    bool error = list_groups(&list);

    if (list.len == 0) {
        return send_udp(fd, res_empty, addr, addrlen) <= 0;
    }

    int n = sprintf(res.data, "RGL %d", list.len);
    if (n < 0)
        return true;

    int offset = n;

    for (int i = 0; i < list.len; i++) {
        n = sprintf(res.data + offset, " %02d %s %04d", i + 1, list.names[i], list.mids[i]);
        if (n < 0)
            return true;

        offset += n;
    }

    n = sprintf(res.data + offset, "\n");
    if (n < 0)
        return true;

    offset += n;
    res.size = offset;

    if (!error) {
        if (args.verbose)
            printf("listed groups\n");
        return send_udp(fd, res, addr, addrlen) <= 0;
    }

    return true;
}

bool list_subscribed_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                             socklen_t addrlen) {
    char uid[6] = {0};

    // REG 95568 password\n
    int args_count = sscanf(request.data + 4, "%5s", uid);
    if (args_count < 0)
        return true;

    // Define buffers for possible responses
    buffer_t res_empty = {.data = "RGM 0\n", .size = 6};
    buffer_t res_eusr = {.data = "RGM E_USR\n", .size = 10};
    buffer_t res;
    create_buffer(res, 3275);

    bool valid_uid = request.data[9] == '\n' && is_uid(uid);
    if (args_count < 1 || !valid_uid) {
        return send_udp(fd, res_eusr, addr, addrlen) <= 0;
    }

    subscribedgroups_t list;
    for (size_t i = 0; i < 99; i++) {
        list.subscribed[i] = false;
    }

    bool failed = false;
    bool error = subscribed_groups(uid, &list, &failed);

    if (failed) {
        return send_udp(fd, res_eusr, addr, addrlen) <= 0;
    } else if (list.len == 0) {
        return send_udp(fd, res_empty, addr, addrlen) <= 0;
    }

    int n = sprintf(res.data, "RGM %d", list.len);
    if (n < 0)
        return true;

    int offset = n;

    int i = 0;
    int gid = 0;
    while (i < list.len) {
        gid++;
        if (!list.subscribed[gid - 1])
            continue;
        n = sprintf(res.data + offset, " %02d %s %04d", gid, list.names[gid - 1],
                    list.mids[gid - 1]);
        if (n < 0)
            return true;

        offset += n;
        i++;
    }

    n = sprintf(res.data + offset, "\n");
    if (n < 0)
        return true;

    offset += n;
    res.size = offset;

    if (!error) {
        if (args.verbose)
            printf("UID=%s: listed subscribed groups\n", uid);
        return send_udp(fd, res, addr, addrlen) <= 0;
    }

    return true;
}

bool subscribed_users(int fd, args_t args) {
    buffer_t res_nok = {.data = "RUL NOK\n", .size = 8};
    buffer_t request;
    create_buffer(request, 4);
    if (receive_tcp(fd, request) <= 0)
        return true;

    char gid[3] = {0};
    int args_count = sscanf(request.data, "%2s", gid);
    if (args_count < 0)
        return true;

    if (!is_gid(gid) || request.data[2] != '\n')
        return send_tcp(fd, res_nok);

    int group_count;
    if (count_groups("GROUPS", &group_count))
        return true;

    int gid_num = atoi(gid);
    if (gid_num == 0 || gid_num > group_count)
        return send_tcp(fd, res_nok);

    char group_dir[10];
    char group_name_file[30];
    sprintf(group_dir, "GROUPS/%s", gid);
    sprintf(group_name_file, "%s/%s_name.txt", group_dir, gid);

    char group_name[25];

    FILE *gname_file = fopen(group_name_file, "r");
    if (gname_file == NULL)
        return true;

    if (fscanf(gname_file, "%24s", group_name) < 0)
        return true;

    if (fclose(gname_file) == EOF)
        return true;

    DIR *dir = opendir(group_dir);
    if (dir == NULL)
        return true;

    buffer_t res = {.data = "RUL OK ", .size = 7};
    if (send_tcp(fd, res))
        return true;
    res.data = group_name;
    res.size = strlen(group_name);
    if (send_tcp(fd, res))
        return true;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char uid[7];
        uid[0] = ' ';
        if (sscanf(entry->d_name, "%5s", uid + 1) <= 0)
            return true;
        if (!is_uid(uid + 1))
            continue;

        res.data = uid;
        res.size = 6;
        if (send_tcp(fd, res))
            return true;
    }

    res.data = "\n";
    res.size = 1;
    if (send_tcp(fd, res))
        return true;

    if (closedir(dir) == -1)
        return true;

    return false;
}

bool post_request(int fd, args_t args) {
    buffer_t request;
    create_buffer(request, 300);
    buffer_t res_nok = {.data = "RPT NOK\n", .size = 8};

    ssize_t bytes_read = receive_tcp(fd, request);
    if (bytes_read <= 0)
        return true;

    char uid[6] = {0};
    char gid[3] = {0};
    char text_size_str[4] = {0};
    int offset;
    int args_count = sscanf(request.data, "%5s%2s%3s%n", uid, gid, text_size_str, &offset);
    if (args_count < 0)
        return true;

    int text_size = atoi(text_size_str);
    size_t text_size_len = strlen(text_size_str);

    bool valid_uid = is_uid(uid) && request.data[5] == ' ';
    bool valid_gid = is_gid(gid) && request.data[8] == ' ';
    bool valid_text_size =
        text_size > 0 && text_size <= 240 && request.data[9 + text_size_len] == ' ';

    if (!valid_uid || !valid_gid || !valid_text_size || args_count < 3)
        return send_tcp(fd, res_nok);
    offset++;

    bool logged_in;
    check_if_logged_in(uid, &logged_in);
    if (!logged_in)
        return send_tcp(fd, res_nok);

    int group_count;
    if (count_groups("GROUPS", &group_count))
        return true;

    int gid_num = atoi(gid);
    if (gid_num == 0 || gid_num > group_count)
        return send_tcp(fd, res_nok);

    bool subscribed;
    check_if_subscribed(gid, uid, &subscribed);
    if (!subscribed)
        return send_tcp(fd, res_nok);

    char text[241] = {0};
    text[text_size] = '\0';
    memcpy(text, request.data + offset, text_size);
    offset += text_size;

    bool has_file = request.data[offset] == ' ';

    message_t data;
    bool failed = false;
    if (create_message(gid, uid, text, &data, &failed))
        return true;

    if (failed)
        return send_tcp(fd, res_nok);

    char rep[10] = {0};
    sprintf(rep, "RPT %04d\n", data.mid);
    buffer_t res = {.data = rep, .size = 9};

    if (!has_file) {
        if (args.verbose)
            printf("UID=%s: post group %s:\n           \"%s\"\n", uid, gid, text);
        return send_tcp(fd, res);
    }

    // Save file
    offset++;

    int offset_inc;
    char file_name[25];
    char file_size_str[11];
    args_count = sscanf(request.data + offset, "%24s%10s%n", file_name, file_size_str, &offset_inc);
    if (args_count < 0)
        return true;

    long file_size = atol(file_size_str);
    size_t file_size_len = strlen(file_size_str);

    bool valid_file_name =
        is_file_name(file_name) && (request.data + offset)[strlen(file_name)] == ' ';
    bool valid_file_size = file_size > 0 && file_size < 10000000000 &&
                           (request.data + offset)[strlen(file_name) + file_size_len + 1] == ' ';
    // Fname Fsize data
    if (!valid_file_name || !valid_file_size || args_count < 2)
        return send_tcp(fd, res_nok);
    offset += offset_inc + 1;
    char file_path[45];
    sprintf(file_path, "%s/%s", data.message_dirname, file_name);

    FILE *posted_file = fopen(file_path, "wb");
    if (posted_file == NULL)
        return true;

    while (file_size > 0) {
        size_t bytes = bytes_read - offset;
        if (file_size < bytes)
            bytes = file_size;
        ssize_t bytes_written = fwrite(request.data + offset, 1, bytes, posted_file);
        if (bytes_written == 0)
            return true;
        file_size -= bytes_written;
        offset += bytes_written;

        if (offset == bytes_read) {
            bytes_read = receive_tcp(fd, request);
            if (bytes_read < 0) {
                fclose(posted_file);
                return true;
            }
            offset = 0;
        }
    }

    fclose(posted_file);

    if (args.verbose)
        printf("UID=%s: post group %s:\n           \"%s\" %s\n", uid, gid, text, file_name);

    return send_tcp(fd, res);
}

bool retrieve_request(int fd, args_t args) {
    buffer_t request;
    create_buffer(request, 15);
    buffer_t res_nok = {.data = "RRT NOK\n", .size = 8};

    if (receive_tcp(fd, request) <= 0)
        return true;

    char uid[6] = {0};
    char gid[3] = {0};
    char mid[5] = {0};
    int args_count = sscanf(request.data, "%5s%2s%4s", uid, gid, mid);
    if (args_count < 0)
        return true;

    bool valid_uid = is_uid(uid) && request.data[5] == ' ';
    bool valid_gid = is_gid(gid) && request.data[8] == ' ';
    bool valid_mid = is_mid(mid) && request.data[13] == '\n';

    if (!valid_uid || !valid_gid || !valid_mid || args_count < 3)
        return send_tcp(fd, res_nok);

    bool logged_in;
    check_if_logged_in(uid, &logged_in);
    if (!logged_in)
        return send_tcp(fd, res_nok);

    int group_count;
    if (count_groups("GROUPS", &group_count))
        return true;

    int gid_num = atoi(gid);
    if (gid_num == 0 || gid_num > group_count)
        return send_tcp(fd, res_nok);

    int current_mid = atoi(mid);
    if (current_mid == 0)
        return send_tcp(fd, res_nok);

    bool subscribed;
    check_if_subscribed(gid, uid, &subscribed);
    if (!subscribed)
        return send_tcp(fd, res_nok);

    char messages_dir[14];
    sprintf(messages_dir, "GROUPS/%s/MSG", gid);
    int message_count;
    if (count_complete_msgs(messages_dir, current_mid, &message_count))
        return true;

    // You can only retrieve up to 20 messages
    message_count = message_count <= 20 ? message_count : 20;
    buffer_t res_eof = {.data = "RRT EOF\n", .size = 8};

    if (message_count == 0)
        return send_tcp(fd, res_eof);

    buffer_t aux;
    create_buffer(aux, 128);

    int n = sprintf(aux.data, "RRT OK %d", message_count);
    if (n < 0)
        return true;
    aux.size = n;
    send_tcp(fd, aux);
    current_mid--;

    if (args.verbose)
        printf("UID=%s: retrieve group %s, message(s)\n", uid, gid);

    while (message_count > 0) {
        current_mid++;
        char message_dir_name[19];
        sprintf(message_dir_name, "%s/%04d", messages_dir, current_mid);
        bool complete = false;
        if (is_message_complete(message_dir_name, &complete))
            return true;
        else if (!complete)
            continue;
        
        message_count--;
        int n = sprintf(aux.data, " %04d ", current_mid);
        if (n < 0)
            return true;
        aux.size = n;
        send_tcp(fd, aux);

        char author_file_name[35];
        char text_file_name[31];
        sprintf(author_file_name, "%s/A U T H O R.txt", message_dir_name);
        sprintf(text_file_name, "%s/T E X T.txt", message_dir_name);

        if (send_file_tcp(fd, author_file_name, 5))
            return true;

        struct stat st;
        if (stat(text_file_name, &st) != 0)
            return true;

        n = sprintf(aux.data, " %lu ", st.st_size);
        if (n < 0)
            return true;
        aux.size = n;
        send_tcp(fd, aux);

        if (send_file_tcp(fd, text_file_name, st.st_size))
            return true;

        DIR *message_dir = opendir(message_dir_name);
        if (message_dir == NULL)
            return true;

        struct dirent *entry;
        while ((entry = readdir(message_dir)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;

            bool not_author = strcmp(entry->d_name, "A U T H O R.txt") != 0;
            bool not_text = strcmp(entry->d_name, "T E X T.txt") != 0;
            if (not_author && not_text) {
                char file_name[44];
                sprintf(file_name, "%s/%s", message_dir_name, entry->d_name);

                if (stat(file_name, &st) != 0)
                    return true;

                n = sprintf(aux.data, " / %s %lu ", entry->d_name, st.st_size);
                if (n < 0)
                    return true;
                aux.size = n;
                send_tcp(fd, aux);

                if (send_file_tcp(fd, file_name, st.st_size))
                    return true;
            }
        }
    }

    aux.data = "\n";
    aux.size = 1;
    if (send_tcp(fd, aux))
        return true;

    return false;
}
