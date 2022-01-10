#include <stdio.h>
#include <string.h>

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
    buffer_t res_gname = {.data = "RGS GNAME\n", .size = 7};

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
    bool error = user_unsubscribe(uid, gid, &res);

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
