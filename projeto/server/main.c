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

#include "../utils/sockets.h"
#include "../utils/validate.h"
#include "commands.h"

#define DEFAULT_PORT "58054"
#define MAX_MESSAGE 129
#define MAX_RESPONSE 3276

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

bool handle_udp_request(int fd, args_t args) {
    buffer_t request;
    create_buffer(request, 39);

    // Client address
    struct sockaddr_in addr;
    socklen_t addrlen;

    ssize_t n = receive_udp(fd, request, &addr, &addrlen);
    if (n <= 0)
        return true;

    if (strncmp(request.data, "REG ", 4) == 0)
        return register_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "UNR ", 4) == 0)
        return unregister_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "LOG ", 4) == 0)
        return login_request(fd, args, request, (struct sockaddr *)&addr, addrlen);
    else if (strncmp(request.data, "OUT ", 4) == 0)
        return logout_request(fd, args, request, (struct sockaddr *)&addr, addrlen);

    return false;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    int fd;
    ssize_t n;

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

    bool should_exit = false;

    while (!should_exit) {
        ready_sockets = current_sockets;
        if (select(FD_SETSIZE, &ready_sockets, NULL, NULL, NULL) < 0)
            exit(EXIT_FAILURE);

        if (FD_ISSET(fd, &ready_sockets)) {
            if (handle_udp_request(fd, args))
                should_exit = true;
        }
    }

    freeaddrinfo(res);
    close(fd);

    return 0;
}
