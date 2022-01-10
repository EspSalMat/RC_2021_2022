#ifndef REQUESTS_H
#define REQUESTS_H

#include <stdbool.h>

typedef struct {
    char *port;
    bool verbose;
} args_t;

bool register_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                      socklen_t addrlen);
bool unregister_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                        socklen_t addrlen);
bool login_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                   socklen_t addrlen);
bool logout_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                    socklen_t addrlen);
bool subscribe_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                       socklen_t addrlen);
bool unsubscribe_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                         socklen_t addrlen);
bool list_groups_request(int fd, args_t args, const struct sockaddr *addr, socklen_t addrlen);
bool list_subscribed_request(int fd, args_t args, buffer_t request, const struct sockaddr *addr,
                             socklen_t addrlen);

// TCP Requests
bool subscribed_users(int fd, args_t args);

#endif /* REQUESTS_H */
