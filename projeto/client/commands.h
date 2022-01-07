#ifndef COMMANDS_H
#define COMMANDS_H

typedef struct {
    int udp_fd;
    struct addrinfo *udp_addr;
    struct addrinfo *tcp_addr;
} sockets_t;

bool show_uid();
bool register_user(sockets_t sockets, char *args);
bool unregister_user(sockets_t sockets, char *args);
bool login(sockets_t sockets, char *args);
bool logout(sockets_t sockets);
bool list_groups(sockets_t sockets);
bool subscribe_group(sockets_t sockets, char *args);
bool unsubscribe_group(sockets_t sockets, char *args);
bool list_user_groups(sockets_t sockets);
bool select_group(char *args);
bool show_gid();
bool list_group_users(sockets_t sockets);
bool post(sockets_t sockets, char *args);
bool retrieve(sockets_t sockets, char *args);

#endif /* COMMANDS_H */