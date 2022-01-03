#ifndef COMMANDS_H
#define COMMANDS_H

#include "../common/common.h"

typedef enum { EXIT, LOCAL, UDP, TCP } command_type_t;

command_type_t show_uid();
command_type_t register_user(sockets_t sockets, char *args);
command_type_t unregister_user(sockets_t sockets, char *args);
command_type_t login(sockets_t sockets, char *args);
command_type_t logout(sockets_t sockets);
command_type_t list_groups(sockets_t sockets);
command_type_t subscribe_group(sockets_t sockets, char *args);
command_type_t unsubscribe_group(sockets_t sockets, char *args);
command_type_t list_user_groups(sockets_t sockets);
command_type_t select_group(char *args);
command_type_t show_gid();
command_type_t list_group_users(sockets_t sockets);
command_type_t post(sockets_t sockets, char *args);
command_type_t retrieve(sockets_t sockets, char *args);

#endif /* COMMANDS_H */