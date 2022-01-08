#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>

typedef struct {
    int len;
    int mids[99];
    char names[99][25];
} grouplist_t;

bool register_user(const char *uid, const char *pass, bool *duplicate);
bool unregister_user(const char *uid, const char *pass, bool *failed);
bool user_login(const char *uid, const char *pass, bool *failed);
bool user_logout(const char *uid, const char *pass, bool *failed);
bool list_groups(grouplist_t *list);

#endif
