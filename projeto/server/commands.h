#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>

typedef struct {
    int len;
    int mids[99];
    char names[99][25];
} grouplist_t;

typedef struct {
    int len;
    bool subscribed[99];
    int mids[99];
    char names[99][25];
} subscribedgroups_t;

typedef struct {
    enum { SUBS_OK, SUBS_NEW, SUBS_EUSR, SUBS_EGRP, SUBS_EGNAME, SUBS_EFULL } status;
    int gid;
} subscribe_t;

typedef enum { UNS_OK, UNS_EUSR, UNS_EGRP } unsubscribe_t;

bool register_user(const char *uid, const char *pass, bool *duplicate);
bool unregister_user(const char *uid, const char *pass, bool *failed);
bool user_login(const char *uid, const char *pass, bool *failed);
bool user_logout(const char *uid, const char *pass, bool *failed);
bool list_groups(grouplist_t *list);
bool subscribed_groups(const char *uid, subscribedgroups_t *list, bool *failed);
bool user_subscribe(const char *uid, const char *gid, const char *gname, subscribe_t *result);
bool user_unsubscribe(const char *uid, const char *gid, unsubscribe_t *result, bool unr);

bool count_groups(const char *dir_name, int *group_count);

#endif
