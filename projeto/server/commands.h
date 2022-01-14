#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>

/* List of groups */
typedef struct {
    int len;
    int mids[99];
    char names[99][25];
} grouplist_t;

/* List of subscribed groups */
typedef struct {
    int len;
    bool subscribed[99];
    int mids[99];
    char names[99][25];
} subscribedgroups_t;

/* Possible result when attempting to subscribe a group */
typedef struct {
    enum { SUBS_OK, SUBS_NEW, SUBS_EUSR, SUBS_EGRP, SUBS_EGNAME, SUBS_EFULL } status;
    int gid;
} subscribe_t;

/* Possible result when attempting to unsubscribe a group */
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
bool check_if_logged_in(const char *uid, bool *success);
bool check_if_subscribed(const char *gid, const char *uid, bool *result);

typedef struct {
    char message_dirname[19];
    int mid;
    bool has_file;
} message_t;

typedef struct {
    int mid[20];
    bool has_file[20];
    char file_names[20][25];
} messages_t;

bool create_message(const char *gid, const char *author, const char *text, message_t *data,
                    bool *failed);
bool is_message_complete(const char *dir_name, bool *is_complete);
bool count_complete_msgs(const char *dir_name, int first_mid, int *last_mid);

#endif
