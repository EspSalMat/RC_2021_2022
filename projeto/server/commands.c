#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../utils/validate.h"
#include "commands.h"

bool check_password(const char *user_pass, const char *pass, bool *failed) {
    char realpass[9];

    FILE *pass_file = fopen(user_pass, "r");
    if (pass_file == NULL)
        return true;

    if (fscanf(pass_file, "%8s", realpass) < 0)
        return true;

    if (fclose(pass_file) == EOF)
        return true;

    if (strcmp(pass, realpass) != 0)
        *failed = true;

    return false;
}

bool register_user(const char *uid, const char *pass, bool *duplicate) {
    char user_dirname[20];
    char user_pass[34];
    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    bool failed = mkdir(user_dirname, 0700) == -1;
    if (failed && errno != EEXIST) {
        return true;
    } else if (failed && errno == EEXIST) {
        *duplicate = true;
        return false;
    }

    FILE *pass_file = fopen(user_pass, "w");
    if (pass_file == NULL)
        return true;

    if (fputs(pass, pass_file) == EOF)
        return true;
    if (fclose(pass_file) == EOF)
        return true;

    return false;
}

bool unsubscribe_all(const char *uid, const char *dir_name) {
    DIR *groups_dir = opendir(dir_name);
    if (groups_dir == NULL)
        return true;

    struct dirent *gid_dir;
    while ((gid_dir = readdir(groups_dir)) != NULL) {
        if (!is_gid(gid_dir->d_name))
            continue;
        unsubscribe_t result;
        if (user_unsubscribe(uid, gid_dir->d_name, &result, true))
            return true;
    }

    if (closedir(groups_dir) == -1)
        return true;

    return false;
}

bool unregister_user(const char *uid, const char *pass, bool *failed) {
    char user_dirname[20];
    char user_pass[34];
    char user_logged_in[35];

    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_logged_in, "%s/%s_login.txt", user_dirname, uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    struct stat st;
    if (stat(user_dirname, &st) != 0) {
        *failed = true;
        return errno != ENOENT;
    }

    if (check_password(user_pass, pass, failed))
        return true;
    else if (*failed)
        return false;

    if (unsubscribe_all(uid, "GROUPS"))
        return true;

    bool logged_out = unlink(user_logged_in) == 0 || errno == ENOENT;
    if (logged_out && unlink(user_pass) == 0 && rmdir(user_dirname) == 0)
        return false;

    return true;
}

bool user_login(const char *uid, const char *pass, bool *failed) {
    char user_dirname[20];
    char user_pass[34];
    char user_logged_in[35];

    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_logged_in, "%s/%s_login.txt", user_dirname, uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    struct stat st;
    if (stat(user_dirname, &st) != 0) {
        *failed = true;
        return errno != ENOENT;
    }

    if (check_password(user_pass, pass, failed))
        return true;
    else if (*failed)
        return false;

    FILE *file = fopen(user_logged_in, "w");
    if (file == NULL)
        return true;
    if (fclose(file) == EOF)
        return true;

    return false;
}

bool user_logout(const char *uid, const char *pass, bool *failed) {
    char user_dirname[20];
    char user_pass[34];
    char user_logged_in[35];

    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_logged_in, "%s/%s_login.txt", user_dirname, uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    struct stat st;
    if (stat(user_dirname, &st) != 0) {
        *failed = true;
        return errno != ENOENT;
    }

    if (check_password(user_pass, pass, failed))
        return true;
    else if (*failed)
        return false;

    if (stat(user_logged_in, &st) != 0) {
        *failed = true;
        return errno != ENOENT;
    }

    if (unlink(user_logged_in) == 0)
        return false;

    return true;
}

bool count_messages(const char *dir_name, int *message_count, int *lock_fd) {
    DIR *msg_dir = opendir(dir_name);
    if (msg_dir == NULL)
        return true;
    
    if (lock_fd != NULL) {
        *lock_fd = dirfd(msg_dir);
        flock(*lock_fd, LOCK_EX);
    }

    *message_count = 0;
    struct dirent *mid_dir;
    while ((mid_dir = readdir(msg_dir)) != NULL) {
        if (!is_mid(mid_dir->d_name))
            continue;
        (*message_count)++;
    }

    if (closedir(msg_dir) == -1) {
        if (lock_fd != NULL) 
            flock(*lock_fd, LOCK_UN);
        return true;
    }

    return false;
}

bool list_groups(grouplist_t *list) {
    list->len = 0;
    DIR *groups_dir = opendir("GROUPS");
    if (groups_dir == NULL)
        return true;

    struct dirent *gid_dir;

    while ((gid_dir = readdir(groups_dir)) != NULL) {
        // Continue if it's not a group id
        if (!is_gid(gid_dir->d_name))
            continue;

        int gid = atoi(gid_dir->d_name);

        char gid_name[30];
        sprintf(gid_name, "GROUPS/%s/%s_name.txt", gid_dir->d_name, gid_dir->d_name);

        FILE *group_name_file = fopen(gid_name, "r");
        if (group_name_file == NULL)
            return true;

        if (fscanf(group_name_file, "%24s", list->names[gid - 1]) < 0)
            return true;

        if (fclose(group_name_file) == EOF)
            return true;

        char msg_name[16];
        sprintf(msg_name, "GROUPS/%s/MSG", gid_dir->d_name);

        int message_count;
        if (count_messages(msg_name, &message_count, NULL))
            return true;
        list->mids[gid - 1] = message_count;

        list->len++;
        if (list->len == 99)
            break;
    }

    if (closedir(groups_dir) == -1)
        return true;

    return false;
}

bool count_groups(const char *dir_name, int *group_count) {
    DIR *groups_dir = opendir(dir_name);
    if (groups_dir == NULL)
        return true;

    *group_count = 0;
    struct dirent *gid_dir;
    while ((gid_dir = readdir(groups_dir)) != NULL) {
        if (!is_gid(gid_dir->d_name))
            continue;
        (*group_count)++;
    }

    if (closedir(groups_dir) == -1)
        return true;

    return false;
}

bool user_subscribe(const char *uid, const char *gid, const char *gname, subscribe_t *result) {
    result->status = SUBS_OK;
    char user_logged_in[35];
    char group_dir[10];
    char group_msg_dir[14];
    char group_name_file[30];
    sprintf(user_logged_in, "USERS/%s/%s_login.txt", uid, uid);

    struct stat st;
    if (stat(user_logged_in, &st) != 0) {
        result->status = SUBS_EUSR;
        return errno != ENOENT;
    }

    int group_id = atoi(gid);
    int groups_count;
    if (count_groups("GROUPS", &groups_count))
        return true;

    if (group_id > groups_count) {
        result->status = SUBS_EGRP;
        return false;
    }

    if (group_id == 0) {
        if (groups_count == 99) {
            result->status = SUBS_EFULL;
            return false;
        }

        group_id = groups_count + 1;
        result->gid = group_id;
        result->status = SUBS_NEW;

        sprintf(group_dir, "GROUPS/%02d", group_id);
        sprintf(group_msg_dir, "%s/MSG", group_dir);
        sprintf(group_name_file, "%s/%02d_name.txt", group_dir, group_id);

        if (mkdir(group_dir, 0700) == -1)
            return true;

        if (mkdir(group_msg_dir, 0700) == -1)
            return true;

        FILE *gname_file = fopen(group_name_file, "w");
        if (gname_file == NULL)
            return true;

        if (fputs(gname, gname_file) <= 0)
            return true;

        if (fclose(gname_file) == EOF)
            return true;
    } else {
        char group_name[25];
        sprintf(group_dir, "GROUPS/%s", gid);
        sprintf(group_name_file, "%s/%s_name.txt", group_dir, gid);

        FILE *gname_file = fopen(group_name_file, "r");
        if (gname_file == NULL)
            return true;

        if (fscanf(gname_file, "%24s", group_name) < 0)
            return true;

        if (strcmp(group_name, gname) != 0) {
            result->status = SUBS_EGNAME;
            return false;
        }

        if (fclose(gname_file) == EOF)
            return true;
    }

    char user_subscribe_file[20];
    sprintf(user_subscribe_file, "%s/%s.txt", group_dir, uid);
    FILE *subscribe_file = fopen(user_subscribe_file, "w");
    if (subscribe_file == NULL)
        return true;

    if (fclose(subscribe_file) == EOF)
        return true;

    return false;
}

bool user_unsubscribe(const char *uid, const char *gid, unsubscribe_t *result, bool unr) {
    *result = UNS_OK;
    char user_logged_in[35];
    sprintf(user_logged_in, "USERS/%s/%s_login.txt", uid, uid);

    struct stat st;
    if (stat(user_logged_in, &st) != 0 && !unr) {
        *result = UNS_EUSR;
        return errno != ENOENT;
    }

    int group_id = atoi(gid);
    int groups_count;
    if (count_groups("GROUPS", &groups_count))
        return true;

    if (group_id > groups_count) {
        *result = UNS_EGRP;
        return false;
    }

    char user_subscribe_file[20];
    sprintf(user_subscribe_file, "GROUPS/%s/%s.txt", gid, uid);

    if (unlink(user_subscribe_file) != 0 && errno != ENOENT)
        return true;

    return false;
}

bool subscribed_groups(const char *uid, subscribedgroups_t *list, bool *failed) {
    list->len = 0;
    char user_logged_in[35];
    sprintf(user_logged_in, "USERS/%s/%s_login.txt", uid, uid);

    struct stat st;
    if (stat(user_logged_in, &st) != 0) {
        *failed = true;
        return errno != ENOENT;
    }

    DIR *groups_dir = opendir("GROUPS");
    if (groups_dir == NULL)
        return true;

    struct dirent *gid_dir;

    while ((gid_dir = readdir(groups_dir)) != NULL) {
        // Continue if it's not a group id
        if (!is_gid(gid_dir->d_name))
            continue;

        int gid = atoi(gid_dir->d_name);

        char user_subscribe_file[20];
        sprintf(user_subscribe_file, "GROUPS/%s/%s.txt", gid_dir->d_name, uid);

        struct stat st;
        bool is_subscribed = stat(user_subscribe_file, &st) == 0;
        if (!is_subscribed && errno != ENOENT)
            return true;
        else if (!is_subscribed)
            continue;

        char gid_name[30];
        sprintf(gid_name, "GROUPS/%s/%s_name.txt", gid_dir->d_name, gid_dir->d_name);

        FILE *group_name_file = fopen(gid_name, "r");
        if (group_name_file == NULL)
            return true;

        if (fscanf(group_name_file, "%24s", list->names[gid - 1]) < 0)
            return true;

        if (fclose(group_name_file) == EOF)
            return true;

        char msg_name[16];
        sprintf(msg_name, "GROUPS/%s/MSG", gid_dir->d_name);

        int message_count;
        if (count_messages(msg_name, &message_count, NULL))
            return true;

        list->mids[gid - 1] = message_count;
        list->subscribed[gid - 1] = true;
        list->len++;
        if (list->len == 99)
            break;
    }

    if (closedir(groups_dir) == -1)
        return true;

    return false;
}

bool check_if_logged_in(const char *uid, bool *success) {
    char user_logged_in[35];
    sprintf(user_logged_in, "USERS/%s/%s_login.txt", uid, uid);

    struct stat st;
    *success = stat(user_logged_in, &st) == 0;
    return !success && errno != ENOENT;
}

bool check_if_subscribed(const char *gid, const char *uid, bool *result) {
    char user_subscribed[20];
    sprintf(user_subscribed, "GROUPS/%s/%s.txt", gid, uid);

    struct stat st;
    *result = stat(user_subscribed, &st) == 0;
    return !result && errno != ENOENT;
}

bool create_message(const char *gid, const char *author, const char *text, message_t *data,
                    bool *failed) {
    char messages_dir[14];
    char author_file_name[35];
    char text_file_name[31];
    sprintf(messages_dir, "GROUPS/%s/MSG", gid);

    // LOCK
    int lock_fd;
    int count;
    count_messages(messages_dir, &count, &lock_fd);
    if (count == 9999) {
        *failed = true;
        flock(lock_fd, LOCK_UN);
        return false;
    }

    data->mid = count + 1;
    sprintf(data->message_dirname, "%s/%04d", messages_dir, count + 1);
    if (mkdir(data->message_dirname, 0700) == -1) {
        flock(lock_fd, LOCK_UN);
        return true;
    }
    
    flock(lock_fd, LOCK_UN);

    sprintf(author_file_name, "%s/A U T H O R.txt", data->message_dirname);
    sprintf(text_file_name, "%s/T E X T.txt", data->message_dirname);

    FILE *author_file = fopen(author_file_name, "w");
    if (author_file == NULL)
        return true;
    if (fputs(author, author_file) == EOF)
        return true;
    if (fclose(author_file) == EOF)
        return true;

    FILE *text_file = fopen(text_file_name, "w");
    if (text_file == NULL)
        return true;
    if (fputs(text, text_file) == EOF)
        return true;
    if (fclose(text_file) == EOF)
        return true;

    return false;
}

bool is_message_complete(const char *dir_name, bool *is_complete) {
    char author_file_name[35];
    char text_file_name[31];
    sprintf(author_file_name, "%s/A U T H O R.txt", dir_name);
    sprintf(text_file_name, "%s/T E X T.txt", dir_name);
    *is_complete = true;

    struct stat st;
    bool exist = stat(author_file_name, &st) == 0;
    if (!exist && errno != ENOENT)
        return true;
    else if (!exist)
        *is_complete = false;

    exist = stat(text_file_name, &st) == 0;
    if (!exist && errno != ENOENT)
        return true;
    else if (!exist)
        *is_complete = false;

    return false;
}

bool count_complete_msgs(const char *dir_name, int first_mid, int *count) {
    DIR *msg_dir = opendir(dir_name);
    if (msg_dir == NULL)
        return true;

    *count = 0;
    struct dirent *mid_dir;
    while ((mid_dir = readdir(msg_dir)) != NULL) {
        if (!is_mid(mid_dir->d_name))
            continue;

        int mid = atoi(mid_dir->d_name); 
        if (mid < first_mid)
            continue;

        char message_dir[19];
        sprintf(message_dir, "%s/%s", dir_name, mid_dir->d_name);
        bool is_complete;
        if (is_message_complete(message_dir, &is_complete))
            return true;
        
        if (is_complete)
            (*count)++;
    }

    if (closedir(msg_dir) == -1)
        return true;

    return false;
}