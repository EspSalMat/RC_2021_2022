#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

bool unregister_user(const char *uid, const char *pass, bool *failed) {
    char user_dirname[20];
    char user_pass[34];

    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    struct stat st;
    if (stat(user_dirname, &st) != 0) {
        *failed = true;
        return false;
    }

    if (check_password(user_pass, pass, failed))
        return true;
    else if (*failed)
        return false;

    if (unlink(user_pass) == 0 && rmdir(user_dirname) == 0)
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
        return false;
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
        return false;
    }

    if (unlink(user_logged_in) == 0)
        return false;

    return true;
}

bool count_messages(const char *dir_name, int *message_count) {
    DIR *msg_dir;
    struct dirent *mid_dir;
    msg_dir = opendir(dir_name);
    if (!msg_dir)
        return true;

    *message_count = 0;
    while ((mid_dir = readdir(msg_dir)) != NULL) {
        if (mid_dir->d_name[0] == '.')
            continue;
        if (strlen(mid_dir->d_name) > 4)
            continue;
        (*message_count)++;
    }
    if (closedir(msg_dir) == -1)
        return true;

    return false;
}

bool list_groups(grouplist_t *list) {
    DIR *groups_dir;
    groups_dir = opendir("GROUPS");
    if (!groups_dir)
        return true;

    struct dirent *gid_dir;
    list->len = 0;
    while ((gid_dir = readdir(groups_dir)) != NULL) {
        if (gid_dir->d_name[0] == '.')
            continue;
        if (strlen(gid_dir->d_name) > 2)
            continue;

        int gid;
        if (sscanf(gid_dir->d_name, "%d", &gid) < 0)
            return true;
        int i = gid - 1;

        char gid_name[30];
        sprintf(gid_name, "GROUPS/%s/%s_name.txt", gid_dir->d_name, gid_dir->d_name);

        FILE *group_name_file;
        group_name_file = fopen(gid_name, "r");
        if (group_name_file == NULL)
            return true;
        if (fscanf(group_name_file, "%24s", list->names[i]) < 0)
            return true;
        if (fclose(group_name_file) == EOF)
            return true;

        char msg_name[16];
        sprintf(msg_name, "GROUPS/%s/MSG", gid_dir->d_name);

        int message_count;
        if (count_messages(msg_name, &message_count))
            return true;
        list->mids[i] = message_count;

        list->len++;
        if (list->len == 99)
            break;
    }

    if (closedir(groups_dir) == -1)
        return true;

    return false;
}