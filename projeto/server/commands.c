#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "commands.h"

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
    char realpass[9];

    sprintf(user_dirname, "USERS/%s", uid);
    sprintf(user_pass, "%s/%s_pass.txt", user_dirname, uid);

    struct stat st;
    if (stat(user_pass, &st) != 0) {
        *failed = true;
        return errno != ENOENT;
    } 

    FILE *pass_file = fopen(user_pass, "r");
    if (pass_file == NULL)
        return true;

    if (fscanf(pass_file, "%8s", realpass) < 0)
        return true;
    
    if (fclose(pass_file) == EOF)
        return true;

    if (strcmp(pass, realpass) != 0) {
        *failed = true;
        return false;
    }

    if (unlink(user_pass) == 0 && rmdir(user_dirname) == 0)
        return false;

    return true;
}