#include <ctype.h>

#include "validate.h"

/* Checks if a string is a user id */
bool is_uid(const char *str) {
    int i = 0;
    
    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]))
            return false;
    }

    return i == 5;
}

/* Checks if a string is a valid password */
bool is_password(const char *str) {
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!isalnum(str[i]))
            return false;
    }

    return i == 8;
}

/* Checks if a string is a valid group name */
bool is_group_name(const char *str) {
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!(isalnum(str[i]) || str[i] == '-' || str[i] == '_'))
            return false;
    }

    return i <= 24;
}

/* Checks if a string is a valid group id */
bool is_gid(const char *str) {
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]))
            return false;
    }

    return i == 2;
}

/* Checks if a string is a valid message id */
bool is_mid(const char *str) { 
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]))
            return false;
    }

    return i == 4;
}

/* Checks if a string is a valid file name */
bool is_file_name(const char *str) { 
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!(isalnum(str[i]) || str[i] == '-' || str[i] == '_' || str[i] == '.'))
            return false;
    }

    return i <= 24;
}