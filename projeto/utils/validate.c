#include <ctype.h>

#include "validate.h"

bool is_uid(const char *str) {
    int i = 0;
    
    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]))
            return false;
    }

    return i == 5;
}

bool is_password(const char *str) {
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!isalnum(str[i]))
            return false;
    }

    return i == 8;
}

bool is_group_name(const char *str) {
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!(isalnum(str[i]) || str[i] == '-' || str[i] == '_'))
            return false;
    }

    return i < 24;
}

bool is_gid(const char *str) {
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]))
            return false;
    }

    return i == 2;
}

bool is_mid(char *str) { 
    int i = 0;

    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]))
            return false;
    }

    return i == 4;
}
