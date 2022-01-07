#ifndef UTILS_VALIDATE_H
#define UTILS_VALIDATE_H

#include <stdbool.h>

bool is_uid(const char *str);
bool is_password(const char *str);
bool is_group_name(const char *str);
bool is_gid(const char *str);
bool is_mid(char *str);

#endif /* UTILS_VALIDATE_H */
