#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>

bool register_user(const char *uid, const char *pass, bool *duplicate);
bool unregister_user(const char *uid, const char *pass, bool *failed);

#endif
