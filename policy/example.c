// Part of readsbee. GPL-3.0-or-later, see COPYING.
//
// Example UUID policy plugin: accept UUIDs starting with the prefix in `policy_arg`
// (accept all if empty). Build: make policy/example.so

#include <string.h>
#include "readsbee_policy.h"

static char prefix[64];

static void setPrefix(const char *arg) {
    strncpy(prefix, arg ? arg : "", sizeof(prefix) - 1);
    prefix[sizeof(prefix) - 1] = '\0';
}

int readsbee_policy_abi(void) {
    return READSBEE_POLICY_ABI;
}

int readsbee_policy_init(const char *arg) {
    setPrefix(arg);
    return 0;
}

void readsbee_policy_reload(const char *arg) {
    setPrefix(arg);
}

int readsbee_policy_check(const char *uuid, int64_t now_ms) {
    (void) now_ms;
    return strncmp(uuid, prefix, strlen(prefix)) == 0 ? 0 : 1;
}
