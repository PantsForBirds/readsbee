// Part of readsbee, a fork of readsb (https://github.com/wiedehopf/readsb).
// GPL-3.0-or-later, see COPYING.
//
// UUID policy plugin ABI, loaded with --net-uuid-policy=<path.so>.
//
// A plugin is a shared object exporting:
//   readsbee_policy_abi()     required, return READSBEE_POLICY_ABI
//   readsbee_policy_check()   required, called once per connection with its first UUID
//   readsbee_policy_init()    optional, called once at start
//   readsbee_policy_reload()  optional, called when the --net-uuid-config file changes
//
// `arg` is the `policy_arg` value from the --net-uuid-config file ("" if none).
// Calls come from one thread. Keep check() fast, it runs in the network loop.

#ifndef READSBEE_POLICY_H
#define READSBEE_POLICY_H

#include <stdint.h>

#define READSBEE_POLICY_ABI 1

#ifdef __cplusplus
extern "C" {
#endif

int readsbee_policy_abi(void);

// uuid: 36 chars, lower case, e.g. "0123abcd-0123-4567-89ab-0123456789ab".
// now_ms: unix time in ms.
// Return 0 to accept, a positive code to reject (shown to staff only), negative on error
// (treated as reject).
int readsbee_policy_check(const char *uuid, int64_t now_ms);

// return 0 on success, anything else stops readsb
int readsbee_policy_init(const char *arg);

void readsbee_policy_reload(const char *arg);

#ifdef __cplusplus
}
#endif

#endif
