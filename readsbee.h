// Part of readsbee, a fork of readsb (https://github.com/wiedehopf/readsb).
// GPL-3.0-or-later, see COPYING.
//
// ADSBee-only ingest filter and Beast extension frame accounting.

#ifndef READSBEE_H
#define READSBEE_H

#include <stdint.h>
#include <pthread.h>

struct client;

// Per connection filter state
enum beeState {
    BEE_OFF = 0,     // filter not active for this connection
    BEE_EXEMPT,      // loopback (mlathub, local tools)
    BEE_PENDING,     // waiting for the 0xE4 UUID, data is dropped
    BEE_OK,          // UUID accepted
    BEE_REJECTED,    // UUID rejected, data is dropped, connection kept open
};

enum beeReason {
    BEE_R_NONE = 0,
    BEE_R_NO_UUID,   // no UUID within --net-uuid-timeout, connection closed
    BEE_R_FORMAT,    // not the ADSBee UUID format
    BEE_R_DATE,      // ADSBee format, but the digits are not a plausible build date
    BEE_R_DENIED,    // listed in --net-uuid-deny-file
    BEE_R_COUNT
};

#define BEE_EXT_FIRST 0xE0  // extension frame types counted: 0xE0..0xFF
#define BEE_EXT_TYPES 32
#define BEE_EXT_MAX_LEN 576 // max escaped length of one extension frame, longer is garbage

#define BEE_EE_SUBS 17 // 0xEE subtypes 0x00..0x0F, index 16 = any other subtype

struct beeClient {
    int8_t state;
    int8_t reason;
    uint64_t dropped; // messages dropped while pending / rejected
    uint32_t ext[BEE_EXT_TYPES]; // extension frames skipped, per type
    uint32_t ee[BEE_EE_SUBS]; // 0xEE frames per subtype
};

struct beeUuid {
    uint64_t hi;
    uint64_t lo;
};

struct beeList {
    char *path;
    struct beeUuid *ids;
    int len;
    int alloc;
    // change detection
    int64_t mtime_ns;
    int64_t size;
    uint64_t ino;
    int exists;
    uint32_t loads;
};

struct beeConfig {
    int require;           // --net-require-adsbee-uuid
    int64_t timeout;       // --net-uuid-timeout (ms)
    struct beeList allow;  // --net-uuid-allow-file
    struct beeList deny;   // --net-uuid-deny-file
    int64_t next_poll;
    // counters since start
    uint64_t rejected_conn[BEE_R_COUNT];
    uint64_t dropped_msgs[BEE_R_COUNT]; // index BEE_R_NONE: dropped while pending
    uint64_t ext_frames[BEE_EXT_TYPES];
    uint64_t ee_frames[BEE_EE_SUBS];
    uint64_t ext_too_long;
    pthread_mutex_t mutex; // guards the lists and the recent rejected table
};

extern struct beeConfig Bee;

// active if any filter option was given
static inline int beeActive(void) {
    return Bee.require || Bee.deny.path;
}

// pure helpers (unit tested in beetests.c)
int beeParseUuid(const char *s, uint64_t *hi, uint64_t *lo);
int beeCheckFormat(uint64_t hi, uint64_t lo, int64_t now_ms); // returns enum beeReason
int beeListContains(struct beeList *l, uint64_t hi, uint64_t lo);
int beeListLoad(struct beeList *l, int force); // 1 if (re)loaded
int beeIsLoopback(const char *host);
int beeProxyIsLoopback(const char *proxy); // proxy_string from a PROXY v1 header
int beeExtFrameLen(const char *p, const char *eod); // >0 length, 0 incomplete, -1 too long
const char *beeStateName(int state, int reason);
const char *beeReasonName(int reason);

// net_io.c hooks
void beeInit(void);
void beeClientAccept(struct client *c, int64_t now);
void beeClientProxy(struct client *c);
void beeClientUuid(struct client *c, int64_t now);
int beeEvaluate(struct client *c, int64_t now); // re-check after a list reload
int beePoll(int64_t now); // 1 if lists changed
int beeTimedOut(struct client *c, int64_t now);
void beeCountExt(struct client *c, const char *p, int len); // p at the type byte
void beeClientClose(struct client *c);

// drop data from pending / rejected connections
int beeDrop(struct client *c);

// json
char *beeAppendStatsJson(char *p, char *end);
void beeWriteJson(const char *dir); // readsbee.json

#endif
