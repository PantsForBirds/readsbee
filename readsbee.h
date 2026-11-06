// Part of readsbee, a fork of readsb (https://github.com/wiedehopf/readsb).
// GPL-3.0-or-later, see COPYING.
//
// UUID ingest filter and Beast extension frame accounting. See README-readsbee.md.

#ifndef READSBEE_H
#define READSBEE_H

#include <stdint.h>
#include <pthread.h>

struct client;
struct messageBuffer;
struct aircraft;
struct modesMessage;

// readsbee feed protocol v2 frames (FEED-PROTOCOL.md), counted per connection and in stats.json
enum beeFrameType {
    BEE_FT_ADSL = 0,  // 0xED ADS-L, decoded
    BEE_FT_RID,       // 0xEF Remote ID, decoded
    BEE_FT_UAT,       // 0xEC s/l/u/S/L/U, any clock
    BEE_FT_UAT_MLAT,  // 0xEC S/L/U with ts on the Mode S clock (ts != 0)
    BEE_FT_BAD,       // 0xEC/0xED/0xEF with an unknown letter, failed bounds, bad CRC / layout
    BEE_FT_COUNT
};

// sub-GHz / Remote ID timestamp quality (letter case + ts, FEED-PROTOCOL.md §2)
enum beeClock {
    BEE_CLK_NOT_MLAT = 0, // lower case: never use for MLAT
    BEE_CLK_UNSYNCED,     // upper case, ts 0
    BEE_CLK_MODES,        // upper case: ts on this connection's Mode S 12 MHz clock
};

// last timed frame of a connection, kept for a later MLAT path
struct beeTiming {
    int64_t ts;      // 12 MHz ticks (BEE_CLK_MODES) or raw
    int64_t when;    // ms, arrival
    int8_t clock;    // enum beeClock
    uint8_t type;    // Beast type byte
    uint16_t epoch;  // +1 each time the sub-GHz clock drops from synced to ts 0 (mode switch:
                     // the clock is re-based after it, don't compare timestamps across epochs)
};

// carried on modesMessage for frames readsbee decoded itself (ADS-L, Remote ID on the globe)
struct beeMsg {
    uint8_t kind;    // 0 = not ours, 1 = ADS-L, 2 = Remote ID
    uint8_t amt;     // ADS-L address mapping table
    uint8_t cat;     // ADS-L aircraft category (G.1.3)
    uint8_t channel; // 0 868.2, 1 868.4, 0xFF unknown
    int8_t dbm;      // valid if hasDbm
    uint8_t hasDbm;  // the level came in as dBm (connection confirmed bit 0)
    int8_t clock;
    int64_t ts;
};

// per aircraft, at the end of struct aircraft (not persisted, zeroed on load)
struct beeAircraft {
    int64_t adslSeen;
    int64_t ridSeen;
    struct beeMsg last;
    int64_t dbmSeen; // last message with a dBm level
    int8_t dbm;
};

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
    BEE_R_POLICY,    // policy plugin said no
    BEE_R_DENIED,    // listed in --net-uuid-deny-file
    BEE_R_REUSE,     // same UUID from too many source addresses
    BEE_R_COUNT
};

// capabilities check 0xE5 (FEED-PROTOCOL.md §7): feature bits
#define BEE_CAP_SIG_DBM 0x01   // signal byte of every frame is int8 dBm after 'C'
#define BEE_CAP_ADSL 0x02      // 0xED
#define BEE_CAP_RID 0x04       // 0xEF
#define BEE_CAP_UAT_UPPER 0x08 // 0xEC S/L/U
#define BEE_CAP_KNOWN 0x0F
#define BEE_CAPS_LEN 6         // 1a E5 letter ver f0 f1
#define BEE_CAPS_VERSION 1
#define BEE_CAPS_ANSWERED 0x01 // capsState
#define BEE_CAPS_CONFIRMED 0x02

#define BEE_EXT_FIRST 0xE0  // extension frame types counted: 0xE0..0xFF
#define BEE_EXT_TYPES 32
#define BEE_EXT_MAX_LEN 576 // max escaped length of one extension frame, longer is garbage
#define BEE_EE_SUBS 17      // 0xEE subtypes 0x00..0x0F, index 16 = any other subtype

struct beeClient {
    int8_t state;
    int8_t reason;
    int8_t reuse;     // counted in the reuse table
    int8_t flagged;   // over the reuse limit, reuse_action=flag
    int32_t code;     // policy reject code
    uint64_t src;     // hash of the source address
    uint64_t dropped; // messages dropped while pending / rejected
    uint32_t ext[BEE_EXT_TYPES]; // extension frames skipped, per type
    uint32_t ee[BEE_EE_SUBS];    // 0xEE frames per subtype
    uint32_t frames[BEE_FT_COUNT]; // v2 frames decoded per type
    struct beeTiming timing;     // last UAT / ADS-L / Remote ID frame
    uint16_t capsOffered;        // bits in the feeder's query
    uint16_t capsActive;         // bits in effect since its confirm
    uint8_t capsState;           // BEE_CAPS_ANSWERED | BEE_CAPS_CONFIRMED
    uint8_t uatHasDbm;           // decodeEncapsulatedUAT -> decodeUatMessage
    int8_t uatDbm;
};

struct beeUuid {
    uint64_t hi;
    uint64_t lo;
};

// a file reloaded when it changes
struct beeFile {
    char *path;
    int64_t mtime_ns;
    int64_t size;
    uint64_t ino;
    int exists;
};

struct beeList {
    struct beeFile f;
    struct beeUuid *ids;
    int len;
    int alloc;
};

struct beeConfig {
    int require;           // --net-uuid-require
    char *policyPath;      // --net-uuid-policy
    char *statusDir;       // --net-uuid-status-dir
    int64_t timeout;       // --net-uuid-timeout (ms)
    struct beeList allow;  // --net-uuid-allow-file
    struct beeList deny;   // --net-uuid-deny-file
    struct beeFile config; // --net-uuid-config
    // from the config file
    int maxSources;        // max_sources: distinct source addresses per UUID, 0 = off
    int reuseReject;       // reuse_action: reject (1) or flag (0)
    char policyArg[256];   // policy_arg
    // plugin
    void *dl;
    int (*policyCheck)(const char *uuid, int64_t now_ms);
    void (*policyReload)(const char *arg);
    int64_t next_poll;
    // counters since start
    uint64_t rejected_conn[BEE_R_COUNT];
    uint64_t dropped_msgs[BEE_R_COUNT]; // index BEE_R_NONE: dropped while pending
    uint64_t reuse_flagged;
    uint64_t ext_frames[BEE_EXT_TYPES];
    uint64_t ee_frames[BEE_EE_SUBS];
    uint64_t ext_too_long;
    pthread_mutex_t mutex; // guards the lists and the rejected table
    // v2 frames
    uint64_t frames[BEE_FT_COUNT];
    int ridGlobe;          // --readsbee-rid-globe: drones also go into the aircraft table
    int ridOperator;       // --readsbee-rid-operator: operator location / ID in public outputs
    int64_t ridTimeout;    // drones are dropped this long after the last message
    uint16_t capsAccept;   // --readsbee-caps: bits answered to a query (default BEE_CAP_KNOWN)
};

extern struct beeConfig Bee;

// active if any filter option was given
static inline int beeActive(void) {
    return Bee.require || Bee.deny.f.path;
}

// helpers (unit tested in beetests.c)
int beeParseUuid(const char *s, uint64_t *hi, uint64_t *lo);
int beeListContains(struct beeList *l, uint64_t hi, uint64_t lo);
int beeListLoad(struct beeList *l, int force); // 1 if (re)loaded
int beeConfigLoad(int force); // 1 if (re)loaded
int beeIsLoopback(const char *host);
int beeProxyIsLoopback(const char *proxy); // proxy_string from a PROXY v1 header
int beeExtFrameLen(const char *p, const char *eod); // >0 length, 0 incomplete, -1 too long
const char *beeStateName(int state, int reason);
const char *beeReasonName(int reason);
int beeReuseCount(uint64_t hi, uint64_t lo); // distinct sources now

// net_io.c hooks
void beeInit(void);
void beeClientAccept(struct client *c, int64_t now);
void beeClientProxy(struct client *c);
void beeClientUuid(struct client *c, int64_t now);
int beeEvaluate(struct client *c, int64_t now); // re-check after a list / config reload
int beePoll(int64_t now); // 1 if lists or config changed
int beeTimedOut(struct client *c, int64_t now);
void beeCountExt(struct client *c, const char *p, int len); // p at the type byte
void beeClientClose(struct client *c);

// drop data from pending / rejected connections
int beeDrop(struct client *c);

// readsbee.json in --net-uuid-status-dir (staff only: has reasons)
void beeWriteJson(int64_t now);

// --- v2 frames (readsbee_ext.c) ---
// readBeast: p at the type byte of an extension frame (0xE0..0xFF, or 0xEC with an unknown
// letter). Returns the bytes to skip from p, 0 if incomplete, -1 if too long (garbage).
int beeExtFrame(struct client *c, char *p, char *eod, int64_t now, struct messageBuffer *mb);
// decodeEncapsulatedUAT: letter as received, ts from the frame. 1 = decode it, 0 = blocked
int beeUatFrame(struct client *c, char letter, int64_t ts, int64_t now);
// trackUpdateFromMessage
void beeTrackUpdate(struct aircraft *a, struct modesMessage *mm, int64_t now);
// sprintAircraftObject (aircraft.json, /re-api/)
char *beeJsonAircraft(char *p, char *end, struct aircraft *a, int64_t now);
// "frames":{...} for readsbee.json (one of f32 / f64)
char *beeFramesJson(char *p, char *end, const uint32_t *f32, const uint64_t *f64);
// stats.json "readsbee" object
char *beeStatsJson(char *p, char *end, const uint32_t *frames);
// remoteid.json in the json dir, remoteid-full.json in the status dir
void beeWriteRemoteId(int64_t now);
// /re-api/?remoteid[&filter_uuid=...], buffer starts with pad free bytes
int beeApiRemoteId(uint64_t filter_uuid, int pad, char **buf, int *len);

// signal byte -> signalLevel: int8 dBm (256-entry table) if the connection confirmed bit 0,
// else the Beast power byte. Sets bm->dbm / hasDbm when bm is given.
double beeSignal(const struct client *c, uint8_t b, struct beeMsg *bm);
// readBeast: p at 0xE5. Returns the bytes to skip from p, 0 incomplete, -1 malformed.
// *answerLen = BEE_CAPS_LEN when answer[] must be sent back on this connection.
int beeCapsFrame(struct client *c, const char *p, const char *eod, char *answer, int *answerLen);
// decodeUatMessage: dBm of the 0xEC frame being decoded
void beeUatMessage(struct client *c, struct modesMessage *mm);

// decoders (unit tested in beetests.c)
struct beeAdsl {
    int version, key, ptype, amt, relay;
    uint32_t addr;
    int traffic;     // 1 if a Traffic payload was decoded
    int ts_qs, fstate, cat, emerg;
    int pos_valid, alt_valid, gs_valid, vr_valid;
    double lat, lon, gs_mps, vr_mps, track;
    int alt_m;
};
enum { BEE_ADSL_OK = 0, BEE_ADSL_LEN = -1, BEE_ADSL_CRC = -2, BEE_ADSL_FEC = -3, BEE_ADSL_KEY = -4 };
int beeAdslDecode(const uint8_t *onair, int len, struct beeAdsl *out); // onair = L, then L bytes
uint32_t beeCrc24(const uint8_t *data, int len);
void beeXxteaDecrypt(uint8_t *data, int len); // key 0, 6 rounds, len % 4 == 0
// one Beast frame body after the letter, unescaped: returns consumed bytes from p (escaped),
// 0 incomplete, -1 bad. body / blen: unescaped bytes after the letter.
int beeExtParse(const char *p, const char *eod, uint8_t *body, int *blen);
// Remote ID: feed one ODID message or pack (as in the frame), mac 6 bytes
void beeRidInput(const uint8_t *odid, int len, const uint8_t *mac, char transport, const struct beeMsg *sig,
        double level, uint64_t rxHi, uint64_t rxLo, int64_t now, struct messageBuffer *mb, struct client *c);
int beeRidCount(void);
// JSON of the drone table (public = 1: no operator data unless --readsbee-rid-operator)
int beeRidJson(char **buf, int *len, int pad, int public, uint64_t filter_uuid, int64_t now);
void beeRidReset(void);

#endif
