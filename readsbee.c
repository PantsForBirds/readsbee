// Part of readsbee, a fork of readsb (https://github.com/wiedehopf/readsb).
// GPL-3.0-or-later, see COPYING.
//
// ADSBee-only ingest filter and Beast extension frame accounting. See README-readsbee.md.

#include "readsb.h"

struct beeConfig Bee = {
    .timeout = 15 * SECONDS,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

// Recently rejected UUIDs, for readsbee.json (no IPs)
#define BEE_RECENT_MAX 512
#define BEE_RECENT_KEEP (24 * HOURS)
#define BEE_LOG_EVERY (10 * MINUTES) // log each rejected UUID at most this often

struct beeRecent {
    uint64_t hi, lo;
    int reason;
    int open;            // connections open right now
    uint64_t connections;
    int64_t first, last, last_log;
};

static struct beeRecent recent[BEE_RECENT_MAX];
static int recentLen;

static const char *reasonNames[BEE_R_COUNT] = { "pending", "no_uuid", "format", "date", "denied" };

const char *beeReasonName(int reason) {
    if (reason < 0 || reason >= BEE_R_COUNT)
        return "?";
    return reasonNames[reason];
}

const char *beeStateName(int state, int reason) {
    switch (state) {
        case BEE_EXEMPT: return "exempt";
        case BEE_PENDING: return "pending";
        case BEE_OK: return "ok";
        case BEE_REJECTED: return beeReasonName(reason);
        default: return "off";
    }
}

// --- pure helpers ---------------------------------------------------------------------------

static int hexval(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

// 32 hex digits, dashes optional. Returns 1 on success.
int beeParseUuid(const char *s, uint64_t *hi, uint64_t *lo) {
    uint64_t h = 0, l = 0;
    int n = 0;
    for (; *s && n <= 32; s++) {
        if (*s == '-')
            continue;
        int x = hexval(*s);
        if (x < 0)
            return 0;
        if (n < 16)
            h = h << 4 | x;
        else
            l = l << 4 | x;
        n++;
    }
    if (n != 32 || *s)
        return 0;
    *hi = h;
    *lo = l;
    return 1;
}

static int daysInMonth(int year, int month) {
    static const int d[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (month == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0))
        return 29;
    return d[month - 1];
}

// ADSBee receiver ID: 0xBEE0 + 48 bit binary of the 13 digit YYYMMDDVVXXXX from the part
// code (YYY = year - 2000), sent as UUID with both halves equal.
int beeCheckFormat(uint64_t hi, uint64_t lo, int64_t now_ms) {
    if (hi != lo || (hi >> 48) != 0xBEE0)
        return BEE_R_FORMAT;
    uint64_t v = hi & 0xFFFFFFFFFFFFULL;
    if (v >= 10000000000000ULL)
        return BEE_R_FORMAT;

    uint64_t ymd = v / 1000000; // YYYMMDD
    int day = ymd % 100;
    int month = (ymd / 100) % 100;
    int year = 2000 + (int) (ymd / 10000);

    time_t t = now_ms / 1000;
    struct tm tm;
    gmtime_r(&t, &tm);
    int maxYear = tm.tm_year + 1900 + 1;

    if (year < 2022 || year > maxYear || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month))
        return BEE_R_DATE;
    return BEE_R_NONE;
}

int beeListContains(struct beeList *l, uint64_t hi, uint64_t lo) {
    for (int i = 0; i < l->len; i++) {
        if (l->ids[i].hi == hi && l->ids[i].lo == lo)
            return 1;
    }
    return 0;
}

// (Re)load when mtime, size or inode changed. A missing file is an empty list.
int beeListLoad(struct beeList *l, int force) {
    if (!l->path)
        return 0;

    struct stat st;
    int exists = (stat(l->path, &st) == 0);
    int64_t mtime_ns = exists ? (int64_t) st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec : 0;
    int64_t size = exists ? (int64_t) st.st_size : 0;
    uint64_t ino = exists ? (uint64_t) st.st_ino : 0;

    if (!force && exists == l->exists && mtime_ns == l->mtime_ns && size == l->size && ino == l->ino)
        return 0;

    FILE *f = exists ? fopen(l->path, "r") : NULL;
    if (exists && !f) {
        fprintf(stderr, "readsbee: can't read %s: %s\n", l->path, strerror(errno));
        return 0; // keep the old list, retry on the next change
    }

    l->exists = exists;
    l->mtime_ns = mtime_ns;
    l->size = size;
    l->ino = ino;
    l->len = 0;

    int bad = 0;
    char line[256];
    while (f && fgets(line, sizeof(line), f)) {
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        // trim
        char *s = line;
        while (*s && isspace((unsigned char) *s))
            s++;
        char *e = s + strlen(s);
        while (e > s && isspace((unsigned char) e[-1]))
            *--e = '\0';
        if (!*s)
            continue;

        uint64_t hi, lo;
        if (!beeParseUuid(s, &hi, &lo)) {
            if (bad++ < 5)
                fprintf(stderr, "readsbee: %s: not a UUID: %.40s\n", l->path, s);
            continue;
        }
        if (beeListContains(l, hi, lo))
            continue;
        if (l->len == l->alloc) {
            l->alloc = l->alloc ? 2 * l->alloc : 64;
            l->ids = realloc(l->ids, l->alloc * sizeof(struct beeUuid));
            if (!l->ids) {
                fprintf(stderr, "readsbee: out of memory\n");
                exit(1);
            }
        }
        l->ids[l->len].hi = hi;
        l->ids[l->len].lo = lo;
        l->len++;
    }
    if (f)
        fclose(f);
    l->loads++;
    fprintf(stderr, "readsbee: loaded %d UUIDs from %s%s\n", l->len, l->path, exists ? "" : " (missing)");
    return 1;
}

int beeIsLoopback(const char *host) {
    if (!host || !*host)
        return 0;
    if (host[0] == '/')
        return 1; // unix socket
    if (!strncmp(host, "::ffff:", 7))
        host += 7;
    return !strncmp(host, "127.", 4) || !strcmp(host, "::1");
}

// "TCP4 <src> <dst> <sport> <dport>"
int beeProxyIsLoopback(const char *proxy) {
    char src[64];
    if (sscanf(proxy, "%*s %63s", src) != 1)
        return 0;
    return beeIsLoopback(src);
}

// p points at the type byte after 0x1a. The frame ends at the next 0x1a that isn't an
// escaped 0x1a 0x1a pair. Returns the frame length from p, 0 if incomplete, -1 if too long.
int beeExtFrameLen(const char *p, const char *eod) {
    const char *q = p + 1;
    while (q < eod) {
        const char *r = memchr(q, 0x1a, eod - q);
        if (!r)
            break;
        if (r - p > BEE_EXT_MAX_LEN)
            return -1;
        if (r + 1 >= eod)
            return 0; // can't tell escape from frame start yet
        if (r[1] == 0x1a) {
            q = r + 2;
            continue;
        }
        return r - p;
    }
    if (eod - p > BEE_EXT_MAX_LEN)
        return -1;
    return 0;
}

// --- recent rejected table (caller holds Bee.mutex) -----------------------------------------

static struct beeRecent *recentGet(uint64_t hi, uint64_t lo, int64_t now) {
    struct beeRecent *oldest = NULL;
    for (int i = 0; i < recentLen; i++) {
        struct beeRecent *r = &recent[i];
        if (r->hi == hi && r->lo == lo)
            return r;
        if (!r->open && (!oldest || r->last < oldest->last))
            oldest = r;
    }
    struct beeRecent *r;
    if (recentLen < BEE_RECENT_MAX)
        r = &recent[recentLen++];
    else if (oldest)
        r = oldest;
    else
        return NULL;
    memset(r, 0, sizeof(*r));
    r->hi = hi;
    r->lo = lo;
    r->first = now;
    return r;
}

static void recentPrune(int64_t now) {
    int j = 0;
    for (int i = 0; i < recentLen; i++) {
        if (recent[i].open || now - recent[i].last < BEE_RECENT_KEEP)
            recent[j++] = recent[i];
    }
    recentLen = j;
}

// --- per connection --------------------------------------------------------------------------

static int logAllowed(int64_t now) {
    // at most 20 lines per minute in total
    static int64_t window;
    static int lines;
    if (now - window > 1 * MINUTES) {
        window = now;
        lines = 0;
    }
    return ++lines <= 20;
}

static void setRejected(struct client *c, int reason, int64_t now) {
    c->bee.state = BEE_REJECTED;
    c->bee.reason = reason;
    __atomic_add_fetch(&Bee.rejected_conn[reason], 1, __ATOMIC_RELAXED);

    char uuid[64];
    sprint_uuid(c->receiverId, c->receiverId2, uuid);

    pthread_mutex_lock(&Bee.mutex);
    struct beeRecent *r = recentGet(c->receiverId, c->receiverId2, now);
    int log = 1;
    if (r) {
        r->reason = reason;
        r->open++;
        r->connections++;
        r->last = now;
        log = (now - r->last_log > BEE_LOG_EVERY);
        if (log)
            r->last_log = now;
    }
    pthread_mutex_unlock(&Bee.mutex);

    if (log && logAllowed(now)) {
        fprintf(stderr, "readsbee: reject %s (%s) %s\n", uuid, beeReasonName(reason), c->proxy_string);
    }
}

static void clearRejected(struct client *c, int64_t now) {
    if (c->bee.state != BEE_REJECTED)
        return;
    pthread_mutex_lock(&Bee.mutex);
    struct beeRecent *r = recentGet(c->receiverId, c->receiverId2, now);
    if (r && r->open > 0) {
        r->open--;
        r->last = now;
    }
    pthread_mutex_unlock(&Bee.mutex);
}

static int decide(struct client *c, int64_t now) {
    uint64_t hi = c->receiverId, lo = c->receiverId2;
    if (Bee.deny.path && beeListContains(&Bee.deny, hi, lo))
        return BEE_R_DENIED;
    if (!Bee.require)
        return BEE_R_NONE;
    if (Bee.allow.path && beeListContains(&Bee.allow, hi, lo))
        return BEE_R_NONE;
    return beeCheckFormat(hi, lo, now);
}

void beeInit(void) {
    beeListLoad(&Bee.allow, 1);
    beeListLoad(&Bee.deny, 1);
    if (beeActive()) {
        fprintf(stderr, "readsbee: ingest filter on: require ADSBee UUID %s, timeout %.0f s, allow %d, deny %d\n",
                Bee.require ? "yes" : "no", Bee.timeout / 1000.0, Bee.allow.len, Bee.deny.len);
    }
}

// Beast input connection accepted on a listen port
void beeClientAccept(struct client *c, int64_t now) {
    MODES_NOTUSED(now);
    c->bee.state = BEE_OFF;
    if (!beeActive() || c->service->read_mode != READ_MODE_BEAST)
        return;
    c->bee.state = beeIsLoopback(c->host) ? BEE_EXEMPT : BEE_PENDING;
}

// PROXY v1 header names the real peer
void beeClientProxy(struct client *c) {
    if (c->bee.state == BEE_EXEMPT && !beeProxyIsLoopback(c->proxy_string))
        c->bee.state = BEE_PENDING;
    else if (c->bee.state == BEE_PENDING && beeProxyIsLoopback(c->proxy_string))
        c->bee.state = BEE_EXEMPT;
}

// first valid 0xE4 UUID of the connection
void beeClientUuid(struct client *c, int64_t now) {
    if (c->bee.state != BEE_PENDING)
        return;
    int reason = decide(c, now);
    if (reason == BEE_R_NONE)
        c->bee.state = BEE_OK;
    else
        setRejected(c, reason, now);
}

// after a list reload: accepted ones may now be denied and rejected ones allowed
int beeEvaluate(struct client *c, int64_t now) {
    if (c->bee.state != BEE_OK && c->bee.state != BEE_REJECTED)
        return 0;
    int reason = decide(c, now);
    if (reason == BEE_R_NONE && c->bee.state == BEE_REJECTED) {
        clearRejected(c, now);
        c->bee.state = BEE_OK;
        c->bee.reason = BEE_R_NONE;
        char uuid[64];
        sprint_uuid(c->receiverId, c->receiverId2, uuid);
        fprintf(stderr, "readsbee: accept %s (list change)\n", uuid);
        return 1;
    }
    if (reason != BEE_R_NONE && (c->bee.state == BEE_OK || c->bee.reason != reason)) {
        clearRejected(c, now);
        setRejected(c, reason, now);
        return 1;
    }
    return 0;
}

int beePoll(int64_t now) {
    if (!beeActive() || now < Bee.next_poll)
        return 0;
    Bee.next_poll = now + 2 * SECONDS;
    pthread_mutex_lock(&Bee.mutex);
    int changed = beeListLoad(&Bee.allow, 0);
    changed |= beeListLoad(&Bee.deny, 0);
    recentPrune(now);
    pthread_mutex_unlock(&Bee.mutex);
    return changed;
}

int beeTimedOut(struct client *c, int64_t now) {
    if (c->bee.state != BEE_PENDING || now - c->connectedSince < Bee.timeout)
        return 0;
    __atomic_add_fetch(&Bee.rejected_conn[BEE_R_NO_UUID], 1, __ATOMIC_RELAXED);
    if (logAllowed(now))
        fprintf(stderr, "readsbee: close, no UUID after %.0f s: %s\n", Bee.timeout / 1000.0, c->proxy_string);
    return 1;
}

void beeClientClose(struct client *c) {
    clearRejected(c, mstime());
    c->bee.state = BEE_OFF;
}

int beeDrop(struct client *c) {
    int s = c->bee.state;
    if (s != BEE_PENDING && s != BEE_REJECTED)
        return 0;
    c->bee.dropped++;
    int idx = (s == BEE_PENDING) ? BEE_R_NONE : c->bee.reason;
    __atomic_add_fetch(&Bee.dropped_msgs[idx], 1, __ATOMIC_RELAXED);
    return 1;
}

// read one logical (unescaped) byte, returns the next position
static const char *unesc(const char *p, const char *end, unsigned char *out) {
    if (p >= end)
        return NULL;
    *out = (unsigned char) *p++;
    if (*out == 0x1a)
        p++; // second byte of the pair
    return p;
}

void beeCountExt(struct client *c, const char *p, int len) {
    unsigned char type = (unsigned char) *p;
    if (type < BEE_EXT_FIRST)
        return;
    int i = type - BEE_EXT_FIRST;
    c->bee.ext[i]++;
    __atomic_add_fetch(&Bee.ext_frames[i], 1, __ATOMIC_RELAXED);

    if (type == 0xEE) {
        // 0x1a 0xEE LEN SUB payload
        const char *end = p + len;
        unsigned char lenByte, sub;
        const char *q = unesc(p + 1, end, &lenByte);
        if (q && unesc(q, end, &sub)) {
            int s = sub < 16 ? sub : 16;
            c->bee.ee[s]++;
            __atomic_add_fetch(&Bee.ee_frames[s], 1, __ATOMIC_RELAXED);
        }
    }
}

// --- json ------------------------------------------------------------------------------------

static char *appendExtCounts(char *p, char *end, const uint32_t *ext32, const uint64_t *ext64,
        const uint32_t *ee32, const uint64_t *ee64) {
    p = safe_snprintf(p, end, "\"ext\":{");
    const char *sep = "";
    for (int i = 0; i < BEE_EXT_TYPES; i++) {
        uint64_t n = ext32 ? ext32[i] : ext64[i];
        if (n) {
            p = safe_snprintf(p, end, "%s\"%02x\":%" PRIu64, sep, BEE_EXT_FIRST + i, n);
            sep = ",";
        }
    }
    p = safe_snprintf(p, end, "},\"ee\":{");
    sep = "";
    for (int i = 0; i < BEE_EE_SUBS; i++) {
        uint64_t n = ee32 ? ee32[i] : ee64[i];
        if (n) {
            if (i < 16)
                p = safe_snprintf(p, end, "%s\"%02x\":%" PRIu64, sep, i, n);
            else
                p = safe_snprintf(p, end, "%s\"other\":%" PRIu64, sep, n);
            sep = ",";
        }
    }
    return safe_snprintf(p, end, "}");
}

// "readsbee" object for stats.json
char *beeAppendStatsJson(char *p, char *end) {
    p = safe_snprintf(p, end, ",\n\"readsbee\":{\"filter\":%s,\"rejected_connections\":{", beeActive() ? "true" : "false");
    for (int i = 1; i < BEE_R_COUNT; i++)
        p = safe_snprintf(p, end, "%s\"%s\":%" PRIu64, i > 1 ? "," : "", reasonNames[i], Bee.rejected_conn[i]);
    p = safe_snprintf(p, end, "},\"dropped_messages\":{");
    for (int i = 0; i < BEE_R_COUNT; i++) {
        if (i == BEE_R_NO_UUID)
            continue;
        p = safe_snprintf(p, end, "%s\"%s\":%" PRIu64, i > 0 ? "," : "", reasonNames[i], Bee.dropped_msgs[i]);
    }
    p = safe_snprintf(p, end, "},");
    p = appendExtCounts(p, end, NULL, Bee.ext_frames, NULL, Bee.ee_frames);
    p = safe_snprintf(p, end, ",\"ext_too_long\":%" PRIu64 "}", Bee.ext_too_long);
    return p;
}

// readsbee.json: filter state, rejected UUIDs and extension frame counts per receiver.
// Safe to publish: no IPs.
void beeWriteJson(const char *dir) {
    if (!dir)
        return;
    int64_t now = mstime();
    size_t buflen = 256 * 1024;
    char *buf = cmalloc(buflen), *p = buf, *end = buf + buflen;

    p = safe_snprintf(p, end, "{\"now\":%.3f,\"filter\":{\"active\":%s,\"require_adsbee\":%s,\"timeout\":%.0f,"
            "\"allow\":%d,\"deny\":%d}",
            now / 1000.0, beeActive() ? "true" : "false", Bee.require ? "true" : "false",
            Bee.timeout / 1000.0, Bee.allow.len, Bee.deny.len);

    // counters (same as stats.json)
    p = beeAppendStatsJson(p, end);

    p = safe_snprintf(p, end, ",\n\"rejected\":[");
    pthread_mutex_lock(&Bee.mutex);
    const char *sep = "\n";
    for (int i = 0; i < recentLen && p + 300 < end; i++) {
        struct beeRecent *r = &recent[i];
        char uuid[64];
        sprint_uuid(r->hi, r->lo, uuid);
        p = safe_snprintf(p, end, "%s{\"uuid\":\"%s\",\"reason\":\"%s\",\"open\":%d,\"connections\":%" PRIu64
                ",\"first\":%.0f,\"last\":%.0f}",
                sep, uuid, beeReasonName(r->reason), r->open, r->connections, r->first / 1000.0, r->last / 1000.0);
        sep = ",\n";
    }
    pthread_mutex_unlock(&Bee.mutex);
    p = safe_snprintf(p, end, "\n],\n\"receivers\":[");

    // same unlocked walk as generateClientsJson(), clients are only freed with all threads locked
    sep = "\n";
    for (struct net_service *service = Modes.services_in.services; service->descr; service++) {
        if (service->read_mode != READ_MODE_BEAST)
            continue;
        for (struct client *c = service->clients; c; c = c->next) {
            if (!c->service)
                continue;
            if ((p + 2000) >= end) {
                int used = p - buf;
                buflen *= 2;
                buf = realloc(buf, buflen);
                if (!buf) {
                    fprintf(stderr, "readsbee: out of memory\n");
                    return;
                }
                p = buf + used;
                end = buf + buflen;
            }
            char uuid[64];
            sprint_uuid(c->receiverId, c->receiverId2, uuid);
            int locked = c->receiverIdLocked;
            p = safe_snprintf(p, end, "%s{\"uuid\":%s%s%s,\"state\":\"%s\",\"dropped\":%" PRIu64 ",",
                    sep, locked ? "\"" : "", locked ? uuid : "null", locked ? "\"" : "",
                    beeStateName(c->bee.state, c->bee.reason), c->bee.dropped);
            p = appendExtCounts(p, end, c->bee.ext, NULL, c->bee.ee, NULL);
            p = safe_snprintf(p, end, "}");
            sep = ",\n";
        }
    }
    p = safe_snprintf(p, end, "\n]}\n");

    struct char_buffer cb = { .buffer = buf, .len = p - buf };
    free(writeJsonToFile(dir, "readsbee.json", cb).buffer);
}
