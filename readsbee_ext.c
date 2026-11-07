// Part of readsbee, a fork of readsb (https://github.com/wiedehopf/readsb).
// GPL-3.0-or-later, see COPYING.
//
// ADSBee Beast extensions (2026-11-06) frames: ADS-L 0xED, Remote ID 0xEF, UAT 0xEC S/L/U.
// See README-readsbee.md and FEED-PROTOCOL.md.

#include "readsb.h"

#define ESC 0x1a

// --- frame bounds ----------------------------------------------------------------------------

// n unescaped bytes from *q: 1 ok, 0 incomplete, -1 lone 0x1a (a frame start) inside
static int takeN(const char **q, const char *eod, uint8_t *out, int n) {
    const char *s = *q;
    for (int i = 0; i < n; i++) {
        if (s >= eod)
            return 0;
        uint8_t x = (uint8_t) *s++;
        if (x == ESC) {
            if (s >= eod)
                return 0;
            if ((uint8_t) *s != ESC)
                return -1;
            s++;
        }
        out[i] = x;
    }
    *q = s;
    return 1;
}

static int isLetter(char k, const char *set) {
    if (!((k >= 'a' && k <= 'z') || (k >= 'A' && k <= 'Z')))
        return 0;
    return strchr(set, k | 0x20) != NULL;
}

#define ODID_LEN 25
#define ODID_PACK_MAX 9

int beeExtParse(const char *p, const char *eod, uint8_t *body, int *blen) {
    if (p + 1 >= eod)
        return 0;
    uint8_t t = (uint8_t) p[0];
    char k = p[1];
    const char *q = p + 2;
    int r, n;
    if (t == 0xED) {
        // letter A|B|X, ts6 dbm1 rep1 L onair[L]
        if (!isLetter(k, "abx"))
            return -1;
        if ((r = takeN(&q, eod, body, 9)) <= 0)
            return r;
        int L = body[8];
        if (L < 1 || L > 31)
            return -1;
        if ((r = takeN(&q, eod, body + 9, L)) <= 0)
            return r;
        n = 9 + L;
    } else if (t == 0xEF) {
        // letter B|C|E|W|N, ts6 dbm1 mac6 odid[25 | 3 + 25n]
        if (!isLetter(k, "bcewn"))
            return -1;
        if ((r = takeN(&q, eod, body, 14)) <= 0)
            return r;
        if (body[13] >> 4 == 0xF) {
            if ((r = takeN(&q, eod, body + 14, 2)) <= 0)
                return r;
            int size = body[14], count = body[15];
            if (size != ODID_LEN || count < 1 || count > ODID_PACK_MAX)
                return -1;
            if ((r = takeN(&q, eod, body + 16, ODID_LEN * count)) <= 0)
                return r;
            n = 16 + ODID_LEN * count;
        } else {
            if ((r = takeN(&q, eod, body + 14, ODID_LEN - 1)) <= 0)
                return r;
            n = 13 + ODID_LEN;
        }
    } else {
        return -1;
    }
    *blen = n;
    return q - p;
}

// --- ADS-L (EASA ADS-L 4 SRD-860 Issue 2, M-band) --------------------------------------------

uint32_t beeCrc24(const uint8_t *data, int len) {
    uint32_t crc = 0;
    for (int i = 0; i < len + 3; i++) {
        crc |= (i < len) ? data[i] : 0;
        for (int b = 0; b < 8; b++) {
            if (crc & 0x80000000u)
                crc ^= 0xFFFA0480u;
            crc <<= 1;
        }
    }
    return crc >> 8;
}

#define XXTEA_DELTA 0x9E3779B9u
#define XXTEA_MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (0 ^ z)) // key 0

void beeXxteaDecrypt(uint8_t *data, int len) {
    int n = len / 4;
    if (n < 2)
        return;
    uint32_t v[16];
    for (int i = 0; i < n; i++)
        v[i] = data[4 * i] | data[4 * i + 1] << 8 | data[4 * i + 2] << 16 | (uint32_t) data[4 * i + 3] << 24;
    uint32_t s = XXTEA_DELTA * 6, y = v[0], z;
    for (int round = 0; round < 6; round++) {
        z = v[n - 2];
        v[n - 1] -= XXTEA_MX;
        y = v[n - 1];
        for (int p = n - 2; p >= 0; p--) {
            z = p > 0 ? v[p - 1] : v[n - 1];
            v[p] -= XXTEA_MX;
            y = v[p];
        }
        s -= XXTEA_DELTA;
    }
    for (int i = 0; i < n; i++) {
        data[4 * i] = v[i];
        data[4 * i + 1] = v[i] >> 8;
        data[4 * i + 2] = v[i] >> 16;
        data[4 * i + 3] = v[i] >> 24;
    }
}

// little-endian bit fields from bit 0 up (B.3)
static uint32_t bits(const uint8_t *b, int off, int w) {
    uint32_t v = 0;
    for (int i = 0; i < w; i++)
        v |= (uint32_t) ((b[(off + i) >> 3] >> ((off + i) & 7)) & 1) << i;
    return v;
}

// exponential encoding (G.1.6)
static int expDec(uint32_t code, int n) {
    int e = code >> n, base = code & ((1 << n) - 1);
    return (1 << e) * ((1 << n) + base) - (1 << n);
}

int beeAdslDecode(const uint8_t *onair, int len, struct beeAdsl *o) {
    memset(o, 0, sizeof(*o));
    int L = onair[0];
    if (len < 1 + L || L < 4 + 5)
        return BEE_ADSL_LEN;
    const uint8_t *net = onair + 1;      // network header + data
    int netLen = L - 3;
    uint32_t crc = (uint32_t) onair[L - 2] << 16 | onair[L - 1] << 8 | onair[L];
    if (beeCrc24(net, netLen) != crc)
        return BEE_ADSL_CRC;
    uint8_t h = net[0];
    o->version = h & 15;
    o->key = (h >> 5) & 3;
    if (h >> 7)
        return BEE_ADSL_FEC;
    if (o->key != 0 && o->key != 3)
        return BEE_ADSL_KEY;
    int dlen = netLen - 1;
    if (dlen < 5 || dlen % 4 || dlen > 64)
        return BEE_ADSL_LEN;
    uint8_t d[64];
    memcpy(d, net + 1, dlen);
    if (o->key == 0)
        beeXxteaDecrypt(d, dlen);
    o->ptype = bits(d, 0, 8);
    o->amt = bits(d, 8, 6);
    o->addr = bits(d, 14, 24);
    o->relay = bits(d, 39, 1);
    if (o->ptype == 2 && dlen == 20) {
        const uint8_t *t = d + 5;
        o->traffic = 1;
        o->ts_qs = bits(t, 0, 6);
        o->fstate = bits(t, 6, 2);
        o->cat = bits(t, 8, 5);
        o->emerg = bits(t, 13, 3);
        uint32_t lat = bits(t, 16, 24), lon = bits(t, 40, 24);
        if (lat != 0x800000 && lon != 0x800000) {
            int32_t la = (lat & 0x800000) ? (int32_t) lat - (1 << 24) : (int32_t) lat;
            int32_t lo = (lon & 0x800000) ? (int32_t) lon - (1 << 24) : (int32_t) lon;
            o->lat = la / 93206.0;
            o->lon = lo / 46603.0;
            o->pos_valid = fabs(o->lat) <= 90 && fabs(o->lon) <= 180;
        }
        uint32_t gs = bits(t, 64, 8), alt = bits(t, 72, 14), vr = bits(t, 86, 9);
        if (gs != 0xFF) {
            o->gs_valid = 1;
            o->gs_mps = expDec(gs, 6) / 4.0;
        }
        if (alt != 0x3FFF) {
            o->alt_valid = 1;
            o->alt_m = expDec(alt, 12) - 320;
        }
        if (vr != 0x1FF) {
            o->vr_valid = 1;
            int v = expDec(vr & 0xFF, 6);
            o->vr_mps = ((vr >> 8) ? -v : v) / 8.0;
        }
        o->track = bits(t, 95, 9) * 360.0 / 512.0;
    }
    return BEE_ADSL_OK;
}

// ADS-L aircraft category (G.1.3) -> ADS-B emitter category (readsb: 0xA1 = A1)
static unsigned adslCategory(int cat) {
    static const uint8_t map[18] = {
        0x00, 0xA1, 0xA3, 0xA7, 0xB1, 0xB2, 0xB4, 0xB4, 0xB3, 0xA7,
        0xA7, 0xB6, 0xB6, 0xB6, 0xB6, 0xA7, 0xB4, 0xB4,
    };
    return (cat >= 0 && cat < 18) ? map[cat] : 0;
}

// int8 dBm byte -> signalLevel on the ADSBee power-byte scale (0.75 dBFS per dB, 0 dBFS at
// -40 dBm), capped at 1. Built once at startup: no pow per frame.
static double dbmLevel[256];

// tests: READSBEE_SIGNAL_LOG=<file> logs each frame's signal byte as read ("<fd> power|dbm <byte>")
static FILE *signalLog;

__attribute__((constructor)) static void initDbmLevel(void) {
    for (int b = 0; b < 256; b++) {
        int d = (int8_t) b;
        double l = pow(10, 0.075 * (d + 40));
        dbmLevel[b] = (d == -128) ? 0 : (l > 1 ? 1 : l);
    }
    const char *log = getenv("READSBEE_SIGNAL_LOG");
    if (log && *log && (signalLog = fopen(log, "a")))
        setvbuf(signalLog, NULL, _IOLBF, 0);
}

double beeSignal(const struct client *c, uint8_t b, struct beeMsg *bm) {
    if (unlikely(signalLog != NULL))
        fprintf(signalLog, "%d %s %u\n", c ? c->fd : -1,
                (c && (c->bee.capsActive & BEE_CAP_SIG_DBM)) ? "dbm" : "power", b);
    if (c && (c->bee.capsActive & BEE_CAP_SIG_DBM)) {
        if (bm) {
            bm->dbm = (int8_t) b;
            bm->hasDbm = b != 0x80;
        }
        return dbmLevel[b];
    }
    if (bm)
        bm->hasDbm = 0;
    double l = b / 255.0;
    return l * l;
}

int beeCapsFrame(struct client *c, const char *p, const char *eod, char *answer, int *answerLen) {
    *answerLen = 0;
    if (eod - p < BEE_CAPS_LEN - 1)
        return 0;
    const uint8_t *q = (const uint8_t *) p;
    char k = q[1];
    if ((k != 'Q' && k != 'A' && k != 'C') || !(q[2] & 0x80) || !(q[3] & 0x80) || !(q[4] & 0x80))
        return -1;
    uint16_t bits = (q[3] & 0x7F) | (q[4] & 0x7F) << 7;
    if (k == 'Q' && !(c->bee.capsState & BEE_CAPS_ANSWERED)) {
        // first query only: answer what this readsbee accepts
        c->bee.capsState |= BEE_CAPS_ANSWERED;
        c->bee.capsOffered = bits;
        uint16_t a = Bee.capsAccept;
        answer[0] = 0x1a;
        answer[1] = (char) 0xE5;
        answer[2] = 'A';
        answer[3] = (char) (0x80 | BEE_CAPS_VERSION);
        answer[4] = (char) (0x80 | (a & 0x7F));
        answer[5] = (char) (0x80 | ((a >> 7) & 0x7F));
        *answerLen = BEE_CAPS_LEN;
    } else if (k == 'C' && !(c->bee.capsState & BEE_CAPS_CONFIRMED)) {
        // the switch point: these bits apply from the next frame on
        c->bee.capsState |= BEE_CAPS_CONFIRMED;
        c->bee.capsActive = bits & Bee.capsAccept;
    }
    // 'A' from a feeder, a second 'Q' or 'C': ignored
    return BEE_CAPS_LEN - 1;
}

void beeUatMessage(struct client *c, struct modesMessage *mm) {
    if (c && c->bee.uatHasDbm) {
        mm->bee.dbm = c->bee.uatDbm;
        mm->bee.hasDbm = 1;
    }
}

static void countFrame(struct client *c, int type) {
    c->bee.frames[type]++;
    __atomic_add_fetch(&Bee.frames[type], 1, __ATOMIC_RELAXED);
    Modes.stats_current.bee_frames[type]++;
}

static int clockOf(char letter, int64_t ts) {
    if (letter >= 'a')
        return BEE_CLK_NOT_MLAT;
    return ts ? BEE_CLK_MODES : BEE_CLK_UNSYNCED;
}

static int64_t ts48(const uint8_t *b) {
    int64_t ts = 0;
    for (int i = 0; i < 6; i++)
        ts = ts << 8 | b[i];
    return ts;
}

static void setTiming(struct client *c, uint8_t type, int64_t ts, int clock, int64_t now) {
    if (clock == BEE_CLK_UNSYNCED && c->bee.timing.clock == BEE_CLK_MODES)
        c->bee.timing.epoch++;
    c->bee.timing.ts = ts;
    c->bee.timing.when = now;
    c->bee.timing.clock = clock;
    c->bee.timing.type = type;
}

static struct modesMessage *beeMM(struct client *c, struct messageBuffer *mb, int64_t now, const struct beeMsg *sig,
        double level) {
    struct modesMessage *mm = netGetMM(mb);
    mm->client = c;
    mm->remote = 1;
    mm->sbs_in = 1;
    mm->source = SOURCE_SBS;
    mm->addrtype = ADDR_OTHER;
    mm->receiverId = c->receiverId;
    if (unlikely(Modes.incrementId))
        mm->receiverId += now / (10 * MINUTES);
    mm->sysTimestamp = now;
    mm->signalLevel = level;
    mm->decoded_nic = 0;
    mm->decoded_rc = RC_UNKNOWN;
    mm->bee.dbm = sig->dbm;
    mm->bee.hasDbm = sig->hasDbm;
    return mm;
}

static void decodeAdslFrame(struct client *c, char letter, const uint8_t *body, int blen, int64_t now,
        struct messageBuffer *mb) {
    int64_t ts = ts48(body);
    struct beeMsg sig = { 0 };
    double level = beeSignal(c, body[6], &sig);
    struct beeAdsl a;
    if (beeAdslDecode(body + 8, blen - 8, &a) != BEE_ADSL_OK || (a.ptype == 2 && !a.traffic)) {
        countFrame(c, BEE_FT_BAD);
        return;
    }
    countFrame(c, BEE_FT_ADSL);
    int clock = clockOf(letter, ts);
    setTiming(c, 0xED, ts, clock, now);
    if (!a.traffic || !a.addr)
        return; // Status and other payloads: counted only

    struct modesMessage *mm = beeMM(c, mb, now, &sig, level);
    // AMT 5 is an ICAO address: same aircraft as its Mode S / ADS-B. Others go to the non-ICAO space.
    mm->addr = a.addr | (a.amt == 5 ? 0 : MODES_NON_ICAO_ADDRESS);
    if (a.pos_valid) {
        mm->decoded_lat = a.lat;
        mm->decoded_lon = a.lon;
        mm->sbs_pos_valid = 1;
    }
    if (a.alt_valid) {
        mm->geom_alt = (int) lround(a.alt_m / 0.3048);
        mm->geom_alt_unit = UNIT_FEET;
        mm->geom_alt_valid = 1;
    }
    if (a.gs_valid) {
        mm->gs_valid = 1;
        mm->gs.v0 = mm->gs.v2 = mm->gs.selected = a.gs_mps * 3600.0 / 1852.0;
        if (a.gs_mps > 0) {
            mm->heading_valid = 1;
            mm->heading_type = HEADING_GROUND_TRACK;
            mm->heading = a.track;
        }
    }
    if (a.vr_valid) {
        mm->geom_rate_valid = 1;
        mm->geom_rate = (int) lround(a.vr_mps / 0.3048 * 60);
    }
    if (a.fstate == 1)
        mm->airground = AG_GROUND;
    else if (a.fstate == 2)
        mm->airground = AG_AIRBORNE;
    unsigned cat = adslCategory(a.cat);
    if (cat) {
        mm->category_valid = 1;
        mm->category = cat;
    }
    static const int8_t emerg[8] = { -1, EMERGENCY_NONE, EMERGENCY_GENERAL, EMERGENCY_LIFEGUARD,
        EMERGENCY_NORDO, EMERGENCY_UNLAWFUL, EMERGENCY_DOWNED, -1 };
    if (emerg[a.emerg & 7] >= 0) {
        mm->emergency_valid = 1;
        mm->emergency = emerg[a.emerg & 7];
    }
    mm->bee.kind = 1;
    mm->bee.amt = a.amt;
    mm->bee.cat = a.cat;
    mm->bee.channel = (letter | 0x20) == 'a' ? 0 : (letter | 0x20) == 'b' ? 1 : 0xFF;
    mm->bee.clock = clock;
    mm->bee.ts = ts;
    netUseMessage(mm);
}

static void decodeRidFrame(struct client *c, char letter, const uint8_t *body, int blen, int64_t now,
        struct messageBuffer *mb) {
    int64_t ts = ts48(body);
    countFrame(c, BEE_FT_RID);
    // ts 0 (today's firmware): readsbee stamps arrival
    setTiming(c, 0xEF, ts, clockOf(letter, ts), now);
    struct beeMsg sig = { 0 };
    double level = beeSignal(c, body[6], &sig);
    beeRidInput(body + 13, blen - 13, body + 7, letter | 0x20, &sig, level,
            c->receiverId, c->receiverId2, now, mb, c);
}

static int blocked(struct client *c) {
    return c->bee.state == BEE_PENDING || c->bee.state == BEE_REJECTED;
}

int beeExtFrame(struct client *c, char *p, char *eod, int64_t now, struct messageBuffer *mb) {
    uint8_t t = (uint8_t) *p;
    if (t == 0xED || t == 0xEF) {
        uint8_t body[256];
        int blen = 0;
        int r = beeExtParse(p, eod, body, &blen);
        if (r == 0)
            return 0;
        if (r > 0) {
            beeCountExt(c, p, r);
            if (beeDrop(c))
                return r;
            if (t == 0xED)
                decodeAdslFrame(c, p[1], body, blen, now, mb);
            else
                decodeRidFrame(c, p[1], body, blen, now, mb);
            return r;
        }
    }
    // unknown type, or a known one with an unknown letter / failed bounds: skip to the next frame start
    int len = beeExtFrameLen(p, eod);
    if (len > 0) {
        beeCountExt(c, p, len);
        if ((t == 0xEC || t == 0xED || t == 0xEF) && !blocked(c))
            countFrame(c, BEE_FT_BAD);
    }
    return len;
}

int beeUatFrame(struct client *c, char letter, int64_t ts, int64_t now) {
    if (blocked(c))
        return 1; // decodeUatMessage drops and counts it
    int clock = clockOf(letter, ts);
    countFrame(c, BEE_FT_UAT);
    if (clock == BEE_CLK_MODES)
        countFrame(c, BEE_FT_UAT_MLAT);
    setTiming(c, 0xEC, ts, clock, now);
    return 1;
}

void beeTrackUpdate(struct aircraft *a, struct modesMessage *mm, int64_t now) {
    if (mm->bee.hasDbm) {
        a->bee.dbm = mm->bee.dbm;
        a->bee.dbmSeen = now;
    }
    if (mm->bee.kind == 1)
        a->bee.adslSeen = now;
    else if (mm->bee.kind == 2)
        a->bee.ridSeen = now;
    else
        return;
    a->bee.last = mm->bee;
}

char *beeJsonAircraft(char *p, char *end, struct aircraft *a, int64_t now) {
    // last level from a feed that sends dBm (rssi stays dBFS)
    if (a->bee.dbmSeen && now - a->bee.dbmSeen < 60 * SECONDS)
        p = safe_snprintf(p, end, ",\"dbm\":%d", a->bee.dbm);
    if (a->bee.adslSeen && now - a->bee.adslSeen < 60 * SECONDS) {
        const struct beeMsg *m = &a->bee.last;
        p = safe_snprintf(p, end, ",\"adsl\":{\"amt\":%u,\"cat\":%u,\"ch\":%s,\"seen\":%.1f",
                m->amt, m->cat, m->channel == 0 ? "868.2" : m->channel == 1 ? "868.4" : "null",
                (now - a->bee.adslSeen) / 1000.0);
        if (m->hasDbm)
            p = safe_snprintf(p, end, ",\"dbm\":%d", m->dbm);
        p = safe_snprintf(p, end, "}");
    }
    if (a->bee.ridSeen && now - a->bee.ridSeen < 60 * SECONDS)
        p = safe_snprintf(p, end, ",\"rid\":{\"seen\":%.1f}", (now - a->bee.ridSeen) / 1000.0);
    return p;
}

static const char *ftNames[BEE_FT_COUNT] = { "adsl", "rid", "uat", "uat_mlat", "bad" };

char *beeStatsJson(char *p, char *end, const uint32_t *frames) {
    p = safe_snprintf(p, end, ",\"readsbee\":{");
    for (int i = 0; i < BEE_FT_COUNT; i++)
        p = safe_snprintf(p, end, "%s\"%s\":%u", i ? "," : "", ftNames[i], frames[i]);
    return safe_snprintf(p, end, "}");
}

char *beeFramesJson(char *p, char *end, const uint32_t *f32, const uint64_t *f64) {
    p = safe_snprintf(p, end, "\"frames\":{");
    for (int i = 0; i < BEE_FT_COUNT; i++)
        p = safe_snprintf(p, end, "%s\"%s\":%" PRIu64, i ? "," : "", ftNames[i], f32 ? (uint64_t) f32[i] : f64[i]);
    return safe_snprintf(p, end, "}");
}

// --- Remote ID (ASTM F3411 / ASD-STAN prEN 4709-002) -----------------------------------------

#define RID_MAX 1024
#define RID_MACS 4
#define RID_RX 8
static const char *ridTransports = "bcewn";
static const char *ridTransportNames[5] = { "bt4_legacy", "bt5_coded", "bt5_ext_1m", "wifi_beacon", "wifi_nan" };

struct beeDrone {
    int used;
    char id[21];       // primary UAS ID (serial preferred)
    int idType;        // 0 none, 1 serial, 2 CAA registration, 3 UTM, 4 session ID
    char id2[21];      // second Basic ID, if any
    int id2Type;
    int uaType;
    uint8_t macs[RID_MACS][6];
    int nmacs;
    uint32_t hex;      // stable 24-bit non-ICAO address, from the ID (or the MAC before a Basic ID)
    uint8_t transports;
    uint16_t msgTypes; // bitmask of ODID message types seen
    int64_t first, seen, seenPos;
    int posValid, status;
    double lat, lon;
    float altGeo, altBaro, height, speed, vspeed, track;
    uint8_t altGeoValid, altBaroValid, heightValid, heightAgl, speedValid, vspeedValid, trackValid;
    char selfId[24];
    int selfIdType;
    char opId[21];
    int opIdType;
    double opLat, opLon;
    float opAlt;
    uint8_t opValid, opAltValid, opLocType, classType, catEU, classEU;
    int8_t dbm;
    uint8_t hasDbm;
    double level;    // signalLevel of the last frame with a level
    uint64_t msgs;
    struct { uint64_t hi, lo; int64_t t; } rx[RID_RX];
};

static struct beeDrone drones[RID_MAX];
static int dronesLen;
static pthread_mutex_t ridMutex = PTHREAD_MUTEX_INITIALIZER;

void beeRidReset(void) {
    pthread_mutex_lock(&ridMutex);
    memset(drones, 0, sizeof(drones));
    dronesLen = 0;
    pthread_mutex_unlock(&ridMutex);
}

int beeRidCount(void) {
    int n = 0;
    pthread_mutex_lock(&ridMutex);
    for (int i = 0; i < dronesLen; i++)
        n += drones[i].used;
    pthread_mutex_unlock(&ridMutex);
    return n;
}

static uint32_t hash24(const void *data, size_t len) {
    uint64_t h = fasthash64(data, len, 0x0d1d0d1d0d1d0d1dULL);
    return (uint32_t) (h ^ (h >> 24) ^ (h >> 48)) & 0xFFFFFF;
}

static void setHex(struct beeDrone *d) {
    if (d->id[0])
        d->hex = hash24(d->id, strlen(d->id));
    else
        d->hex = hash24(d->macs[0], 6);
}

static int idRank(int type) {
    static const int rank[5] = { 0, 4, 3, 1, 2 }; // serial > CAA > session > UTM > none
    return (type >= 0 && type < 5) ? rank[type] : 0;
}

// printable ASCII, trailing NUL / spaces dropped
static void odidString(char *out, const uint8_t *in, int n) {
    int len = 0;
    for (int i = 0; i < n && in[i]; i++)
        out[len++] = (in[i] >= 32 && in[i] < 127) ? in[i] : '?';
    while (len > 0 && out[len - 1] == ' ')
        len--;
    out[len] = '\0';
}

static struct beeDrone *findMac(const uint8_t *mac) {
    for (int i = 0; i < dronesLen; i++) {
        struct beeDrone *d = &drones[i];
        if (!d->used)
            continue;
        for (int j = 0; j < d->nmacs; j++)
            if (!memcmp(d->macs[j], mac, 6))
                return d;
    }
    return NULL;
}

static struct beeDrone *findId(const char *id) {
    for (int i = 0; i < dronesLen; i++) {
        struct beeDrone *d = &drones[i];
        if (d->used && ((d->id[0] && !strcmp(d->id, id)) || (d->id2[0] && !strcmp(d->id2, id))))
            return d;
    }
    return NULL;
}

static void addMac(struct beeDrone *d, const uint8_t *mac) {
    for (int j = 0; j < d->nmacs; j++)
        if (!memcmp(d->macs[j], mac, 6))
            return;
    if (d->nmacs == RID_MACS) // keep the newest: drop the oldest
        memmove(d->macs[0], d->macs[1], 6 * (RID_MACS - 1)), d->nmacs--;
    memcpy(d->macs[d->nmacs++], mac, 6);
}

static void dropMac(struct beeDrone *d, const uint8_t *mac) {
    for (int j = 0; j < d->nmacs; j++) {
        if (!memcmp(d->macs[j], mac, 6)) {
            memmove(d->macs[j], d->macs[j + 1], 6 * (d->nmacs - j - 1));
            d->nmacs--;
            return;
        }
    }
}

static struct beeDrone *newDrone(const uint8_t *mac, int64_t now) {
    struct beeDrone *d = NULL;
    for (int i = 0; i < dronesLen && !d; i++)
        if (!drones[i].used)
            d = &drones[i];
    if (!d && dronesLen < RID_MAX)
        d = &drones[dronesLen++];
    if (!d) { // full: reuse the oldest
        d = &drones[0];
        for (int i = 1; i < dronesLen; i++)
            if (drones[i].seen < d->seen)
                d = &drones[i];
    }
    memset(d, 0, sizeof(*d));
    d->used = 1;
    d->first = now;
    memcpy(d->macs[0], mac, 6);
    d->nmacs = 1;
    setHex(d);
    return d;
}

// fold an ID-less record (the MAC seen before its Basic ID) into the record with the ID
static void mergeInto(struct beeDrone *dst, struct beeDrone *src) {
    for (int j = 0; j < src->nmacs; j++)
        addMac(dst, src->macs[j]);
    if (src->seenPos > dst->seenPos) {
        dst->seenPos = src->seenPos;
        dst->posValid = src->posValid;
        dst->lat = src->lat; dst->lon = src->lon; dst->status = src->status;
        dst->altGeo = src->altGeo; dst->altGeoValid = src->altGeoValid;
        dst->altBaro = src->altBaro; dst->altBaroValid = src->altBaroValid;
        dst->height = src->height; dst->heightValid = src->heightValid; dst->heightAgl = src->heightAgl;
        dst->speed = src->speed; dst->speedValid = src->speedValid;
        dst->vspeed = src->vspeed; dst->vspeedValid = src->vspeedValid;
        dst->track = src->track; dst->trackValid = src->trackValid;
    }
    if (!dst->opValid && src->opValid) {
        dst->opValid = 1; dst->opLat = src->opLat; dst->opLon = src->opLon; dst->opLocType = src->opLocType;
        dst->opAlt = src->opAlt; dst->opAltValid = src->opAltValid;
    }
    if (!dst->selfId[0] && src->selfId[0])
        memcpy(dst->selfId, src->selfId, sizeof(dst->selfId)), dst->selfIdType = src->selfIdType;
    if (!dst->opId[0] && src->opId[0])
        memcpy(dst->opId, src->opId, sizeof(dst->opId)), dst->opIdType = src->opIdType;
    dst->transports |= src->transports;
    dst->msgTypes |= src->msgTypes;
    dst->msgs += src->msgs;
    if (src->first < dst->first)
        dst->first = src->first;
    for (int i = 0; i < RID_RX; i++) {
        if (!src->rx[i].t)
            continue;
        int slot = -1;
        for (int j = 0; j < RID_RX && slot < 0; j++)
            if (dst->rx[j].hi == src->rx[i].hi && dst->rx[j].lo == src->rx[i].lo)
                slot = j;
        for (int j = 0; j < RID_RX && slot < 0; j++)
            if (!dst->rx[j].t)
                slot = j;
        if (slot >= 0 && src->rx[i].t > dst->rx[slot].t)
            dst->rx[slot] = src->rx[i];
    }
    src->used = 0;
}

static void noteReceiver(struct beeDrone *d, uint64_t hi, uint64_t lo, int64_t now) {
    int slot = 0;
    for (int i = 0; i < RID_RX; i++) {
        if (d->rx[i].hi == hi && d->rx[i].lo == lo) {
            slot = i;
            break;
        }
        if (d->rx[i].t < d->rx[slot].t)
            slot = i;
    }
    d->rx[slot].hi = hi;
    d->rx[slot].lo = lo;
    d->rx[slot].t = now;
}

static int32_t le32(const uint8_t *b) {
    return (int32_t) (b[0] | b[1] << 8 | b[2] << 16 | (uint32_t) b[3] << 24);
}

static uint16_t le16(const uint8_t *b) {
    return b[0] | b[1] << 8;
}

static float odidAlt(uint16_t v) {
    return v * 0.5f - 1000.0f;
}

// one 25-byte message. Returns the drone, *pos = 1 if it carried a new position.
static struct beeDrone *ridMessage(const uint8_t *m, const uint8_t *mac, int64_t now, int *pos) {
    int type = m[0] >> 4;
    struct beeDrone *d = findMac(mac);

    if (type == 0) { // Basic ID
        char id[21];
        odidString(id, m + 2, 20);
        int idType = m[1] >> 4;
        if (id[0]) {
            struct beeDrone *e = findId(id);
            if (e && d && e != d) {
                if (d->id[0]) // the MAC now belongs to another drone (random BLE addresses)
                    dropMac(d, mac);
                else
                    mergeInto(e, d);
                d = e;
            } else if (e) {
                d = e;
            }
            if (!d)
                d = newDrone(mac, now);
            addMac(d, mac);
            if (strcmp(d->id, id) && strcmp(d->id2, id)) {
                if (!d->id[0] || idRank(idType) > idRank(d->idType)) {
                    if (d->id[0]) {
                        memcpy(d->id2, d->id, sizeof(d->id2));
                        d->id2Type = d->idType;
                    }
                    memcpy(d->id, id, sizeof(d->id));
                    d->idType = idType;
                    setHex(d);
                } else {
                    memcpy(d->id2, id, sizeof(d->id2));
                    d->id2Type = idType;
                }
            }
            if (!strcmp(d->id, id))
                d->uaType = m[1] & 15;
        }
    }
    if (!d)
        d = newDrone(mac, now);
    if (type <= 5)
        d->msgTypes |= 1 << type;

    if (type == 1) { // Location / Vector
        uint8_t f = m[1];
        d->status = f >> 4;
        d->heightAgl = (f >> 2) & 1;
        int ew = (f >> 1) & 1, mult = f & 1;
        float dir = m[2] + (ew ? 180 : 0);
        d->trackValid = dir <= 360;
        d->track = dir;
        float sp = mult ? m[3] * 0.75f + 255 * 0.25f : m[3] * 0.25f;
        d->speedValid = !(mult && m[3] == 255);
        d->speed = sp;
        d->vspeedValid = (int8_t) m[4] != 126;
        d->vspeed = (int8_t) m[4] * 0.5f;
        int32_t la = le32(m + 5), lo = le32(m + 9);
        double lat = la * 1e-7, lon = lo * 1e-7;
        if ((la || lo) && fabs(lat) <= 90 && fabs(lon) <= 180) {
            d->posValid = 1;
            d->lat = lat;
            d->lon = lon;
            d->seenPos = now;
            *pos = 1;
        }
        uint16_t ab = le16(m + 13), ag = le16(m + 15), ht = le16(m + 17);
        d->altBaroValid = ab != 0;
        d->altBaro = odidAlt(ab);
        d->altGeoValid = ag != 0;
        d->altGeo = odidAlt(ag);
        d->heightValid = ht != 0;
        d->height = odidAlt(ht);
    } else if (type == 3) { // Self-ID
        d->selfIdType = m[1];
        odidString(d->selfId, m + 2, 23);
    } else if (type == 4) { // System
        d->opLocType = m[1] & 3;
        d->classType = (m[1] >> 2) & 7;
        int32_t la = le32(m + 2), lo = le32(m + 6);
        double lat = la * 1e-7, lon = lo * 1e-7;
        if ((la || lo) && fabs(lat) <= 90 && fabs(lon) <= 180) {
            d->opValid = 1;
            d->opLat = lat;
            d->opLon = lon;
        }
        d->classEU = m[17] & 15;
        d->catEU = m[17] >> 4;
        uint16_t oa = le16(m + 18);
        d->opAltValid = oa != 0;
        d->opAlt = odidAlt(oa);
    } else if (type == 5) { // Operator ID
        d->opIdType = m[1];
        odidString(d->opId, m + 2, 20);
    }
    return d;
}

void beeRidInput(const uint8_t *odid, int len, const uint8_t *mac, char transport, const struct beeMsg *sig,
        double level, uint64_t rxHi, uint64_t rxLo, int64_t now, struct messageBuffer *mb, struct client *c) {
    const uint8_t *msgs = odid;
    int n = 1;
    if (odid[0] >> 4 == 0xF) {
        msgs = odid + 3;
        n = odid[2];
    }
    if (len < n * ODID_LEN)
        return;
    const char *tp = strchr(ridTransports, transport);
    int pos = 0;
    struct beeDrone snap;
    int haveSnap = 0;

    pthread_mutex_lock(&ridMutex);
    struct beeDrone *d = NULL;
    for (int i = 0; i < n; i++) {
        d = ridMessage(msgs + i * ODID_LEN, mac, now, &pos);
        d->seen = now;
        d->msgs++;
        if (level > 0) {
            d->level = level;
            d->dbm = sig->dbm;
            d->hasDbm = sig->hasDbm;
        }
        if (tp)
            d->transports |= 1 << (tp - ridTransports);
        noteReceiver(d, rxHi, rxLo, now);
    }
    if (pos && d && d->posValid && Bee.ridGlobe && mb) {
        snap = *d;
        haveSnap = 1;
    }
    pthread_mutex_unlock(&ridMutex);

    if (!haveSnap)
        return;
    // --readsbee-rid-globe: the drone as an aircraft (category B6) for tar1090
    struct modesMessage *mm = beeMM(c, mb, now, sig, level);
    mm->addr = snap.hex | MODES_NON_ICAO_ADDRESS;
    mm->decoded_lat = snap.lat;
    mm->decoded_lon = snap.lon;
    mm->sbs_pos_valid = 1;
    if (snap.altGeoValid) {
        mm->geom_alt = (int) lround(snap.altGeo / 0.3048);
        mm->geom_alt_unit = UNIT_FEET;
        mm->geom_alt_valid = 1;
    }
    if (snap.altBaroValid) {
        mm->baro_alt = (int) lround(snap.altBaro / 0.3048);
        mm->baro_alt_unit = UNIT_FEET;
        mm->baro_alt_valid = 1;
    }
    if (snap.speedValid) {
        mm->gs_valid = 1;
        mm->gs.v0 = mm->gs.v2 = mm->gs.selected = snap.speed * 3600.0 / 1852.0;
    }
    if (snap.trackValid && snap.speedValid && snap.speed > 0) {
        mm->heading_valid = 1;
        mm->heading_type = HEADING_GROUND_TRACK;
        mm->heading = snap.track;
    }
    if (snap.vspeedValid) {
        mm->geom_rate_valid = 1;
        mm->geom_rate = (int) lround(snap.vspeed / 0.3048 * 60);
    }
    if (snap.status == 1)
        mm->airground = AG_GROUND;
    else if (snap.status == 2 || snap.status == 3)
        mm->airground = AG_AIRBORNE;
    mm->category_valid = 1;
    mm->category = 0xB6;
    mm->bee.kind = 2;
    netUseMessage(mm);
}

static const char *idTypeName(int t) {
    static const char *n[5] = { "none", "serial", "caa", "utm", "session" };
    return (t >= 0 && t < 5) ? n[t] : "other";
}

static const char *statusName(int s) {
    static const char *n[5] = { "undeclared", "ground", "airborne", "emergency", "rid_failure" };
    return (s >= 0 && s < 5) ? n[s] : "other";
}

static char *jstr(char *p, char *end, const char *key, const char *s) {
    p = safe_snprintf(p, end, ",\"%s\":\"", key);
    for (; *s && p + 8 < end; s++) {
        if (*s == '"' || *s == '\\')
            *p++ = '\\';
        *p++ = *s;
    }
    return safe_snprintf(p, end, "\"");
}

static char *printDrone(char *p, char *end, struct beeDrone *d, int full, int operator, int64_t now) {
    p = safe_snprintf(p, end, "{\"hex\":\"~%06x\"", d->hex);
    if (d->id[0]) {
        p = jstr(p, end, "id", d->id);
        p = safe_snprintf(p, end, ",\"id_type\":\"%s\",\"ua_type\":%d", idTypeName(d->idType), d->uaType);
    }
    if (d->id2[0]) {
        p = jstr(p, end, "id2", d->id2);
        p = safe_snprintf(p, end, ",\"id2_type\":\"%s\"", idTypeName(d->id2Type));
    }
    p = safe_snprintf(p, end, ",\"transports\":[");
    const char *sep = "";
    for (int i = 0; i < 5; i++) {
        if (d->transports & (1 << i)) {
            p = safe_snprintf(p, end, "%s\"%s\"", sep, ridTransportNames[i]);
            sep = ",";
        }
    }
    p = safe_snprintf(p, end, "]");
    if (d->posValid) {
        p = safe_snprintf(p, end, ",\"lat\":%.7f,\"lon\":%.7f,\"seen_pos\":%.1f,\"status\":\"%s\"",
                d->lat, d->lon, (now - d->seenPos) / 1000.0, statusName(d->status));
        if (d->altGeoValid)
            p = safe_snprintf(p, end, ",\"alt_geom_m\":%.1f", d->altGeo);
        if (d->altBaroValid)
            p = safe_snprintf(p, end, ",\"alt_baro_m\":%.1f", d->altBaro);
        if (d->heightValid)
            p = safe_snprintf(p, end, ",\"height_m\":%.1f,\"height_ref\":\"%s\"", d->height, d->heightAgl ? "ground" : "takeoff");
        if (d->speedValid)
            p = safe_snprintf(p, end, ",\"gs_mps\":%.2f", d->speed);
        if (d->vspeedValid)
            p = safe_snprintf(p, end, ",\"vrate_mps\":%.1f", d->vspeed);
        if (d->trackValid)
            p = safe_snprintf(p, end, ",\"track\":%.0f", d->track);
    }
    if (d->selfId[0])
        p = jstr(p, end, "self_id", d->selfId);
    if (d->msgTypes & (1 << 4)) {
        p = safe_snprintf(p, end, ",\"class_type\":%d", d->classType);
        if (d->classType == 1)
            p = safe_snprintf(p, end, ",\"eu_category\":%d,\"eu_class\":%d", d->catEU, d->classEU);
    }
    if (operator) {
        if (d->opValid) {
            static const char *lt[4] = { "takeoff", "live", "fixed", "other" };
            p = safe_snprintf(p, end, ",\"operator\":{\"lat\":%.7f,\"lon\":%.7f,\"loc_type\":\"%s\"",
                    d->opLat, d->opLon, lt[d->opLocType & 3]);
            if (d->opAltValid)
                p = safe_snprintf(p, end, ",\"alt_geom_m\":%.1f", d->opAlt);
            p = safe_snprintf(p, end, "}");
        }
        if (d->opId[0])
            p = jstr(p, end, "operator_id", d->opId);
    }
    if (d->level > 0)
        p = safe_snprintf(p, end, ",\"rssi\":%.1f", 10 * log10(d->level));
    if (d->hasDbm)
        p = safe_snprintf(p, end, ",\"dbm\":%d", d->dbm);
    int nrx = 0;
    for (int i = 0; i < RID_RX; i++)
        nrx += d->rx[i].t && now - d->rx[i].t < Bee.ridTimeout;
    p = safe_snprintf(p, end, ",\"messages\":%" PRIu64 ",\"seen\":%.1f,\"first\":%.0f,\"receivers\":%d",
            d->msgs, (now - d->seen) / 1000.0, d->first / 1000.0, nrx);
    if (full) {
        p = safe_snprintf(p, end, ",\"macs\":[");
        for (int j = 0; j < d->nmacs; j++) {
            const uint8_t *m = d->macs[j];
            p = safe_snprintf(p, end, "%s\"%02x:%02x:%02x:%02x:%02x:%02x\"", j ? "," : "", m[0], m[1], m[2], m[3], m[4], m[5]);
        }
        p = safe_snprintf(p, end, "],\"uuids\":[");
        sep = "";
        for (int i = 0; i < RID_RX; i++) {
            if (!d->rx[i].t || now - d->rx[i].t >= Bee.ridTimeout)
                continue;
            char uuid[64];
            sprint_uuid(d->rx[i].hi, d->rx[i].lo, uuid);
            p = safe_snprintf(p, end, "%s\"%s\"", sep, uuid);
            sep = ",";
        }
        p = safe_snprintf(p, end, "]");
    }
    return safe_snprintf(p, end, "}");
}

int beeRidJson(char **out, int *outLen, int pad, int public, uint64_t filter_uuid, int64_t now) {
    int operator = !public || Bee.ridOperator;
    pthread_mutex_lock(&ridMutex);
    size_t alloc = pad + 256 + (size_t) dronesLen * 1400;
    char *buf = cmalloc(alloc);
    if (!buf) {
        pthread_mutex_unlock(&ridMutex);
        return 0;
    }
    char *p = buf + pad, *end = buf + alloc;
    p = safe_snprintf(p, end, "{\"now\":%.3f,\"operator\":%s,\"drones\":[", now / 1000.0, operator ? "true" : "false");
    const char *sep = "\n";
    for (int i = 0; i < dronesLen; i++) {
        struct beeDrone *d = &drones[i];
        if (!d->used || now - d->seen >= Bee.ridTimeout)
            continue;
        if (filter_uuid) {
            int match = 0;
            for (int j = 0; j < RID_RX; j++)
                match |= d->rx[j].t && d->rx[j].hi == filter_uuid && now - d->rx[j].t < Bee.ridTimeout;
            if (!match)
                continue;
        }
        p = safe_snprintf(p, end, "%s", sep);
        p = printDrone(p, end, d, !public, operator, now);
        sep = ",\n";
    }
    pthread_mutex_unlock(&ridMutex);
    p = safe_snprintf(p, end, "\n]}\n");
    *out = buf;
    *outLen = p - buf;
    return 1;
}

int beeApiRemoteId(uint64_t filter_uuid, int pad, char **buf, int *len) {
    return beeRidJson(buf, len, pad, 1, filter_uuid, mstime());
}

void beeWriteRemoteId(int64_t now) {
    static int64_t next;
    if (now < next)
        return;
    next = now + 2 * SECONDS;

    pthread_mutex_lock(&ridMutex);
    for (int i = 0; i < dronesLen; i++) {
        if (drones[i].used && now - drones[i].seen > 2 * Bee.ridTimeout)
            drones[i].used = 0;
    }
    while (dronesLen > 0 && !drones[dronesLen - 1].used)
        dronesLen--;
    pthread_mutex_unlock(&ridMutex);

    char *buf;
    int len;
    if (Modes.json_dir && beeRidJson(&buf, &len, 0, 1, 0, now)) {
        struct char_buffer cb = { .buffer = buf, .len = len };
        free(writeJsonToFile(Modes.json_dir, "remoteid.json", cb).buffer);
    }
    if (Bee.statusDir && beeRidJson(&buf, &len, 0, 0, 0, now)) {
        struct char_buffer cb = { .buffer = buf, .len = len };
        free(writeJsonToFile(Bee.statusDir, "remoteid-full.json", cb).buffer);
    }
}
