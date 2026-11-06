// Part of readsbee, a fork of readsb. GPL-3.0-or-later, see COPYING.
// Unit tests for the UUID filter: make beetest

#include "readsb.h"

struct _Modes Modes;
struct _Threads Threads;

void setExit(int arg) {
    fprintf(stderr, "setExit(%d)\n", arg);
    exit(2);
}

// json output isn't tested here
struct char_buffer writeJsonToFile(const char *dir, const char *file, struct char_buffer cb) {
    MODES_NOTUSED(dir); MODES_NOTUSED(file);
    return cb;
}

// captured instead of going to the tracker
static struct messageBuffer testMb;
static struct modesMessage testMsgs[64];
static int testUsed;

struct modesMessage *netGetMM(struct messageBuffer *buf) {
    MODES_NOTUSED(buf);
    struct modesMessage *mm = &testMsgs[testUsed % 64];
    memset(mm, 0, sizeof(*mm));
    return mm;
}

void netUseMessage(struct modesMessage *mm) {
    MODES_NOTUSED(mm);
    testUsed++;
}

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static const int64_t NOW = 1793836800000LL; // 2026-11-05

// test UUIDs: the example policy accepts the prefix "ab"
#define OK1   "ab000000-0000-0000-0000-000000000001"
#define OK2   "ab000000-0000-0000-0000-000000000002"
#define OK3   "ab000000-0000-0000-0000-000000000003"
#define OTHER "cd000000-0000-0000-0000-000000000004"

static void writeFile(const char *path, const char *text) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    fputs(text, f);
    fclose(f);
    rename(tmp, path); // atomic replace, like the website does
}

static void testParse(void) {
    uint64_t hi, lo;
    CHECK(beeParseUuid("0123abcd-0123-4567-89ab-0123456789ab", &hi, &lo));
    CHECK(hi == 0x0123abcd01234567ULL && lo == 0x89ab0123456789abULL);
    CHECK(beeParseUuid("0123ABCD0123456789AB0123456789AB", &hi, &lo));
    CHECK(!beeParseUuid("0123abcd-0123-4567-89ab-0123456789a", &hi, &lo));   // short
    CHECK(!beeParseUuid("0123abcd-0123-4567-89ab-0123456789abc", &hi, &lo)); // long
    CHECK(!beeParseUuid("0123abcd-0123-4567-89ab-0123456789xx", &hi, &lo));  // not hex
    CHECK(!beeParseUuid("", &hi, &lo));
}

static void testLists(const char *dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/allow.txt", dir);
    struct beeList l = { .f.path = path };
    uint64_t hi, lo;

    unlink(path);
    CHECK(beeListLoad(&l, 1) == 1 && l.len == 0); // missing = empty
    CHECK(beeListLoad(&l, 0) == 0);

    writeFile(path, "# approved stations\n"
            OTHER "  # a station\n"
            "\n   AB000000-0000-0000-0000-000000000001\n"
            "not-a-uuid\n"
            OTHER "\n"); // duplicate
    CHECK(beeListLoad(&l, 0) == 1);
    CHECK(l.len == 2);
    beeParseUuid(OTHER, &hi, &lo);
    CHECK(beeListContains(&l, hi, lo));
    beeParseUuid(OK1, &hi, &lo);
    CHECK(beeListContains(&l, hi, lo));
    CHECK(beeListLoad(&l, 0) == 0); // unchanged

    // change within the same second
    writeFile(path, OTHER "\n");
    CHECK(beeListLoad(&l, 0) == 1);
    CHECK(l.len == 1 && !beeListContains(&l, hi, lo));

    unlink(path);
    CHECK(beeListLoad(&l, 0) == 1 && l.len == 0);
    free(l.ids);
}

static void testLoopback(void) {
    CHECK(beeIsLoopback("127.0.0.1"));
    CHECK(beeIsLoopback("127.1.2.3"));
    CHECK(beeIsLoopback("::1"));
    CHECK(beeIsLoopback("::ffff:127.0.0.1"));
    CHECK(beeIsLoopback("/run/readsb/beast.sock"));
    CHECK(!beeIsLoopback("172.17.0.1"));
    CHECK(!beeIsLoopback("10.42.1.104"));
    CHECK(!beeIsLoopback("::ffff:10.0.0.1"));
    CHECK(!beeIsLoopback("1270.0.0.1"));
    CHECK(!beeIsLoopback(""));
    CHECK(beeProxyIsLoopback("TCP4 127.0.0.1 127.0.0.1 40223 30004"));
    CHECK(!beeProxyIsLoopback("TCP4 172.12.2.132 172.191.123.45 40223 30004"));
    CHECK(!beeProxyIsLoopback("garbage"));
}

static struct net_service beastIn = { .descr = "Beast TCP input", .read_mode = READ_MODE_BEAST };
static struct net_service sbsIn = { .descr = "SBS TCP input", .read_mode = READ_MODE_ASCII };

static void mkClient(struct client *c, struct net_service *s, const char *host) {
    memset(c, 0, sizeof(*c));
    c->service = s;
    strcpy(c->host, host);
    snprintf(c->proxy_string, sizeof(c->proxy_string), "%s port 1234", host);
    c->connectedSince = NOW;
    beeClientAccept(c, NOW);
}

static void giveUuid(struct client *c, const char *uuid) {
    beeParseUuid(uuid, &c->receiverId, &c->receiverId2);
    c->receiverIdLocked = 1;
    beeClientUuid(c, NOW);
}

static int pollNow(void) {
    Bee.next_poll = 0;
    return beePoll(NOW);
}

static void testClients(const char *dir, const char *plugin) {
    char allow[512], deny[512], conf[512];
    snprintf(allow, sizeof(allow), "%s/a.txt", dir);
    snprintf(deny, sizeof(deny), "%s/d.txt", dir);
    snprintf(conf, sizeof(conf), "%s/readsbee.conf", dir);
    writeFile(allow, "\n");
    writeFile(deny, OK3 "\n");
    writeFile(conf, "policy_arg = ab\nmax_sources = 2\nreuse_action = reject\n");
    Bee.require = 1;
    Bee.policyPath = (char *) plugin;
    Bee.allow.f.path = allow;
    Bee.deny.f.path = deny;
    Bee.config.path = conf;
    beeInit();
    CHECK(Bee.policyCheck != NULL);
    CHECK(Bee.deny.len == 1 && Bee.maxSources == 2 && Bee.reuseReject == 1);

    struct client c;

    // loopback exempt (mlathub to localhost:30004)
    mkClient(&c, &beastIn, "127.0.0.1");
    CHECK(c.bee.state == BEE_EXEMPT);
    CHECK(!beeDrop(&c));
    CHECK(!beeTimedOut(&c, NOW + 60 * SECONDS));
    // ... unless a PROXY header names a remote peer
    strcpy(c.proxy_string, "TCP4 203.0.113.9 127.0.0.1 40223 30004");
    beeClientProxy(&c);
    CHECK(c.bee.state == BEE_PENDING);

    // other input types untouched
    mkClient(&c, &sbsIn, "203.0.113.9");
    CHECK(c.bee.state == BEE_OFF);

    // pending: data dropped, closed after the timeout
    mkClient(&c, &beastIn, "203.0.113.9");
    CHECK(c.bee.state == BEE_PENDING);
    CHECK(beeDrop(&c));
    CHECK(!beeTimedOut(&c, NOW + 14 * SECONDS));
    CHECK(beeTimedOut(&c, NOW + 15 * SECONDS));

    // policy accepts
    struct client a;
    mkClient(&a, &beastIn, "203.0.113.1");
    giveUuid(&a, OK1);
    CHECK(a.bee.state == BEE_OK && !beeDrop(&a));

    // policy rejects, code kept for staff
    struct client f;
    mkClient(&f, &beastIn, "198.51.100.7");
    giveUuid(&f, OTHER);
    CHECK(f.bee.state == BEE_REJECTED && f.bee.reason == BEE_R_POLICY && f.bee.code == 1);
    CHECK(beeDrop(&f));
    CHECK(Bee.rejected_conn[BEE_R_POLICY] == 1);

    // denied, even though the policy would accept it
    struct client d;
    mkClient(&d, &beastIn, "203.0.113.3");
    giveUuid(&d, OK3);
    CHECK(d.bee.state == BEE_REJECTED && d.bee.reason == BEE_R_DENIED);
    beeClientClose(&d);

    // live allow edit accepts the rejected one without a reconnect
    writeFile(allow, OTHER "\n");
    CHECK(pollNow() == 1);
    CHECK(beeEvaluate(&f, NOW) == 1);
    CHECK(f.bee.state == BEE_OK && !beeDrop(&f));

    // deny wins over allow
    writeFile(deny, OTHER "\n");
    CHECK(pollNow() == 1);
    CHECK(beeEvaluate(&f, NOW) == 1);
    CHECK(f.bee.state == BEE_REJECTED && f.bee.reason == BEE_R_DENIED);

    // previously denied UUID is accepted after the deny edit
    mkClient(&d, &beastIn, "203.0.113.3");
    giveUuid(&d, OK3);
    CHECK(d.bee.state == BEE_OK);

    // reuse limit: 2 sources per UUID, a third address is rejected
    struct client r1, r2, r3, r4;
    mkClient(&r1, &beastIn, "192.0.2.1");
    giveUuid(&r1, OK2);
    mkClient(&r2, &beastIn, "192.0.2.2");
    giveUuid(&r2, OK2);
    mkClient(&r4, &beastIn, "192.0.2.2"); // same address again: not a new source
    giveUuid(&r4, OK2);
    CHECK(r1.bee.state == BEE_OK && r2.bee.state == BEE_OK && r4.bee.state == BEE_OK);
    CHECK(beeReuseCount(r1.receiverId, r1.receiverId2) == 2);
    mkClient(&r3, &beastIn, "192.0.2.3");
    giveUuid(&r3, OK2);
    CHECK(r3.bee.state == BEE_REJECTED && r3.bee.reason == BEE_R_REUSE);
    CHECK(beeReuseCount(r1.receiverId, r1.receiverId2) == 2);
    // one source leaves (both of its connections): room again
    beeClientClose(&r2);
    CHECK(beeReuseCount(r1.receiverId, r1.receiverId2) == 2);
    beeClientClose(&r4);
    CHECK(beeReuseCount(r1.receiverId, r1.receiverId2) == 1);
    beeClientClose(&r3);
    mkClient(&r3, &beastIn, "192.0.2.3");
    giveUuid(&r3, OK2);
    CHECK(r3.bee.state == BEE_OK);

    // a local proxy's PROXY header source counts, not the proxy's address
    struct client p1;
    mkClient(&p1, &beastIn, "127.0.0.1");
    strcpy(p1.proxy_string, "TCP4 192.0.2.9 10.0.0.1 40000 30004");
    beeClientProxy(&p1);
    CHECK(p1.bee.state == BEE_PENDING);
    giveUuid(&p1, OK2);
    CHECK(p1.bee.state == BEE_REJECTED && p1.bee.reason == BEE_R_REUSE);

    // a remote peer's PROXY header is ignored: no exemption, its own address counts
    struct client p2;
    mkClient(&p2, &beastIn, "192.0.2.1");
    strcpy(p2.proxy_string, "TCP4 127.0.0.1 10.0.0.1 40000 30004");
    beeClientProxy(&p2);
    CHECK(p2.bee.state == BEE_PENDING);
    giveUuid(&p2, OK2);
    CHECK(p2.bee.state == BEE_OK); // same source as r1
    beeClientClose(&p2);

    // flag instead of reject, via a config reload
    writeFile(conf, "policy_arg = ab\nmax_sources = 2\nreuse_action = flag\n");
    CHECK(pollNow() == 1 && Bee.reuseReject == 0);
    struct client r5;
    mkClient(&r5, &beastIn, "192.0.2.5");
    giveUuid(&r5, OK2);
    CHECK(r5.bee.state == BEE_OK && r5.bee.flagged && Bee.reuse_flagged == 1);
    CHECK(beeReuseCount(r1.receiverId, r1.receiverId2) == 3);

    // policy_arg reload reaches the plugin
    writeFile(conf, "policy_arg = cd\n");
    CHECK(pollNow() == 1 && Bee.maxSources == 0);
    writeFile(deny, "\n");
    writeFile(allow, "\n");
    pollNow();
    struct client q;
    mkClient(&q, &beastIn, "198.51.100.8");
    giveUuid(&q, OTHER);
    CHECK(q.bee.state == BEE_OK);
    CHECK(beeEvaluate(&a, NOW) == 1); // OK1 no longer passes the policy
    CHECK(a.bee.state == BEE_REJECTED && a.bee.reason == BEE_R_POLICY);

    // filter off: nothing changes
    Bee.require = 0;
    Bee.deny.f.path = NULL;
    mkClient(&c, &beastIn, "203.0.113.9");
    CHECK(c.bee.state == BEE_OFF && !beeDrop(&c));
    giveUuid(&c, OTHER);
    CHECK(c.bee.state == BEE_OFF);

    unlink(allow);
    unlink(deny);
    unlink(conf);
}

static void testExtFrames(void) {
    // p points at the type byte (after 0x1a)
    const char a[] = { (char) 0xEE, 0x03, 0x01, 0x11, 0x22, 0x1a, '3' };
    CHECK(beeExtFrameLen(a, a + sizeof(a)) == 5);

    // escaped 0x1a inside the body
    const char b[] = { (char) 0xEE, 0x03, 0x02, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, '2' };
    CHECK(beeExtFrameLen(b, b + sizeof(b)) == 7);

    // split over two reads: wait
    CHECK(beeExtFrameLen(b, b + 4) == 0);
    CHECK(beeExtFrameLen(b, b + 6) == 0); // trailing 0x1a: escape or frame start?
    CHECK(beeExtFrameLen(a, a + 5) == 0); // no next frame yet

    // too long
    char big[BEE_EXT_MAX_LEN + 10];
    memset(big, 0x55, sizeof(big));
    big[0] = (char) 0xE9;
    CHECK(beeExtFrameLen(big, big + sizeof(big)) == -1);
    big[BEE_EXT_MAX_LEN + 5] = 0x1a;
    big[BEE_EXT_MAX_LEN + 6] = '3';
    CHECK(beeExtFrameLen(big, big + sizeof(big)) == -1);

    // counted per type and 0xEE subtype, a LEN byte of 0x1a is escaped
    struct client c;
    memset(&c, 0, sizeof(c));
    const char e[] = { (char) 0xEE, 0x1a, 0x1a, 0x02, 0x00 };
    beeCountExt(&c, e, sizeof(e));
    beeCountExt(&c, a, 5);
    const char i9[] = { (char) 0xE9, 0x00 };
    beeCountExt(&c, i9, sizeof(i9));
    CHECK(c.bee.ext[0xEE - BEE_EXT_FIRST] == 2);
    CHECK(c.bee.ext[0xE9 - BEE_EXT_FIRST] == 1);
    CHECK(c.bee.ee[0x02] == 1 && c.bee.ee[0x01] == 1);
}

// --- v2 frames ---

struct feedVec { const char *name; const char *wire; int len; int type; const char *kind; char letter; int64_t ts; int sig; int dbmMode; int unknown; };
struct capsVec { const char *name; const char *wire; int valid; char letter; int bits; };
struct adslVec { const char *name; const char *pkt; int len; int crc_ok; int ptype; int amt; uint32_t addr; int cat; int fstate;
    double lat, lon, alt, gs, vrate, track; };
struct odidVec { const char *name; const char *msg; int len; const char *id; int idType; int uaType; int loc; int status;
    double lat, lon, altGeo, altBaro, height; int heightType; double gs, vrate, track; const char *selfId;
    int sys; double opLat, opLon, opAlt; int opLocType; const char *opId; };
#include "tests/bee_vectors.h"

#define NEAR(a, b, eps) (fabs((a) - (b)) <= (eps))

static void testFeedVectors(void) {
    uint8_t body[256];
    int blen;
    for (size_t i = 0; i < sizeof(feedVecs) / sizeof(feedVecs[0]); i++) {
        const struct feedVec *v = &feedVecs[i];
        const char *p = v->wire + 1; // type byte
        const char *eod = v->wire + v->len;
        if (v->type != 0xED && v->type != 0xEF)
            continue;
        int r = beeExtParse(p, eod, body, &blen);
        CHECK(r == v->len - 1);
        if (r != v->len - 1)
            fprintf(stderr, "  vector %s: %d\n", v->name, r);
        int64_t ts = 0;
        for (int j = 0; j < 6; j++)
            ts = ts << 8 | body[j];
        CHECK(ts == v->ts);
        CHECK(body[6] == v->sig);
        // the signal byte follows the connection's mode (v3.2): dBm only after 'C' with bit 0
        struct client c;
        memset(&c, 0, sizeof(c));
        c.bee.capsActive = v->dbmMode ? BEE_CAP_SIG_DBM : 0;
        struct beeMsg bm = { 0 };
        double l = beeSignal(&c, body[6], &bm);
        CHECK(v->dbmMode ? (bm.hasDbm == (v->sig != 0x80) && NEAR(l, dbmLevels[v->sig], 1e-12))
                         : (!bm.hasDbm && NEAR(l, (v->sig / 255.0) * (v->sig / 255.0), 1e-12)));
        // every shorter read is incomplete, never bad
        for (int n = 1; n < v->len - 1; n++)
            CHECK(beeExtParse(p, p + n, body, &blen) == 0);
    }

    // unknown type / unknown letter: that frame only is skipped, the Mode S frame after it stays
    for (size_t i = 0; i < sizeof(feedVecs) / sizeof(feedVecs[0]); i++) {
        const struct feedVec *v = &feedVecs[i];
        if (!v->unknown)
            continue;
        struct client c;
        memset(&c, 0, sizeof(c));
        char *buf = (char *) v->wire;
        int len = beeExtFrame(&c, buf + 1, buf + v->len, NOW, &testMb);
        CHECK(len > 0 && buf[1 + len] == 0x1a && buf[2 + len] == '2');
        CHECK(v->len - (1 + len) == 16); // 0x1a 0x32 ts6 rssi1 msg7, no escapes in the tail
        int bad = (strcmp(v->name, "unknown_uat_letter") == 0);
        CHECK((int) c.bee.frames[BEE_FT_BAD] == bad);
    }

    // bounds: L 0 / 32, pack size != 25, count 0 / 10, unknown letter
    const char l32[] = { (char) 0xED, 'A', 0, 0, 0, 0, 0, 0, (char) 0x94, 0, 32 };
    CHECK(beeExtParse(l32, l32 + sizeof(l32), body, &blen) == -1);
    const char l0[] = { (char) 0xED, 'B', 0, 0, 0, 0, 0, 0, (char) 0x94, 0, 0 };
    CHECK(beeExtParse(l0, l0 + sizeof(l0), body, &blen) == -1);
    const char q[] = { (char) 0xED, 'Q', 0 };
    CHECK(beeExtParse(q, q + sizeof(q), body, &blen) == -1);
    char pk[] = { (char) 0xEF, 'W', 0, 0, 0, 0, 0, 0, (char) 0xc4, 1, 2, 3, 4, 5, 6, (char) 0xF2, 24, 3 };
    CHECK(beeExtParse(pk, pk + sizeof(pk), body, &blen) == -1);
    pk[16] = 25; pk[17] = 0;
    CHECK(beeExtParse(pk, pk + sizeof(pk), body, &blen) == -1);
    pk[17] = 10;
    CHECK(beeExtParse(pk, pk + sizeof(pk), body, &blen) == -1);
    pk[17] = 9;
    CHECK(beeExtParse(pk, pk + sizeof(pk), body, &blen) == 0); // fine, wants 225 more bytes
    pk[1] = 'z';
    CHECK(beeExtParse(pk, pk + sizeof(pk), body, &blen) == -1);
}

static void testCaps(void) {
    for (size_t i = 0; i < sizeof(capsVecs) / sizeof(capsVecs[0]); i++) {
        const struct capsVec *v = &capsVecs[i];
        struct client c;
        memset(&c, 0, sizeof(c));
        char answer[BEE_CAPS_LEN];
        int alen = -1;
        int r = beeCapsFrame(&c, v->wire + 1, v->wire + 6, answer, &alen);
        if (!v->valid) {
            CHECK(r == -1 && alen == 0 && c.bee.capsState == 0);
            continue;
        }
        CHECK(r == 5);
        for (int n = 1; n < 5; n++) // shorter: incomplete
            CHECK(beeCapsFrame(&c, v->wire + 1, v->wire + 1 + n, answer, &alen) == 0);
        if (v->letter == 'Q') {
            // answered once, with every known bit by default: 1a e5 41 81 8f 80
            CHECK(c.bee.capsOffered == v->bits && c.bee.capsActive == 0);
            int a2;
            CHECK(beeCapsFrame(&c, v->wire + 1, v->wire + 6, answer, &a2) == 5 && a2 == 0);
        } else if (v->letter == 'C') {
            CHECK(c.bee.capsActive == (v->bits & BEE_CAP_KNOWN) && (c.bee.capsState & BEE_CAPS_CONFIRMED));
        } else {
            CHECK(c.bee.capsState == 0 && c.bee.capsActive == 0); // 'A' from a feeder: ignored
        }
    }
    struct client c;
    memset(&c, 0, sizeof(c));
    char answer[BEE_CAPS_LEN];
    int alen;
    const char q[] = { 0x1a, (char) 0xE5, 'Q', (char) 0x81, (char) 0x8F, (char) 0x80 };
    CHECK(beeCapsFrame(&c, q + 1, q + 6, answer, &alen) == 5 && alen == 6
          && memcmp(answer, "\x1a\xe5\x41\x81\x8f\x80", 6) == 0);
    // --readsbee-caps narrows the answer and the confirmed bits
    memset(&c, 0, sizeof(c));
    Bee.capsAccept = BEE_CAP_RID;
    CHECK(beeCapsFrame(&c, q + 1, q + 6, answer, &alen) == 5 && memcmp(answer, "\x1a\xe5\x41\x81\x84\x80", 6) == 0);
    const char cf[] = { 0x1a, (char) 0xE5, 'C', (char) 0x81, (char) 0x8F, (char) 0x80 };
    CHECK(beeCapsFrame(&c, cf + 1, cf + 6, answer, &alen) == 5 && alen == 0 && c.bee.capsActive == BEE_CAP_RID);
    Bee.capsAccept = BEE_CAP_KNOWN;
    // a second 'C' changes nothing
    const char c0[] = { 0x1a, (char) 0xE5, 'C', (char) 0x81, (char) 0x80, (char) 0x80 };
    CHECK(beeCapsFrame(&c, c0 + 1, c0 + 6, answer, &alen) == 5 && c.bee.capsActive == BEE_CAP_RID);

    // dBm table: every byte as readsbee_proto.signal_level_from_dbm; no connection = power byte
    memset(&c, 0, sizeof(c));
    c.bee.capsActive = BEE_CAP_SIG_DBM;
    int bad = 0;
    for (int b = 0; b < 256; b++) {
        bad += !NEAR(beeSignal(&c, b, NULL), dbmLevels[b], 1e-12);
        bad += !NEAR(beeSignal(NULL, b, NULL), (b / 255.0) * (b / 255.0), 1e-15);
    }
    CHECK(bad == 0);
}

static void testAdsl(void) {
    // spec examples
    // CRC over network header + data; key 3 is sent in clear, key 0 scrambled (XXTEA round trip)
    uint8_t w[20];
    for (int j = 0; j < 20; j++)
        w[j] = j * 13;
    CHECK(beeCrc24(w, 0) == 0);

    for (size_t i = 0; i < sizeof(adslVecs) / sizeof(adslVecs[0]); i++) {
        const struct adslVec *v = &adslVecs[i];
        int before = fails;
        struct beeAdsl a;
        int r = beeAdslDecode((const uint8_t *) v->pkt, v->len, &a);
        if (!v->crc_ok) {
            CHECK(r == BEE_ADSL_CRC);
            continue;
        }
        CHECK(r == BEE_ADSL_OK);
        if (r != BEE_ADSL_OK) {
            fprintf(stderr, "  vector %s: %d\n", v->name, r);
            continue;
        }
        CHECK(a.ptype == v->ptype && a.amt == v->amt && a.addr == v->addr);
        if (v->ptype != 2) {
            CHECK(!a.traffic);
            continue;
        }
        CHECK(a.traffic && a.cat == v->cat && a.fstate == v->fstate);
        CHECK(isnan(v->lat) ? !a.pos_valid : (a.pos_valid && NEAR(a.lat, v->lat, 1e-9) && NEAR(a.lon, v->lon, 1e-9)));
        CHECK(isnan(v->alt) ? !a.alt_valid : (a.alt_valid && a.alt_m == (int) v->alt));
        CHECK(isnan(v->gs) ? !a.gs_valid : (a.gs_valid && NEAR(a.gs_mps, v->gs, 1e-9)));
        CHECK(isnan(v->vrate) ? !a.vr_valid : (a.vr_valid && NEAR(a.vr_mps, v->vrate, 1e-9)));
        CHECK(NEAR(a.track, v->track, 1e-9));
        if (fails != before)
            fprintf(stderr, "  vector %s\n", v->name);
    }

    // a real packet in an 0xED frame -> one aircraft message, address by AMT, nothing else
    const struct adslVec *v = &adslVecs[0];
    char frame[128];
    int n = 0;
    frame[n++] = (char) 0xED;
    frame[n++] = 'B';
    const uint8_t hdr[] = { 0x00, 0x00, 0x01, 0x1a, 0x00, 0x05, (uint8_t) -87, 2 };
    for (size_t j = 0; j < sizeof(hdr); j++) {
        frame[n++] = hdr[j];
        if (hdr[j] == 0x1a)
            frame[n++] = 0x1a;
    }
    for (int j = 0; j < v->len; j++) {
        frame[n++] = v->pkt[j];
        if ((uint8_t) v->pkt[j] == 0x1a)
            frame[n++] = 0x1a;
    }
    frame[n] = 0x1a;
    frame[n + 1] = '3';
    struct client c;
    memset(&c, 0, sizeof(c));
    c.receiverId = 0xbee0003ca8bd5d38ULL;
    // no confirmed bit 0: the signal byte a9 is a power byte
    testUsed = 0;
    CHECK(beeExtFrame(&c, frame, frame + n + 2, NOW, &testMb) == n);
    CHECK(testUsed == 1 && !testMsgs[0].bee.hasDbm && NEAR(testMsgs[0].signalLevel, (169 / 255.0) * (169 / 255.0), 1e-12));
    // after 'C' with bit 0: int8 dBm
    memset(&c.bee.frames, 0, sizeof(c.bee.frames));
    c.bee.capsActive = BEE_CAP_SIG_DBM;
    testUsed = 0;
    CHECK(beeExtFrame(&c, frame, frame + n + 2, NOW, &testMb) == n);
    CHECK(testUsed == 1 && c.bee.frames[BEE_FT_ADSL] == 1 && c.bee.frames[BEE_FT_BAD] == 0);
    struct modesMessage *mm = &testMsgs[0];
    CHECK(mm->addr == 0xBEE000); // AMT 5: ICAO
    CHECK(mm->bee.kind == 1 && mm->bee.amt == 5 && mm->bee.channel == 1 && mm->bee.hasDbm && mm->bee.dbm == -87);
    CHECK(NEAR(mm->signalLevel, pow(10, 0.075 * (-87 + 40)), 1e-12));
    CHECK(mm->bee.clock == BEE_CLK_MODES && mm->bee.ts == 0x0000011a0005LL);
    CHECK(mm->sbs_in && mm->sbs_pos_valid && NEAR(mm->decoded_lat, v->lat, 1e-9));
    CHECK(mm->geom_alt_valid && mm->geom_alt == 3281 && mm->category_valid && mm->category == 0xA1);
    CHECK(mm->addrtype == ADDR_OTHER && mm->receiverId == c.receiverId);
    CHECK(c.bee.timing.type == 0xED && c.bee.timing.clock == BEE_CLK_MODES);

    // lower case: not MLAT; pending connection: dropped, not decoded
    frame[1] = 'b';
    testUsed = 0;
    beeExtFrame(&c, frame, frame + n + 2, NOW, &testMb);
    CHECK(testMsgs[0].bee.clock == BEE_CLK_NOT_MLAT);
    c.bee.state = BEE_PENDING;
    testUsed = 0;
    CHECK(beeExtFrame(&c, frame, frame + n + 2, NOW, &testMb) == n);
    CHECK(testUsed == 0 && c.bee.dropped == 1 && c.bee.frames[BEE_FT_ADSL] == 2);

    // UAT clock flags
    memset(&c, 0, sizeof(c));
    beeUatFrame(&c, 's', 12345, NOW);
    beeUatFrame(&c, 'S', 0, NOW);
    beeUatFrame(&c, 'L', 777, NOW);
    CHECK(c.bee.frames[BEE_FT_UAT] == 3 && c.bee.frames[BEE_FT_UAT_MLAT] == 1);
    CHECK(c.bee.timing.clock == BEE_CLK_MODES && c.bee.timing.ts == 777 && c.bee.timing.epoch == 0);
    beeUatFrame(&c, 'S', 0, NOW); // mode switch: ts 0 again -> new clock epoch
    beeUatFrame(&c, 'S', 5, NOW);
    CHECK(c.bee.timing.epoch == 1 && c.bee.timing.clock == BEE_CLK_MODES);
}

static int jsonHas(const char *json, const char *needle) {
    int ok = strstr(json, needle) != NULL;
    if (!ok)
        fprintf(stderr, "  missing %s\n", needle);
    return ok;
}

static void testRemoteId(void) {
    const uint8_t mac[6] = { 0xc0, 0xff, 0xee, 0x1a, 0x00, 0x01 };
    char want[256];
    char *buf;
    int len;
    for (size_t i = 0; i < sizeof(odidVecs) / sizeof(odidVecs[0]); i++) {
        const struct odidVec *v = &odidVecs[i];
        int before = fails;
        beeRidReset();
        beeRidInput((const uint8_t *) v->msg, v->len, mac, 'w', &(struct beeMsg) { .dbm = -60, .hasDbm = 1 }, 0.01, 0xbee0000000000001ULL, 2, NOW, NULL, NULL);
        CHECK(beeRidCount() == 1);
        CHECK(beeRidJson(&buf, &len, 0, 0, 0, NOW));
        if (v->id[0] && v->idType == 1) {
            snprintf(want, sizeof(want), "\"id\":\"%s\",\"id_type\":\"serial\",\"ua_type\":%d", v->id, v->uaType);
            CHECK(jsonHas(buf, want));
        }
        if (v->idType == 4)
            CHECK(jsonHas(buf, "\"id_type\":\"session\""));
        if (v->loc && !(v->lat == 0 && v->lon == 0)) {
            snprintf(want, sizeof(want), "\"lat\":%.7f,\"lon\":%.7f", v->lat, v->lon);
            CHECK(jsonHas(buf, want));
            snprintf(want, sizeof(want), "\"alt_geom_m\":%.1f,\"alt_baro_m\":%.1f,\"height_m\":%.1f,\"height_ref\":\"%s\",\"gs_mps\":%.2f,\"vrate_mps\":%.1f,\"track\":%.0f",
                    v->altGeo, v->altBaro, v->height, v->heightType ? "ground" : "takeoff", v->gs, v->vrate, v->track);
            CHECK(jsonHas(buf, want));
        }
        if (v->loc && v->lat == 0 && v->lon == 0)
            CHECK(!strstr(buf, "\"lat\"") && !strstr(buf, "gs_mps") && !strstr(buf, "track"));
        if (v->selfId[0]) {
            snprintf(want, sizeof(want), "\"self_id\":\"%s\"", v->selfId);
            CHECK(jsonHas(buf, want));
        }
        if (v->sys) {
            snprintf(want, sizeof(want), "\"operator\":{\"lat\":%.7f,\"lon\":%.7f,\"loc_type\":\"live\",\"alt_geom_m\":%.1f}",
                    v->opLat, v->opLon, v->opAlt);
            CHECK(jsonHas(buf, want));
            CHECK(jsonHas(buf, "\"eu_category\":1,\"eu_class\":2"));
        }
        if (v->opId[0]) {
            snprintf(want, sizeof(want), "\"operator_id\":\"%s\"", v->opId);
            CHECK(jsonHas(buf, want));
        }
        CHECK(jsonHas(buf, "\"transports\":[\"wifi_beacon\"]") && jsonHas(buf, "\"dbm\":-60"));
        CHECK(jsonHas(buf, "\"macs\":[\"c0:ff:ee:1a:00:01\"]") && jsonHas(buf, "\"uuids\":[\"bee00000-0000-0001-0000-000000000002\"]"));
        free(buf);
        // public: no operator data, no MACs, no UUIDs
        CHECK(beeRidJson(&buf, &len, 0, 1, 0, NOW));
        CHECK(!strstr(buf, "operator") || strstr(buf, "\"operator\":false"));
        CHECK(!strstr(buf, "\"operator\":{") && !strstr(buf, "operator_id") && !strstr(buf, "macs") && !strstr(buf, "uuids"));
        free(buf);
        if (fails != before)
            fprintf(stderr, "  vector %s\n", v->name);
    }

    // BLE legacy: Location before Basic ID on the same MAC -> one drone with the serial; same serial
    // over Wi-Fi with another MAC -> still one drone, two transports; filter by receiver
    const struct odidVec *basic = &odidVecs[0], *loc = &odidVecs[2];
    const uint8_t mac2[6] = { 0x6a, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e };
    beeRidReset();
    beeRidInput((const uint8_t *) loc->msg, 25, mac, 'b', &(struct beeMsg) { .dbm = -80, .hasDbm = 1 }, 0.01, 0x1111, 1, NOW, NULL, NULL);
    beeRidInput((const uint8_t *) basic->msg, 25, mac, 'b', &(struct beeMsg) { .dbm = -80, .hasDbm = 1 }, 0.01, 0x1111, 1, NOW + 100, NULL, NULL);
    CHECK(beeRidCount() == 1);
    beeRidInput((const uint8_t *) basic->msg, 25, mac2, 'w', &(struct beeMsg) { .dbm = -70, .hasDbm = 1 }, 0.01, 0x2222, 2, NOW + 200, NULL, NULL);
    CHECK(beeRidCount() == 1);
    CHECK(beeRidJson(&buf, &len, 0, 0, 0, NOW + 300));
    CHECK(jsonHas(buf, "\"transports\":[\"bt4_legacy\",\"wifi_beacon\"]") && jsonHas(buf, "\"receivers\":2"));
    CHECK(jsonHas(buf, "\"lat\":47.3977419") && jsonHas(buf, "\"id\":\"1581F5FKD229400ABCDE\""));
    free(buf);
    CHECK(beeRidJson(&buf, &len, 0, 1, 0x2222, NOW + 300) && strstr(buf, "1581F5FKD229400ABCDE"));
    free(buf);
    CHECK(beeRidJson(&buf, &len, 0, 1, 0x3333, NOW + 300) && !strstr(buf, "1581F5FKD229400ABCDE"));
    free(buf);
    // timeout: listed for ridTimeout, then gone
    CHECK(beeRidJson(&buf, &len, 0, 1, 0, NOW + 200 + Bee.ridTimeout) && !strstr(buf, "hex"));
    free(buf);

    // --readsbee-rid-globe: Location becomes an aircraft message, category B6, non-ICAO address
    struct client c;
    memset(&c, 0, sizeof(c));
    Bee.ridGlobe = 1;
    testUsed = 0;
    beeRidInput((const uint8_t *) odidVecs[8].msg, odidVecs[8].len, mac, 'w', &(struct beeMsg) { .dbm = -60, .hasDbm = 1 }, 0.01, 1, 1, NOW, &testMb, &c);
    CHECK(testUsed == 1 && testMsgs[0].bee.kind == 2 && testMsgs[0].category == 0xB6);
    CHECK((testMsgs[0].addr & MODES_NON_ICAO_ADDRESS) && testMsgs[0].sbs_pos_valid);
    Bee.ridGlobe = 0;
    beeRidReset();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: beetests policy/example.so\n");
        return 2;
    }
    char plugin[PATH_MAX];
    if (!realpath(argv[1], plugin)) {
        perror(argv[1]);
        return 2;
    }
    char dir[] = "/tmp/beetests.XXXXXX";
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 2;
    }
    testParse();
    testLists(dir);
    testLoopback();
    testClients(dir, plugin);
    testExtFrames();
    testFeedVectors();
    testCaps();
    testAdsl();
    testRemoteId();
    rmdir(dir);
    fprintf(stderr, "beetests: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
