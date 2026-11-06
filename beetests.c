// Part of readsbee, a fork of readsb. GPL-3.0-or-later, see COPYING.
// Unit tests for the ADSBee ingest filter: make beetest

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

static int fails, checks;
#define CHECK(cond) do { checks++; if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static int64_t NOW; // 2026-11-05

static int fmt(const char *uuid) {
    uint64_t hi, lo;
    if (!beeParseUuid(uuid, &hi, &lo))
        return -1;
    return beeCheckFormat(hi, lo, NOW);
}

static void testFormat(void) {
    // well-formed, taken from live feeders
    const char *good[] = {
        "bee0003c-a8bd-5d38-bee0-003ca8bd5d38", // 026 05 29 02 0216
        "bee00038-1e26-8717-bee0-00381e268717", // 024 10 24 01 0007
        "bee0003a-7e1e-0601-bee0-003a7e1e0601", // 025 12 24
        "BEE0003A-59B3-356F-BEE0-003A59B3356F", // upper case
        "bee0003ca8bd5d38bee0003ca8bd5d38",     // no dashes
    };
    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        CHECK(fmt(good[i]) == BEE_R_NONE);

    // mirrored halves mismatch
    CHECK(fmt("bee0003c-a8bd-5d38-bee0-003ca8bd5d39") == BEE_R_FORMAT);
    CHECK(fmt("bee0003c-a8bd-5d38-0000-000000000000") == BEE_R_FORMAT);
    // foreign
    CHECK(fmt("7ad590e5-b1cc-3000-7ad5-90e5b1cc3000") == BEE_R_FORMAT); // mirrored, no bee0
    CHECK(fmt("6d3d8366-7233-ef32-0000-000000000000") == BEE_R_FORMAT);
    CHECK(fmt("bee1003c-a8bd-5d38-bee1-003ca8bd5d38") == BEE_R_FORMAT);
    // value >= 10^13 (0x9184e72a000)
    CHECK(fmt("bee00918-4e72-a000-bee0-09184e72a000") == BEE_R_FORMAT);
    CHECK(fmt("bee0ffff-ffff-ffff-bee0-ffffffffffff") == BEE_R_FORMAT);
    // implausible dates
    CHECK(fmt("bee00000-0000-0000-bee0-000000000000") == BEE_R_DATE); // blank part code
    // 0261329020216: month 13
    CHECK(fmt("bee0003c-d86c-6538-bee0-003cd86c6538") == BEE_R_DATE);
    // 0260230000000: Feb 30
    CHECK(fmt("bee0003c-96ea-ad80-bee0-003c96eaad80") == BEE_R_DATE);
    // 0350101000000: 2035, too far ahead
    CHECK(fmt("bee00051-83a5-4f40-bee0-005183a54f40") == BEE_R_DATE);
    // 0210101000000: 2021, before ADSBee
    CHECK(fmt("bee00030-eafe-d740-bee0-0030eafed740") == BEE_R_DATE);

    // malformed strings
    uint64_t hi, lo;
    CHECK(!beeParseUuid("bee0003c-a8bd-5d38-bee0-003ca8bd5d3", &hi, &lo));   // short
    CHECK(!beeParseUuid("bee0003c-a8bd-5d38-bee0-003ca8bd5d388", &hi, &lo)); // long
    CHECK(!beeParseUuid("bee0003c-a8bd-5d38-bee0-003ca8bd5dxx", &hi, &lo));  // not hex
    CHECK(!beeParseUuid("", &hi, &lo));
}

static void writeFile(const char *path, const char *text) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    fputs(text, f);
    fclose(f);
    rename(tmp, path); // like the website: atomic replace
}

static void testLists(const char *dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/allow.txt", dir);
    struct beeList l = { .path = path };
    uint64_t hi, lo;

    // missing file = empty
    unlink(path);
    CHECK(beeListLoad(&l, 1) == 1 && l.len == 0);
    CHECK(beeListLoad(&l, 0) == 0);

    writeFile(path, "# approved stations\n"
            "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000  # Bob's station\n"
            "\n   6D3D8366-7233-EF32-0000-000000000000\n"
            "not-a-uuid\n"
            "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000\n"); // duplicate
    CHECK(beeListLoad(&l, 0) == 1);
    CHECK(l.len == 2);
    beeParseUuid("7ad590e5-b1cc-3000-7ad5-90e5b1cc3000", &hi, &lo);
    CHECK(beeListContains(&l, hi, lo));
    beeParseUuid("6d3d8366-7233-ef32-0000-000000000000", &hi, &lo);
    CHECK(beeListContains(&l, hi, lo));
    CHECK(beeListLoad(&l, 0) == 0); // unchanged

    // reload after a change within the same second
    writeFile(path, "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000\n");
    CHECK(beeListLoad(&l, 0) == 1);
    CHECK(l.len == 1 && !beeListContains(&l, hi, lo));

    // deleted again
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
}

static void giveUuid(struct client *c, const char *uuid) {
    beeParseUuid(uuid, &c->receiverId, &c->receiverId2);
    c->receiverIdLocked = 1;
    beeClientUuid(c, NOW);
}

static void testClients(const char *dir) {
    char allow[512], deny[512];
    snprintf(allow, sizeof(allow), "%s/a.txt", dir);
    snprintf(deny, sizeof(deny), "%s/d.txt", dir);
    writeFile(allow, "\n");
    writeFile(deny, "bee0003c-a8bd-5d23-bee0-003ca8bd5d23\n");
    Bee.require = 1;
    Bee.allow.path = allow;
    Bee.deny.path = deny;
    beeInit();
    CHECK(Bee.deny.len == 1);

    struct client c;

    // loopback exempt (mlathub to localhost:30004)
    mkClient(&c, &beastIn, "127.0.0.1");
    beeClientAccept(&c, NOW);
    CHECK(c.bee.state == BEE_EXEMPT);
    CHECK(!beeDrop(&c));
    CHECK(!beeTimedOut(&c, NOW + 60 * SECONDS));
    // ... unless a PROXY header names a remote peer
    strcpy(c.proxy_string, "TCP4 203.0.113.9 127.0.0.1 40223 30004");
    beeClientProxy(&c);
    CHECK(c.bee.state == BEE_PENDING);

    // other input types untouched
    mkClient(&c, &sbsIn, "203.0.113.9");
    beeClientAccept(&c, NOW);
    CHECK(c.bee.state == BEE_OFF);

    // pending: data dropped, closed after the timeout
    mkClient(&c, &beastIn, "203.0.113.9");
    beeClientAccept(&c, NOW);
    CHECK(c.bee.state == BEE_PENDING);
    CHECK(beeDrop(&c));
    CHECK(!beeTimedOut(&c, NOW + 14 * SECONDS));
    CHECK(beeTimedOut(&c, NOW + 15 * SECONDS));

    // good bee
    mkClient(&c, &beastIn, "203.0.113.9");
    beeClientAccept(&c, NOW);
    giveUuid(&c, "bee0003c-a8bd-5d38-bee0-003ca8bd5d38");
    CHECK(c.bee.state == BEE_OK);
    CHECK(!beeDrop(&c));

    // denied bee
    mkClient(&c, &beastIn, "203.0.113.9");
    beeClientAccept(&c, NOW);
    giveUuid(&c, "bee0003c-a8bd-5d23-bee0-003ca8bd5d23");
    CHECK(c.bee.state == BEE_REJECTED && c.bee.reason == BEE_R_DENIED);
    CHECK(beeDrop(&c));
    beeClientClose(&c);

    // foreign station, then allowed by a live edit, then denied
    struct client f;
    mkClient(&f, &beastIn, "198.51.100.7");
    beeClientAccept(&f, NOW);
    giveUuid(&f, "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000");
    CHECK(f.bee.state == BEE_REJECTED && f.bee.reason == BEE_R_FORMAT);
    CHECK(beeDrop(&f));
    CHECK(Bee.rejected_conn[BEE_R_FORMAT] == 1);

    writeFile(allow, "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000\n");
    Bee.next_poll = 0;
    CHECK(beePoll(NOW) == 1);
    CHECK(beeEvaluate(&f, NOW) == 1);
    CHECK(f.bee.state == BEE_OK && !beeDrop(&f));

    writeFile(deny, "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000\n");
    Bee.next_poll = 0;
    CHECK(beePoll(NOW) == 1);
    CHECK(beeEvaluate(&f, NOW) == 1);
    CHECK(f.bee.state == BEE_REJECTED && f.bee.reason == BEE_R_DENIED); // deny wins

    // the previously denied bee is no longer listed
    struct client g;
    mkClient(&g, &beastIn, "203.0.113.10");
    beeClientAccept(&g, NOW);
    giveUuid(&g, "bee0003c-a8bd-5d23-bee0-003ca8bd5d23");
    CHECK(g.bee.state == BEE_OK);

    // filter off: nothing changes
    Bee.require = 0;
    Bee.deny.path = NULL;
    mkClient(&c, &beastIn, "203.0.113.9");
    beeClientAccept(&c, NOW);
    CHECK(c.bee.state == BEE_OFF && !beeDrop(&c));
    giveUuid(&c, "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000");
    CHECK(c.bee.state == BEE_OFF);

    unlink(allow);
    unlink(deny);
}

static void testExtFrames(void) {
    // p points at the type byte (after 0x1a)
    const char a[] = { (char) 0xEE, 0x03, 0x01, 0x11, 0x22, 0x1a, '3' };
    CHECK(beeExtFrameLen(a, a + sizeof(a)) == 5);

    // escaped 0x1a inside the body
    const char b[] = { (char) 0xEE, 0x03, 0x02, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, '2' };
    CHECK(beeExtFrameLen(b, b + sizeof(b)) == 7);

    // body ends in an escape pair split over two reads: wait
    CHECK(beeExtFrameLen(b, b + 4) == 0);
    CHECK(beeExtFrameLen(b, b + 6) == 0); // trailing 0x1a: escape or frame start?
    // no next frame yet
    CHECK(beeExtFrameLen(a, a + 5) == 0);

    // too long
    char big[BEE_EXT_MAX_LEN + 10];
    memset(big, 0x55, sizeof(big));
    big[0] = (char) 0xE9;
    CHECK(beeExtFrameLen(big, big + sizeof(big)) == -1);
    big[BEE_EXT_MAX_LEN + 5] = 0x1a;
    big[BEE_EXT_MAX_LEN + 6] = '3';
    CHECK(beeExtFrameLen(big, big + sizeof(big)) == -1);

    // counting per type and 0xEE subtype, LEN byte equal to 0x1a is escaped
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

int main(void) {
    NOW = 1793836800000LL; // 2026-11-05 00:00 UTC
    char dir[] = "/tmp/beetests.XXXXXX";
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 2;
    }
    testFormat();
    testLists(dir);
    testLoopback();
    testClients(dir);
    testExtFrames();
    rmdir(dir);
    fprintf(stderr, "beetests: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
