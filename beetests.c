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
    rmdir(dir);
    fprintf(stderr, "beetests: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
