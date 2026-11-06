#!/usr/bin/env python3
"""readsbee ingest filter, end to end: runs ./readsb and feeds it over TCP.

usage: tests/readsbee_net_test.py [path/to/readsb]

Needs a non-loopback local IPv4 address (to look like a remote feeder).
"""
import json
import re
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

READSB = sys.argv[1] if len(sys.argv) > 1 else "./readsb"
PORT = 39004

GOOD = "bee0003c-a8bd-5d38-bee0-003ca8bd5d38"
GOOD2 = "bee0003a-71b8-8022-bee0-003a71b88022"
DENIED = "bee0003c-a8bd-5d23-bee0-003ca8bd5d23"
FOREIGN = "7ad590e5-b1cc-3000-7ad5-90e5b1cc3000"
BADDATE = "bee00000-0000-0000-bee0-000000000000"

fails = 0


def check(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails += 1


def crc(msg: bytes) -> int:
    poly = 0xFFF409
    c = 0
    for b in msg:
        c ^= b << 16
        for _ in range(8):
            c <<= 1
            if c & 0x1000000:
                c ^= poly
    return c & 0xFFFFFF


def df17_ident(icao: int, callsign: str) -> bytes:
    chars = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"
    v = 0
    for ch in callsign.ljust(8)[:8]:
        v = v << 6 | chars.index(ch)
    me = (4 << 51) | v  # TC 4, category 0
    body = bytes([0x8D]) + icao.to_bytes(3, "big") + me.to_bytes(7, "big")
    return body + crc(body).to_bytes(3, "big")


def esc(b: bytes) -> bytes:
    return b.replace(b"\x1a", b"\x1a\x1a")


def beast(msg: bytes, ts: int = 0x1a1a1a1a1a1a, sig: int = 0x80) -> bytes:
    t = b"\x33" if len(msg) == 14 else b"\x32"
    return b"\x1a" + t + esc(ts.to_bytes(6, "big") + bytes([sig]) + msg)


def uuid_frame(u: str) -> bytes:
    return b"\x1a\xe4" + u.encode()


def ee_frame(sub: int, payload: bytes) -> bytes:
    body = bytes([1 + len(payload), sub]) + payload
    return b"\x1a\xee" + esc(body)


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    finally:
        s.close()


def connect(src):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((src, 0))
    s.connect((src if src != "127.0.0.1" else "127.0.0.1", PORT))
    return s


def is_open(s):
    s.setblocking(False)
    try:
        d = s.recv(4096)
        return d != b""  # b"" = closed by readsb
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        s.setblocking(True)


def load(path, wait_for=None, timeout=25):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            with open(path) as f:
                last = json.load(f)
            if wait_for is None or wait_for(last):
                return last
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
    return last


def main():
    ip = local_ip()
    print("remote feeders from", ip)
    tmp = tempfile.mkdtemp(prefix="readsbee-net-")
    jdir = os.path.join(tmp, "json")
    os.mkdir(jdir)
    allow = os.path.join(tmp, "allow.txt")
    deny = os.path.join(tmp, "deny.txt")
    open(allow, "w").write("# approved\n")
    open(deny, "w").write(DENIED + "  # blocked\n")

    log = open(os.path.join(tmp, "readsb.log"), "w")
    p = subprocess.Popen([READSB, "--net", "--net-only", "--quiet", f"--net-bi-port={PORT}",
                          "--net-ro-port=0", "--net-sbs-port=0", "--net-bo-port=0",
                          "--net-receiver-id", "--net-ingest", f"--write-json={jdir}",
                          "--net-require-adsbee-uuid", "--net-uuid-timeout=3",
                          f"--net-uuid-allow-file={allow}", f"--net-uuid-deny-file={deny}"],
                         stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(1.5)
        icaos = {"good": 0xA00001, "good2": 0xA00002, "denied": 0xA00003, "foreign": 0xA00004,
                 "baddate": 0xA00005, "nouuid": 0xA00006, "loop": 0xA00007, "early": 0xA00008}
        socks = {}

        def feed(name, src, uuid, extra=b"", n=20):
            s = connect(src)
            data = b""
            if uuid:
                data += uuid_frame(uuid)
            data += extra
            for i in range(n):
                data += beast(df17_ident(icaos[name], "BEE%d" % i))
            s.sendall(data)
            socks[name] = s
            return s

        # Mode S before the UUID is dropped, after it is used
        early = connect(ip)
        early.sendall(b"".join(beast(df17_ident(icaos["early"], "EARLY")) for _ in range(10)))
        time.sleep(0.3)
        early.sendall(uuid_frame(GOOD2) + b"".join(beast(df17_ident(icaos["good2"], "GOOD2")) for _ in range(10)))
        socks["early"] = early

        # extension frames with escapes, between Mode S frames, on a good feed
        ext = b""
        for k in range(50):
            ext += ee_frame(0x01, bytes([0x1a, 0x1a, k, 0x1a]) + bytes(24))  # ADS-L
            ext += ee_frame(0x02, bytes(range(25)) + b"\x1a")                 # Remote ID
            ext += b"\x1a\xe9" + esc(bytes([0x1a] * 10 + [1, 2, 3]))           # ADSBee info
            ext += beast(df17_ident(icaos["good"], "EXT%d" % (k % 10)))
        feed("good", ip, GOOD, ext)
        feed("denied", ip, DENIED)
        feed("foreign", ip, FOREIGN)
        feed("baddate", ip, BADDATE)
        feed("nouuid", ip, None)
        feed("loop", "127.0.0.1", None)

        time.sleep(1)
        ac = load(os.path.join(jdir, "aircraft.json"), lambda d: len(d.get("aircraft", [])) >= 3)
        seen = {int(a["hex"], 16) for a in ac["aircraft"]} if ac else set()
        check(icaos["good"] in seen, "ADSBee UUID: data used")
        check(icaos["good2"] in seen, "ADSBee UUID after early data: data used")
        check(icaos["early"] not in seen, "data before UUID: dropped")
        check(icaos["loop"] in seen, "loopback without UUID: exempt")
        for n in ("denied", "foreign", "baddate", "nouuid"):
            check(icaos[n] not in seen, f"{n}: data dropped")

        time.sleep(3.5)
        check(not is_open(socks["nouuid"]), "no UUID: closed after timeout")
        check(is_open(socks["foreign"]), "foreign: kept open, data dropped")
        check(is_open(socks["good"]), "good with extension frames: still open (no garbage close)")
        check(is_open(socks["loop"]), "loopback: still open")

        # live allow-file edit
        with open(allow + ".tmp", "w") as f:
            f.write("# approved\n" + FOREIGN + "\n")
        os.rename(allow + ".tmp", allow)
        time.sleep(3)
        socks["foreign"].sendall(b"".join(beast(df17_ident(icaos["foreign"], "OKNOW")) for _ in range(10)))
        ac = load(os.path.join(jdir, "aircraft.json"),
                  lambda d: icaos["foreign"] in {int(a["hex"], 16) for a in d.get("aircraft", [])}, 10)
        seen = {int(a["hex"], 16) for a in ac["aircraft"]} if ac else set()
        check(icaos["foreign"] in seen, "foreign: accepted after allow-file edit, no reconnect")

        rb = load(os.path.join(jdir, "readsbee.json"),
                  lambda d: any(r.get("state") == "ok" and r.get("uuid") == FOREIGN for r in d.get("receivers", [])))
        check(rb is not None, "readsbee.json written")
        if rb:
            st = {r["uuid"]: r for r in rb["receivers"] if r["uuid"]}
            check(st.get(GOOD, {}).get("state") == "ok", "readsbee.json: good ok")
            check(st.get(DENIED, {}).get("state") == "denied", "readsbee.json: denied")
            check(st.get(BADDATE, {}).get("state") == "date", "readsbee.json: bad date")
            check(st.get(FOREIGN, {}).get("state") == "ok", "readsbee.json: foreign ok after allow")
            ext = st.get(GOOD, {}).get("ext", {})
            ee = st.get(GOOD, {}).get("ee", {})
            check(ext.get("ee") == 100 and ext.get("e9") == 50, f"ext frames per type counted: {ext}")
            check(ee.get("01") == 50 and ee.get("02") == 50, f"0xEE subtypes counted: {ee}")
            rej = {r["uuid"]: r for r in rb["rejected"]}
            check(set(rej) >= {DENIED, BADDATE}, "rejected list has denied + bad date")
            check(rej.get(FOREIGN, {}).get("open") == 0, "rejected list: foreign no longer open")
            check(rb["readsbee"]["rejected_connections"]["no_uuid"] >= 1, "counter no_uuid")
            check(rb["readsbee"]["dropped_messages"]["pending"] >= 10, "counter pending drops")
            check(rb["readsbee"]["dropped_messages"]["format"] >= 20, "counter format drops")
            check(not re.search(r"\d+\.\d+\.\d+\.\d+|port", json.dumps(rb)), "readsbee.json: no IPs")

        stats = load(os.path.join(jdir, "stats.json"), lambda d: "readsbee" in d)
        check(stats is not None and stats["readsbee"]["ext"].get("ee") == 100, "stats.json readsbee counters")
        cl = load(os.path.join(jdir, "clients.json"))
        check(cl is not None and cl["format"][-1] == "bee" and all(len(c) == 10 for c in cl["clients"]),
              "clients.json: bee column")
        malformed = stats["total"].get("remote_malformed_beast", 0) if stats else -1
        check(malformed == 0, f"no malformed beast bytes from extension frames ({malformed})")
    finally:
        p.terminate()
        p.wait(10)
        log.close()
        print("--- readsb log (readsbee lines)")
        for line in open(os.path.join(tmp, "readsb.log")):
            if "readsbee" in line:
                print("  " + line.rstrip())
        shutil.rmtree(tmp)
    print(f"{'PASS' if not fails else 'FAIL'}: {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
