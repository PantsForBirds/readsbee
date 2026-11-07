#!/usr/bin/env python3
"""readsbee end to end: runs ./readsb and feeds it over TCP.
1. UUID filter (policy/example.so), 2. ADSBee Beast extension frames (UAT S/L/U, ADS-L, Remote ID) with an
upstream connector to a local sink, 3. --readsbee-rid-globe.

usage: tests/readsbee_net_test.py [path/to/readsb] [path/to/policy.so]

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
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import readsbee_proto as proto  # noqa: E402

READSB = sys.argv[1] if len(sys.argv) > 1 else "./readsb"
POLICY = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "policy/example.so")
PORT = 39004

# the example policy accepts UUIDs starting with policy_arg ("ab")
GOOD = "ab000000-0000-0000-0000-000000000001"
GOOD2 = "ab000000-0000-0000-0000-000000000002"
DENIED = "ab000000-0000-0000-0000-000000000003"
FOREIGN = "cd000000-0000-0000-0000-000000000004"
REUSED = "ab000000-0000-0000-0000-000000000005"

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


def connect(src, proxy_src=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((src, 0))
    s.connect((src, PORT))
    if proxy_src:
        s.sendall(f"PROXY TCP4 {proxy_src} {src} 40000 {PORT}\r\n".encode())
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


# ---- extension frames ---------------------------------------------------------------------------------
V2 = "ab0000b2-0000-0000-0000-0000000000b2"  # first half differs from GOOD: filter_uuid uses it
VDIR = Path(__file__).parent / "vectors"


def uat_basic(addr: int, lat: float, lon: float, alt_ft: int, mdb_type: int = 0, n: int = 30) -> bytes:
    """UAT ADS-B HDR + state vector (DO-282B), ICAO address, airborne, nic 8, N 100 kt / E 100 kt."""
    f = bytearray(n)
    f[0] = mdb_type << 3
    f[1:4] = addr.to_bytes(3, "big")
    rlat = round(lat / 360 * (1 << 24)) & 0x7FFFFF
    rlon = round(lon / 360 * (1 << 24)) & 0xFFFFFF
    f[4] = rlat >> 15
    f[5] = (rlat >> 7) & 0xFF
    f[6] = ((rlat & 0x7F) << 1) | (rlon >> 23)
    f[7] = (rlon >> 15) & 0xFF
    f[8] = (rlon >> 7) & 0xFF
    f[9] = (rlon & 0x7F) << 1
    ralt = (alt_ft + 1000) // 25 + 1
    f[10] = ralt >> 4
    f[11] = ((ralt & 15) << 4) | 8
    ns = ew = 101
    f[12] = (ns >> 6) & 0x1F
    f[13] = ((ns & 0x3F) << 2) | ((ew >> 9) & 3)
    f[14] = (ew >> 1) & 0xFF
    f[15] = (ew & 1) << 7
    return bytes(f)


def xxtea_enc(data: bytes, rounds=6) -> bytes:
    M = 0xFFFFFFFF
    v = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    n, z, s = len(v), v[-1], 0
    mx = lambda z, y, s, p, e: ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + z)) & M  # key 0
    for _ in range(rounds):
        s = (s + 0x9E3779B9) & M
        e = (s >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            v[p] = (v[p] + mx(z, y, s, p, e)) & M
            z = v[p]
    return b"".join(w.to_bytes(4, "little") for w in v)


def crc24(data: bytes) -> int:
    c = 0
    for b in list(data) + [0, 0, 0]:
        c |= b
        for _ in range(8):
            if c & 0x80000000:
                c ^= 0xFFFA0480
            c = (c << 1) & 0xFFFFFFFF
    return c >> 8


def adsl_traffic(amt: int, addr: int, lat: float, lon: float, alt_m: int, gs_mps: int, cat: int) -> bytes:
    """ADS-L Traffic packet (length .. CRC), small values only (exponent 0)."""
    fields = [(2, 8), (amt, 6), (addr, 24), (0, 1), (0, 1),                      # header
              (0, 6), (2, 2), (cat, 5), (1, 3), (round(lat * 93206) & 0xFFFFFF, 24),
              (round(lon * 46603) & 0xFFFFFF, 24), (gs_mps * 4, 8), (alt_m + 320, 14), (0, 9), (128, 9),
              (0, 2), (0, 2), (0, 4), (0, 3), (0, 2), (0, 2), (0, 1)]
    v, off = 0, 0
    for val, w in fields:
        v |= val << off
        off += w
    net = b"\x00" + xxtea_enc(v.to_bytes(20, "little"))
    pkt = net + crc24(net).to_bytes(3, "big")
    return bytes([len(pkt)]) + pkt


def run_readsb(tmp, extra):
    jdir = os.path.join(tmp, "json")
    os.makedirs(jdir, exist_ok=True)
    log = open(os.path.join(tmp, "readsb.log"), "w")
    p = subprocess.Popen([READSB, "--net", "--net-only", "--quiet", f"--net-bi-port={PORT}",
                          "--net-ro-port=0", "--net-sbs-port=0", "--net-bo-port=0",
                          "--net-receiver-id", "--net-ingest", f"--write-json={jdir}", "--write-json-every=1"] + extra,
                         stdout=log, stderr=subprocess.STDOUT)
    return p, log, jdir


def api(port, query):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/re-api/?{query}", timeout=5) as r:
        return json.loads(r.read())


def by_hex(ac):
    return {a["hex"]: a for a in (ac or {}).get("aircraft", [])}


def v2_frames(adsl_pkts, step):
    """the mixed READSBEE stream after the UUID, in steps (one per 0.25 s), like a feeder"""
    odid = {v["name"]: bytes.fromhex(v["hex"]) for v in json.loads((VDIR / "odid_vectors.json").read_text())}
    mac_w = bytes.fromhex("6a1a2b3c4d5e")
    mac_b = bytes.fromhex("c0ffee1a0001")
    ts = 0x0123451A6789
    out = []
    for i in range(30):
        out.append(b"")
        out[-1] += beast(df17_ident(0xA00010, "MODES%d" % (i % 10)))
        if i < 6:
            out[-1] += proto.enc_uat("s", 0x1a1a + i, 200, uat_basic(0xA00011, 47.40, 8.50, 3000), modes_clock=False)
            out[-1] += proto.enc_uat("s", ts + i, 0x1a, uat_basic(0xA00012, 47.41, 8.51, 4000), modes_clock=True)
        if i < 3:
            out[-1] += proto.enc_uat("l", 0, 150, uat_basic(0xA00013, 47.42, 8.52, 5000, mdb_type=2, n=48), modes_clock=True)
        if i == 4:
            out[-1] += proto.enc_uat("u", ts, 90, bytes(552), modes_clock=True)
        if True:
            for k, pkt in enumerate(adsl_pkts(i)):
                out[-1] += proto.enc_adsl(pkt, ts + i, proto.dbm_to_power(-87 - k), "ab"[k % 2], repaired=i % 3)
        if i == 5:
            out[-1] += proto.enc_rid(odid["pack"], 0, proto.dbm_to_power(-60), "w", mac_w)
            out[-1] += proto.enc_rid(odid["location_fast"], 0, proto.dbm_to_power(-75), "b", mac_b)
            out[-1] += proto.enc_rid(odid["basic_id_session"], 0, proto.dbm_to_power(-75), "b", mac_b)
        if i == 7:
            # bad frames: unknown letters, failed bound, unknown type. Only these are lost.
            out[-1] += b"\x1a\xedQ" + esc(bytes(20))
            out[-1] += b"\x1a\xecz" + esc(bytes(40))
            out[-1] += b"\x1a\xedA" + esc(bytes(8) + b"\x20" + bytes(32))       # L = 32
            out[-1] += b"\x1a\xf5q" + esc(b"\x1a\x33" + bytes(20))
    return out


def test_extension_frames(ip):
    print("--- extension frames")
    tmp = tempfile.mkdtemp(prefix="readsbee-ext-")
    sdir = os.path.join(tmp, "status")
    # upstream connector to a local sink: must carry Mode S only
    sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sink.bind(("127.0.0.1", 0))
    sink.listen(1)
    sink_port = sink.getsockname()[1]
    api_port = PORT + 1
    p, log, jdir = run_readsb(tmp, [f"--net-uuid-status-dir={sdir}", "--net-uuid-require",
                                    f"--net-api-port={api_port}",
                                    f"--net-connector=127.0.0.1,{sink_port},beast_reduce_plus_out"])
    try:
        sink.settimeout(10)
        up, _ = sink.accept()
        up.settimeout(0.2)
        time.sleep(1)
        real = [bytes.fromhex(v["packet"]) for v in json.loads((VDIR / "adsl_vectors.json").read_text())["vectors"]
                if v["name"] in ("traffic_v0_k0", "traffic_neg")]
        # glider with a FLARM address, moving north
        pkts = lambda i: real + [adsl_traffic(6, 0xDDEEFF, 47.30 + i * 0.0001, 8.60, 1200, 10, 4)]
        s = connect(ip)
        s.sendall(uuid_frame(V2))

        def stream():
            for chunk in v2_frames(pkts, 0):
                s.sendall(chunk)
                time.sleep(0.25)
        feeder = threading.Thread(target=stream)
        feeder.start()
        other = connect(ip)                                                # second receiver: Mode S only
        other.sendall(uuid_frame(GOOD) + b"".join(beast(df17_ident(0xA00020, "OTHER")) for _ in range(10)))

        ac = load(os.path.join(jdir, "aircraft.json"),
                  lambda d: all("lat" in by_hex(d).get(k, {}) for k in ("bee000", "~ddeeff", "bee001")) and "a00012" in by_hex(d))
        h = by_hex(ac)
        check("a00010" in h, "Mode S aircraft")
        check({"a00011", "a00012", "a00013"} <= set(h), f"UAT s / S / L aircraft: {sorted(k for k in h if k.startswith('a0001'))}")
        a = h.get("bee000", {})
        check(a.get("type") == "other" and "adsl" in a, f"ADS-L AMT 5 (ICAO) bee000: type other + adsl block: {a.get('type')} {a.get('adsl')}")
        check(abs(a.get("lat", 0) - 37.4124949) < 1e-5 and abs(a.get("lon", 0) + 122.0566916) < 1e-5, "ADS-L position")
        check(a.get("alt_geom") == 3281 and a.get("category") == "A1", f"ADS-L altitude / category: {a.get('alt_geom')} {a.get('category')}")
        check(abs(a.get("gs", 0) - 116.6) < 0.1 and abs(a.get("track", 0) - 135) < 0.1, f"ADS-L speed / track: {a.get('gs')} {a.get('track')}")
        check(a.get("adsl", {}).get("amt") == 5 and a.get("adsl", {}).get("ch") in (868.2, 868.4), "adsl block: amt, channel")
        f = h.get("~ddeeff", {})
        check(f.get("type") == "other" and f.get("category") == "B1" and f.get("adsl", {}).get("amt") == 6,
              f"ADS-L FLARM address -> non-ICAO ~ddeeff, glider B1: {f.get('category')} {f.get('adsl')}")
        check(f.get("alt_geom") == round(1200 / 0.3048) and 47.3 <= f.get("lat", 0) <= 47.3030, f"FLARM position / altitude {f.get('lat')}")
        check("bee001" in h and h["bee001"].get("category") == "B1", "second real ADS-L packet (glider, negative lat)")
        check(not any(x.get("category") == "B6" for x in h.values()), "drones not in aircraft.json by default")
        for i in range(5):  # the other receiver's aircraft needs fresh positions for filter_uuid
            other.sendall(proto.enc_adsl(adsl_traffic(0, 0x0A0020, 47.5 + i * 0.001, 8.7, 600, 5, 7), 0, proto.dbm_to_power(-95), "x", modes_clock=False))
            time.sleep(0.3)

        # API, per receiver
        mine = {a["hex"] for a in api(api_port, f"all&filter_uuid={V2}")["aircraft"]}
        theirs = {a["hex"] for a in api(api_port, f"all&filter_uuid={GOOD}")["aircraft"]}
        check({"bee000", "~ddeeff"} <= mine and "~0a0020" not in mine, f"/re-api/ filter_uuid: ADS-L under its receiver ({len(mine)})")
        check("bee000" not in theirs and "~0a0020" in theirs, f"/re-api/ filter_uuid: other receiver has no ADS-L {sorted(theirs)}")
        check("adsl" in next(a for a in api(api_port, "all")["aircraft"] if a["hex"] == "bee000"), "/re-api/: adsl block")

        # Remote ID
        rid = load(os.path.join(jdir, "remoteid.json"), lambda d: len(d.get("drones", [])) >= 2, 10)
        drones = {d.get("id"): d for d in (rid or {}).get("drones", [])}
        check(rid and rid["operator"] is False and len(drones) == 2, f"remoteid.json: 2 drones, operator off: {list(drones)}")
        d = drones.get("1581F5FKD229400ABCDE", {})
        check(d.get("id_type") == "serial" and d.get("transports") == ["wifi_beacon"] and abs(d.get("lat", 0) - 47.3977419) < 1e-7,
              "Wi-Fi pack drone: serial, position")
        check(d.get("hex", "").startswith("~") and "operator" not in d and "operator_id" not in d and "macs" not in d,
              "public drone: stable ~hex, no operator data, no MACs")
        b = next((x for x in drones.values() if x.get("id_type") == "session"), {})
        check(b.get("transports") == ["bt4_legacy"] and b.get("lat", 0) < -33, "BLE drone: Location then Basic ID on one MAC")
        full = load(os.path.join(sdir, "remoteid-full.json"), lambda x: len(x.get("drones", [])) >= 2, 10)
        fd = next((x for x in (full or {}).get("drones", []) if x.get("id") == "1581F5FKD229400ABCDE"), {})
        check(abs(fd.get("operator", {}).get("lat", 0) - 47.3970001) < 1e-7 and fd.get("operator_id") == "FIN87astrdge12k8"
              and fd.get("uuids") == [V2], "remoteid-full.json (status dir): operator, UUIDs")
        ra = api(api_port, f"remoteid&filter_uuid={V2}")
        check(len(ra["drones"]) == 2 and not ra["operator"], "/re-api/?remoteid&filter_uuid: 2 drones, no operator")
        check(len(api(api_port, f"remoteid&filter_uuid={GOOD}")["drones"]) == 0, "/re-api/?remoteid other receiver: none")

        # counts
        feeder.join()
        rb = load(os.path.join(sdir, "readsbee.json"),
                  lambda x: any(r.get("uuid") == V2 and r["frames"]["rid"] >= 3 for r in x.get("receivers", [])))
        r = next((r for r in (rb or {}).get("receivers", []) if r.get("uuid") == V2), {})
        fr = r.get("frames", {})
        check(fr == {"adsl": 90, "rid": 3, "uat": 16, "uat_mlat": 7, "bad": 3}, f"readsbee.json frames per receiver: {fr}")
        ro = next((r for r in (rb or {}).get("receivers", []) if r.get("uuid") == GOOD), {})
        check(ro.get("frames", {}).get("adsl") == 5 and ro["frames"]["uat"] == 0, f"other receiver: 5 ADS-L (random address, paraglider) {ro.get('frames')}")
        check(r.get("last_timed", {}).get("clock") in ("modes", "not_mlat", "unsynced"), f"timing kept: {r.get('last_timed')}")
        check(r.get("messages_s", 0) > 0 and r.get("positions", 0) > 0, f"extension frame receiver rates: {r.get('messages_s')} msg/s, {r.get('positions')} positions")
        check(rb and rb["frames"]["adsl"] == 95 and rb["drones"] == 2, "readsbee.json totals")
        st = load(os.path.join(jdir, "stats.json"), lambda x: x.get("total", {}).get("remote", {}).get("readsbee", {}).get("adsl") == 95)
        sr = (st or {}).get("total", {}).get("remote", {}).get("readsbee", {})
        check(sr.get("adsl") == 95 and sr.get("rid") == 3 and sr.get("uat") == 16 and sr.get("uat_mlat") == 7, f"stats.json readsbee counts: {sr}")
        check(st and st["total"].get("remote_malformed_beast", 0) == 0, "no malformed Beast bytes")
        check(is_open(s), "feed with all frame types: still open")

        # upstream connector: Mode S only, nothing from ADS-L / Remote ID
        time.sleep(2)
        data = b""
        end = time.time() + 3
        while time.time() < end:
            try:
                chunk = up.recv(65536)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                pass
        frames, dec = proto.decode_all(data)
        starts, i = set(), 0
        while i + 1 < len(data):  # every frame start, escape aware
            if data[i] == 0x1a:
                if data[i + 1] != 0x1a:
                    starts.add(data[i + 1])
                i += 2
            else:
                i += 1
        types = {fr.type for fr in frames}
        addrs = set()
        for fr in frames:
            if fr.type == 0x33:
                m = bytes.fromhex(fr.fields["msg"])
                addrs.add(m[1:4].hex())
        check(len(frames) > 10 and types <= {0x31, 0x32, 0x33, 0xE3}, f"connector: Mode S only {sorted(hex(t) for t in types)}")
        check(starts <= {0x31, 0x32, 0x33, 0xE3, ord("P"), ord("W")}, f"connector frame types: Mode S, receiver ID, ping, W command {sorted(hex(t) for t in starts)}")
        check("a00010" in addrs and not addrs & {"bee000", "bee001", "ddeeff"}, f"connector: no ADS-L aircraft {sorted(addrs)}")
        print(f"     (UAT-derived DF18 forwarded as upstream readsb does: {sorted(addrs & {'a00011', 'a00012', 'a00013'})})")
        up.close()
    finally:
        p.terminate()
        p.wait(10)
        log.close()
        sink.close()
        shutil.rmtree(tmp)


def test_rid_globe(ip):
    print("--- --readsbee-rid-globe")
    tmp = tempfile.mkdtemp(prefix="readsbee-rid-")
    p, log, jdir = run_readsb(tmp, ["--readsbee-rid-globe"])
    try:
        time.sleep(1.2)
        pack = next(bytes.fromhex(v["hex"]) for v in json.loads((VDIR / "odid_vectors.json").read_text()) if v["name"] == "pack")
        s = connect(ip)
        s.sendall(uuid_frame(V2))
        for _ in range(4):  # a drone sends about once a second
            s.sendall(proto.enc_rid(pack, 0, proto.dbm_to_power(-60), "w", bytes.fromhex("6a1a2b3c4d5e")))
            time.sleep(1)
        ac = load(os.path.join(jdir, "aircraft.json"), lambda d: any(a.get("category") == "B6" for a in d.get("aircraft", [])), 10)
        dr = [a for a in (ac or {}).get("aircraft", []) if a.get("category") == "B6"]
        check(len(dr) == 1 and dr[0]["hex"].startswith("~") and dr[0]["type"] == "other" and "rid" in dr[0],
              f"drone on the globe: ~hex, type other, B6: {dr[:1]}")
        check(dr and abs(dr[0].get("lat", 0) - 47.3977419) < 1e-6 and dr[0].get("alt_baro") == round(485 / 0.3048), "drone position / altitude")
        rid = load(os.path.join(jdir, "remoteid.json"))
        check(rid and rid["drones"] and rid["drones"][0]["hex"] == dr[0]["hex"] if dr else False, "same hex in remoteid.json")
    finally:
        p.terminate()
        p.wait(10)
        log.close()
        shutil.rmtree(tmp)


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
    conf = os.path.join(tmp, "readsbee.conf")
    open(conf, "w").write("policy_arg = ab\nmax_sources = 2\nreuse_action = reject\n")
    sdir = os.path.join(tmp, "status")  # created by readsb

    log = open(os.path.join(tmp, "readsb.log"), "w")
    p = subprocess.Popen([READSB, "--net", "--net-only", "--quiet", f"--net-bi-port={PORT}",
                          "--net-ro-port=0", "--net-sbs-port=0", "--net-bo-port=0",
                          "--net-receiver-id", "--net-ingest", f"--write-json={jdir}",
                          f"--net-uuid-policy={POLICY}", f"--net-uuid-config={conf}",
                          "--net-uuid-timeout=3", f"--net-uuid-status-dir={sdir}",
                          f"--net-uuid-allow-file={allow}", f"--net-uuid-deny-file={deny}"],
                         stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(1.5)
        icaos = {"good": 0xA00001, "good2": 0xA00002, "denied": 0xA00003, "foreign": 0xA00004,
                 "reuse3": 0xA00005, "nouuid": 0xA00006, "loop": 0xA00007, "early": 0xA00008,
                 "reuse1": 0xA00009, "reuse2": 0xA0000A, "spoof": 0xA0000B}
        socks = {}

        def feed(name, src, uuid, extra=b"", n=20, proxy_src=None):
            s = connect(src, proxy_src)
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
            ext += b"\x1a\xe9" + esc(bytes([0x1a] * 10 + [1, 2, 3]))           # 0xE9
            ext += beast(df17_ident(icaos["good"], "EXT%d" % (k % 10)))
        feed("good", ip, GOOD, ext)
        feed("denied", ip, DENIED)
        feed("foreign", ip, FOREIGN)
        # same UUID from 3 source addresses via a local proxy (PROXY headers), max_sources = 2
        feed("reuse1", "127.0.0.1", REUSED, proxy_src="192.0.2.1")
        feed("reuse2", "127.0.0.1", REUSED, proxy_src="192.0.2.2")
        time.sleep(0.3)
        feed("reuse3", "127.0.0.1", REUSED, proxy_src="192.0.2.3")
        # a remote peer can't claim loopback with a PROXY header
        feed("spoof", ip, None, proxy_src="127.0.0.1")
        feed("nouuid", ip, None)
        feed("loop", "127.0.0.1", None)

        time.sleep(1)
        want = {icaos[n] for n in ("good", "good2", "loop", "reuse1", "reuse2")}
        ac = load(os.path.join(jdir, "aircraft.json"), lambda d: want <= {int(a["hex"], 16) for a in d.get("aircraft", [])})
        seen = {int(a["hex"], 16) for a in ac["aircraft"]} if ac else set()
        check(icaos["good"] in seen, "accepted UUID: data used")
        check(icaos["good2"] in seen, "accepted UUID after early data: data used")
        check(icaos["early"] not in seen, "data before UUID: dropped")
        check(icaos["loop"] in seen, "loopback without UUID: exempt")
        check(icaos["reuse1"] in seen and icaos["reuse2"] in seen, "reused UUID: first 2 sources used")
        for n in ("denied", "foreign", "reuse3", "nouuid", "spoof"):
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

        rb = load(os.path.join(sdir, "readsbee.json"),
                  lambda d: any(r.get("state") == "ok" and r.get("uuid") == FOREIGN for r in d.get("receivers", [])))
        check(rb is not None, "readsbee.json written")
        if rb:
            st = {r["uuid"]: r for r in rb["receivers"] if r["uuid"]}
            check(st.get(GOOD, {}).get("state") == "ok", "readsbee.json: good ok")
            check(st.get(DENIED, {}).get("state") == "denied", "readsbee.json: denied")
            check(any(r["uuid"] == REUSED and r["state"] == "reuse" for r in rb["receivers"]), "readsbee.json: reuse")
            check(st.get(REUSED, {}).get("sources") == 2, "readsbee.json: 2 sources for the reused UUID")
            check(st.get(FOREIGN, {}).get("state") == "ok", "readsbee.json: foreign ok after allow")
            ext = st.get(GOOD, {}).get("ext", {})
            ee = st.get(GOOD, {}).get("ee", {})
            check(ext.get("ee") == 100 and ext.get("e9") == 50, f"ext frames per type counted: {ext}")
            check(ee.get("01") == 50 and ee.get("02") == 50, f"0xEE subtypes counted: {ee}")
            rej = {r["uuid"]: r for r in rb["rejected"]}
            check(set(rej) >= {DENIED, REUSED}, "rejected list has denied + reuse")
            check(rej.get(FOREIGN, {}).get("open") == 0, "rejected list: foreign no longer open")
            check(rb["rejected_connections"]["no_uuid"] >= 1, "counter no_uuid")
            check(rb["dropped_messages"]["pending"] >= 10, "counter pending drops")
            check(rb["dropped_messages"]["policy"] >= 20, "counter policy drops")
            check(not re.search(r"\d+\.\d+\.\d+\.\d+|port", json.dumps(rb)), "readsbee.json: no IPs")

        stats = load(os.path.join(jdir, "stats.json"))
        check(stats is not None and "readsbee" not in stats, "stats.json (web root): no filter details")
        check(not os.path.exists(os.path.join(jdir, "readsbee.json")), "readsbee.json not in the web root")
        cl = load(os.path.join(jdir, "clients.json"))
        check(cl is not None and cl["format"][-1] == "positions", "clients.json format unchanged")
        # clients.json columns per receiver in readsbee.json (no addresses)
        rb = load(os.path.join(sdir, "readsbee.json"), lambda d: d["now"] > rb["now"], 15) if rb else None
        g = next((r for r in (rb or {}).get("receivers", []) if r.get("uuid") == GOOD), {})
        c = next((c for c in (cl or {}).get("clients", []) if c[0] == GOOD), None)
        check(all(k in g for k in ("conn_s", "kbps", "messages_s", "positions_s", "messages", "positions")),
              f"readsbee.json receiver rates: {[(k, g.get(k)) for k in ('conn_s', 'kbps', 'messages_s', 'positions_s', 'messages', 'positions')]}")
        check(g.get("messages", 0) >= 70 and g.get("kbps", 0) > 0 and g.get("conn_s", 0) >= 5
              and abs(g["messages_s"] * g["conn_s"] - g["messages"]) <= max(2, 0.05 * g["messages"]), "rates consistent")
        check(c is not None and c[8] == g.get("positions") and abs(c[4] * c[3] - g.get("messages", -99)) <= max(2, 0.05 * g.get("messages", 0)),
              f"rates match clients.json (positions {c[8] if c else None}, msgs ~{round(c[4] * c[3]) if c else None})")
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
    test_extension_frames(ip)
    test_rid_globe(ip)
    print(f"{'PASS' if not fails else 'FAIL'}: {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
