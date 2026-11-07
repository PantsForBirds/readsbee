#!/usr/bin/env python3
"""ADSBee Beast extensions (2026-11-06) against a running readsb: capabilities answer, power bytes.

  python3 tests/readsbee_caps_test.py ./readsb [--captures DIR]

1. Every feeder -> server vector of tests/vectors/feed_vectors.json over its own connection: a
   query gets exactly one answer, nothing else does, and no connection is closed. The exchange
   vectors run in order: query, the answer (byte-exact), then the agreed frames.
2. The answer bytes for --readsbee-caps default / 14 / 4 / 0 equal the server -> feeder vectors;
   reserved bit 0 is never answered.
3. Feeder model: answer seen after 0 s, 1 s or 6 s (5 s timeout: plain), a server answering
   Remote ID only, and a feeder that never queries. The feeder sends the agreed frames as soon as
   it has read the answer (no confirm frame). Every signal byte is a power byte: readsb's Beast
   output must carry each Mode S frame's byte back, and the drones' rssi must match theirs.
4. aircraft.json / remoteid.json: rssi in dBFS from the power byte, no "dbm" field.
5. --captures DIR: the t-1069 ADSBee captures replay (Mode S aircraft and the bench drone).
"""
import json
import math
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

D = Path(__file__).parent
sys.path.insert(0, str(D))
import readsbee_proto as P  # noqa: E402

READSB = sys.argv[1] if len(sys.argv) > 1 else "./readsb"
CAPTURES = sys.argv[sys.argv.index("--captures") + 1] if "--captures" in sys.argv else None
PORT_IN, PORT_OUT = 31600 + os.getpid() % 200 * 2, 31601 + os.getpid() % 200 * 2
UUID = "0bee0003-8172-d18c-0bee-00038172d18c"
failed = 0


def check(cond, what):
    global failed
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    failed += not cond


class Readsb:
    def __init__(self, tmp, extra=()):
        self.jdir = Path(tmp) / "json"
        self.jdir.mkdir(exist_ok=True)
        self.p = subprocess.Popen([READSB, "--net", "--net-only", "--quiet", f"--net-bi-port={PORT_IN}",
                                   "--net-ro-port=0", "--net-sbs-port=0", f"--net-bo-port={PORT_OUT}",
                                   f"--write-json={self.jdir}", "--write-json-every=1", *extra],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT_IN), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)

    def json(self, name, ok=lambda x: True, timeout=5.0):
        end = time.time() + timeout
        last = {}
        while time.time() < end:
            try:
                last = json.loads((self.jdir / name).read_text())
                if ok(last):
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        return last

    def stop(self):
        self.p.terminate()
        self.p.wait()


def recv_some(s, n, timeout):
    s.settimeout(timeout)
    data = b""
    end = time.time() + timeout
    try:
        while len(data) < n and time.time() < end:
            chunk = s.recv(4096)
            if not chunk:
                return data, True
            data += chunk
    except socket.timeout:
        pass
    return data, False


def still_open(s):
    """readsb closes a feed with a FIN; nothing to read and no EOF = still open."""
    s.setblocking(False)
    try:
        return s.recv(1, socket.MSG_PEEK) != b""
    except BlockingIOError:
        return True
    finally:
        s.setblocking(True)


def test_vectors(tmp):
    vecs = json.loads((D / "vectors" / "feed_vectors.json").read_text())
    rs = Readsb(tmp, ["--modeac"])
    answer = P.enc_caps(P.CAPS_ANSWER, P.CAP_KNOWN)
    n_ok = n_vec = 0
    try:
        for v in vecs:
            if v.get("direction") == "server_to_feeder":
                continue
            n_vec += 1
            queries = sum(f.get("kind") == "caps_query" for f in v["decoded"])
            s = socket.create_connection(("127.0.0.1", PORT_IN))
            if "exchange" in v:
                # query (and what was sent while waiting), the answer, then the agreed frames
                feeder1, server, feeder2 = (bytes.fromhex(x["hex"]) for x in v["exchange"])
                s.sendall(feeder1)
                back, eof = recv_some(s, 6, 1.0)
                good = back == answer and server[:3] == answer[:3]
                s.sendall(feeder2)
            else:
                s.sendall(bytes.fromhex(v["hex"]))
                back, eof = recv_some(s, 64, 0.6 if queries else 0.3)
                good = back == (answer if queries else b"")
            time.sleep(0.05)
            good = good and not eof and still_open(s)
            s.close()
            n_ok += good
            if not good:
                print(f"  {v['name']}: back {back.hex()} ({queries} queries), eof {eof}")
        check(n_ok == n_vec, f"vectors through readsb: {n_ok}/{n_vec} (answer only to a query, no close)")

        # one answer per connection: a second query, a client 'A' and the reserved 'C' are ignored
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        s.sendall(P.enc_uuid(UUID) + bytes.fromhex("1ae543818e80") + P.enc_caps("Q", 14) + P.enc_caps("Q", 14)
                  + P.enc_caps("A", 14) + bytes.fromhex("1ae543818e80"))
        back, _ = recv_some(s, 64, 1.0)
        s.close()
        check(back == answer, f"'C', two queries, an 'A', 'C': one answer ({back.hex()})")
        # a plain Beast client gets nothing back
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        s.sendall(P.enc_uuid(UUID) + P.enc_mode_s(bytes.fromhex("5d4840d6abcdef"), 1, 4))
        back, _ = recv_some(s, 64, 1.0)
        s.close()
        check(back == b"", "no query: nothing sent back")
    finally:
        rs.stop()


def test_answers(tmp):
    vecs = {v["name"]: v for v in json.loads((D / "vectors" / "feed_vectors.json").read_text())}
    for caps, name in ((None, "answer_all"), ("15", "answer_all"), ("14", "answer_all"),
                       ("4", "answer_rid_only"), ("0", "answer_none")):
        rs = Readsb(tmp, [f"--readsbee-caps={caps}"] if caps else [])
        try:
            s = socket.create_connection(("127.0.0.1", PORT_IN))
            s.sendall(P.enc_uuid(UUID) + P.enc_caps("Q", 15))  # an older feeder that still offers bit 0
            back, _ = recv_some(s, 6, 2.0)
            s.close()
            check(back.hex() == vecs[name]["hex"], f"--readsbee-caps={caps or 'default'}: answer {back.hex()} = {name}")
        finally:
            rs.stop()


def crc24(msg: bytes) -> int:
    data = int.from_bytes(msg, "big") << 24
    for i in range(len(msg) * 8):
        if data & (1 << (len(msg) * 8 + 23 - i)):
            data ^= 0x1FFF409 << (len(msg) * 8 - 1 - i)
    return data & 0xFFFFFF


def df17(icao: int) -> bytes:
    m = bytes([0x8d, icao >> 16 & 255, icao >> 8 & 255, icao & 255, 0x20, 0x2c, 0xc3, 0x71, 0xc3, 0x2c, 0xe0])
    return m + crc24(m).to_bytes(3, "big")


ADSL_ONAIR = bytes([26]) + bytes.fromhex("00021a3c4d5e6f1a1a00112233445566778899aabb0102a1b2c3")
MAC = bytes.fromhex("c0ffee1a0001")
ODID = bytes([0x12]) + bytes(24)  # Location message, all zero
RID_POWER = P.dbm_to_power(-72)  # 16


def feeder(delay, query=True, seconds=7.0, rate=200, icao0=0x700000):
    """The feeder: E4 + query, Beast at once, the agreed frames from the moment the answer is
    read (delay s after it arrived; ignored after 5 s). Returns the power byte per Mode S ICAO,
    the agreed bits (None = plain) and the extension frames sent before / after the answer."""
    s = socket.create_connection(("127.0.0.1", PORT_IN))
    s.setblocking(False)
    t0 = time.time()
    s.sendall(P.enc_uuid(UUID) + (P.enc_caps(P.CAPS_QUERY, P.CAP_KNOWN) if query else b""))
    scan = P.AnswerScanner()
    arrived = None
    bits = None
    modes = {}
    ext = {"rid": 0, "adsl": 0, "upper": 0}
    i = 0
    while time.time() - t0 < seconds:
        try:
            data = s.recv(4096)
            if data and arrived is None:
                scan.feed(data)
                if scan.answer is not None:
                    arrived = time.time()
        except BlockingIOError:
            pass
        if bits is None and arrived is not None and time.time() >= arrived + delay:
            bits = P.negotiate(P.CAP_KNOWN, scan.answer[1]) if time.time() - t0 <= P.CAPS_ANSWER_TIMEOUT_S else -1
        agreed = bits if bits and bits > 0 else 0
        b = P.dbm_to_power(-105 + (i * 7) % 80)  # -105 .. -26 dBm: power bytes 1 .. 255
        icao = icao0 + i
        modes[icao] = b
        out = P.enc_mode_s(df17(icao), i, b)
        if i % 10 == 5:
            up = bool(agreed & P.CAP_UAT_MODES_CLOCK)
            out += P.enc_uat("s", i, b, bytes(30), modes_clock=up)
            ext["upper"] += up
            if agreed & P.CAP_ADSL:
                out += P.enc_adsl(ADSL_ONAIR, i, b, "a")
                ext["adsl"] += 1
            if agreed & P.CAP_RID:
                out += P.enc_rid(ODID, 0, RID_POWER, "b", MAC)
                ext["rid"] += 1
        s.setblocking(True)
        s.sendall(out)
        s.setblocking(False)
        i += 1
        time.sleep(1 / rate)
    open_ = still_open(s)
    s.close()
    return modes, bits, ext, open_


def beast_out_levels(port):
    """Collects readsb's Beast output: power byte per ICAO of DF17 frames."""
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(0.2)
    buf = bytearray()

    def drain():
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
        except socket.timeout:
            pass
        out = {}
        for f in P.Decoder().feed(bytes(buf)):
            if f.type == 0x33:
                out[int.from_bytes(f.body[8:11], "big")] = f.body[6]
        return out
    return s, drain


def test_feeder(tmp):
    known = P.CAP_KNOWN
    cases = [("answer at once", {}, 0.0, True, known),
             ("answer after 1 s", {}, 1.0, True, known),
             ("answer after 6 s (timeout)", {}, 6.0, True, -1),
             ("server answers Remote ID only", {"caps": "4"}, 0.0, True, P.CAP_RID),
             ("feeder never queries", {}, 0.0, False, None)]
    for k, (name, opt, delay, query, want_bits) in enumerate(cases):
        rs = Readsb(tmp, [f"--readsbee-caps={opt['caps']}"] if "caps" in opt else [])
        try:
            out, drain = beast_out_levels(PORT_OUT)
            modes, bits, ext, open_ = feeder(delay, query, icao0=0x700000 + k * 0x10000)
            check(bits == want_bits and open_, f"feeder, {name}: agreed bits {bits}, ext frames {ext}, open {open_}")
            # the Beast output carries each frame's power byte back (readsb: sqrt(level) * 255)
            time.sleep(1.5)
            levels = drain()
            out.close()
            bad = sum(abs(levels[icao] - max(1, b)) > 1 for icao, b in modes.items() if icao in levels)
            check(len(levels) > len(modes) * 0.9 and bad == 0,
                  f"feeder, {name}: Beast output levels {len(levels)}/{len(modes)} frames, {bad} off")
            if ext["rid"]:
                rid = rs.json("remoteid.json", lambda x: x.get("drones"))
                d = (rid.get("drones") or [{}])[0]
                want = 20 * math.log10(RID_POWER / 255)
                check(abs(d.get("rssi", 99) - want) < 0.11 and "dbm" not in d,
                      f"feeder, {name}: drone rssi {d.get('rssi')} dBFS = power byte {RID_POWER}, no dbm")
        finally:
            rs.stop()


def test_json(tmp):
    """aircraft.json: rssi is dBFS from the power byte, no dbm field, for feeds with and without a query."""
    rs = Readsb(tmp)
    try:
        a, b = 0x7A0001, 0x7A0002
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        s.sendall(P.enc_uuid(UUID) + P.enc_caps("Q", 14))
        recv_some(s, 6, 1.0)
        s.sendall(b"".join(P.enc_mode_s(df17(a), i, P.dbm_to_power(-60)) for i in range(8)))
        t = socket.create_connection(("127.0.0.1", PORT_IN))
        t.sendall(P.enc_uuid(UUID) + b"".join(P.enc_mode_s(df17(b), i, P.dbm_to_power(-87)) for i in range(8)))
        ac = rs.json("aircraft.json", lambda x: len(x.get("aircraft", [])) >= 2)
        ac = {x["hex"]: x for x in ac.get("aircraft", [])}
        for icao, dbm, what in ((a, -60, "answered feed"), (b, -87, "plain feed")):
            x = ac.get(f"{icao:06x}", {})
            want = 20 * math.log10(P.dbm_to_power(dbm) / 255)
            check("dbm" not in x and abs(x.get("rssi", 99) - want) < 0.2,
                  f"aircraft.json, {what}: rssi {x.get('rssi')} dBFS (power byte {P.dbm_to_power(dbm)}), no dbm")
        s.close()
        t.close()
    finally:
        rs.stop()


def test_captures(tmp, d):
    for name in ("beast.bin", "readsbee.bin"):
        data = (Path(d) / name).read_bytes()
        n_ef = sum(f.type == 0xEF for f in P.Decoder().feed(data))
        rs = Readsb(tmp)
        try:
            s = socket.create_connection(("127.0.0.1", PORT_IN))
            for i in range(0, len(data), 8192):
                s.sendall(data[i:i + 8192])
                time.sleep(0.001)
            time.sleep(1)
            ac = rs.json("aircraft.json", lambda x: x.get("aircraft"))
            check(len(ac.get("aircraft", [])) > 0 and still_open(s),
                  f"capture {name}: {len(ac.get('aircraft', []))} aircraft, connection open")
            if n_ef:
                rid = rs.json("remoteid.json", lambda x: x.get("drones"))
                ids = [x.get("id") for x in rid.get("drones", [])]
                check(ids == ["ADSBEEBENCHA"] and all("dbm" not in x for x in rid["drones"]),
                      f"capture {name}: drones {ids} ({n_ef} 0xEF), no dbm")
            s.close()
        finally:
            rs.stop()


def main():
    tmp = tempfile.mkdtemp(prefix="readsbee-caps-")
    test_vectors(tmp)
    test_answers(tmp)
    test_json(tmp)
    test_feeder(tmp)
    if CAPTURES:
        test_captures(tmp, CAPTURES)
    subprocess.run(["rm", "-rf", tmp])
    print("FAIL: %d failed" % failed if failed else "all ok")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
