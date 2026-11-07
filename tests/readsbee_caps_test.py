#!/usr/bin/env python3
"""ADSBee Beast extensions (2026-11-06) against a running readsb: capabilities answer, confirm, signal byte per connection.

  python3 tests/readsbee_caps_test.py ./readsb [--captures DIR]

1. Every feeder -> server vector of tests/vectors/feed_vectors.json over its own connection: each
   frame's signal byte must be read as the vector decodes it (power byte or dBm, same value), and
   a query must get exactly one answer.
2. The answer bytes for --readsbee-caps 15 / 14 / 4 / 0 equal the server -> feeder vectors.
3. Feeder model: answer seen after 0 s, 1 s or 6 s (5 s timeout: plain), a server without bit 0,
   and a feeder that never queries. Misread signal levels must be 0, and readsb's Beast output
   must carry the level the feeder meant.
4. --captures DIR: the t-1069 ADSBee captures (no query) replay in power-byte mode.

readsb logs each frame's signal byte to READSBEE_SIGNAL_LOG ("<fd> power|dbm <byte>").
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
        self.log = Path(tmp) / f"signal{len(list(Path(tmp).glob('signal*')))}.log"
        self.jdir = Path(tmp) / "json"
        self.jdir.mkdir(exist_ok=True)
        env = dict(os.environ, READSBEE_SIGNAL_LOG=str(self.log))
        self.p = subprocess.Popen([READSB, "--net", "--net-only", "--quiet", f"--net-bi-port={PORT_IN}",
                                   "--net-ro-port=0", "--net-sbs-port=0", f"--net-bo-port={PORT_OUT}",
                                   f"--write-json={self.jdir}", "--write-json-every=1", *extra],
                                  env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT_IN), timeout=1).close()
                break
            except OSError:
                time.sleep(0.05)
        self.pos = 0

    def readings(self, n, timeout=5.0):
        """Next signal log lines after the last call, waiting for at least n, then a little more."""
        end = time.time() + timeout
        out = []
        while True:
            text = self.log.read_text() if self.log.exists() else ""
            out = text[self.pos:].splitlines()
            if len(out) >= n or time.time() > end:
                time.sleep(0.2)
                text = self.log.read_text()
                break
            time.sleep(0.02)
        new = text[self.pos:]
        self.pos = len(text)
        return [(m, int(b)) for _, m, b in (line.split() for line in new.splitlines())]

    def stop(self):
        self.p.terminate()
        self.p.wait()


def expected_readings(vec):
    out = []
    for f in vec["decoded"]:
        if "ts" not in f:
            continue
        if "dbm" in f:
            out.append(("dbm", P.dbm_byte(f["dbm"])))
        else:
            out.append(("power", f["rssi"]))
    return out


def recv_some(s, n, timeout):
    s.settimeout(timeout)
    data = b""
    end = time.time() + timeout
    try:
        while len(data) < n and time.time() < end:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def test_vectors(tmp):
    vecs = json.loads((D / "vectors" / "feed_vectors.json").read_text())
    rs = Readsb(tmp, ["--modeac"])  # without it readsb ignores 0x31 input before the signal byte
    answer = P.enc_caps(P.CAPS_ANSWER, P.CAP_KNOWN)
    n_ok = n_vec = 0
    try:
        for v in vecs:
            if v.get("direction") == "server_to_feeder":
                continue
            n_vec += 1
            wire = bytes.fromhex(v["hex"])
            if v.get("signal_mode") == "dbm":  # decoded as after 'C' with bit 0
                wire = P.enc_caps(P.CAPS_CONFIRM, P.CAP_KNOWN) + wire
            want = expected_readings(v)
            queries = sum(f.get("kind") == "caps_query" for f in v["decoded"])
            s = socket.create_connection(("127.0.0.1", PORT_IN))
            s.sendall(wire)
            back = recv_some(s, 64, 0.6 if queries else 0.3)
            s.close()
            got = rs.readings(len(want))
            good = got == want and back == (answer if queries else b"")
            n_ok += good
            if not good:
                print(f"  {v['name']}: readings {got} want {want}, back {back.hex()} ({queries} queries)")
        check(n_ok == n_vec, f"vectors through readsb: {n_ok}/{n_vec} byte-exact (signal byte per frame, answers)")

        # one answer per connection: a second query is ignored, a client 'A' is ignored
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        s.sendall(P.enc_uuid(UUID) + P.enc_caps("Q", 15) + P.enc_caps("Q", 15) + P.enc_caps("A", 15))
        back = recv_some(s, 64, 1.0)
        s.close()
        check(back == answer, f"two queries and an 'A': one answer ({back.hex()})")
        # a second 'C' doesn't change the mode
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        ds = bytes.fromhex("5d4840d6abcdef")
        s.sendall(P.enc_caps("C", 15) + P.enc_mode_s(ds, 1, dbm=-87) + P.enc_caps("C", 14) + P.enc_mode_s(ds, 2, dbm=-87))
        time.sleep(0.3)
        s.close()
        got = rs.readings(2)
        check(got == [("dbm", 0xa9), ("dbm", 0xa9)], f"second 'C' ignored: {got}")
        # a plain Beast client gets nothing back
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        s.sendall(P.enc_uuid(UUID) + P.enc_mode_s(ds, 1, rssi=4))
        back = recv_some(s, 64, 1.0)
        s.close()
        check(back == b"" and rs.readings(1) == [("power", 4)], "no query: nothing sent back, power byte")
    finally:
        rs.stop()


def test_answers(tmp):
    vecs = {v["name"]: v for v in json.loads((D / "vectors" / "feed_vectors.json").read_text())}
    for caps, name in ((None, "answer_all_dbm"), ("14", "answer_no_dbm"), ("4", "answer_rid_only"), ("0", "answer_none")):
        rs = Readsb(tmp, [f"--readsbee-caps={caps}"] if caps else [])
        try:
            s = socket.create_connection(("127.0.0.1", PORT_IN))
            s.sendall(P.enc_uuid(UUID) + P.enc_caps("Q", 15))
            back = recv_some(s, 6, 2.0)
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


def feeder(rs, delay, query=True, seconds=7.0, rate=200, icao0=0x700000):
    """The feeder: E4 + query, Beast at once, 'C' when the answer is seen (delay s after it
    arrived; ignored after 5 s), then the confirmed bits. Returns what it sent: (mode, byte) per
    signal reading, the Mode S frames by ICAO, and the confirmed bits (None = plain)."""
    s = socket.create_connection(("127.0.0.1", PORT_IN))
    s.setblocking(False)
    t0 = time.time()
    s.sendall(P.enc_uuid(UUID) + (P.enc_caps(P.CAPS_QUERY, P.CAP_KNOWN) if query else b""))
    scan = P.AnswerScanner()
    arrived = None
    bits = None
    sent = []
    modes = {}
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
            if time.time() - t0 <= P.CAPS_ANSWER_TIMEOUT_S:
                bits = P.negotiate(P.CAP_KNOWN, scan.answer[1])
                s.sendall(P.enc_caps(P.CAPS_CONFIRM, bits))
            else:
                bits = -1  # too late: plain until this connection closes
        dbm_mode = bits is not None and bits > 0 and bits & P.CAP_SIG_DBM
        d = -105 + (i * 7) % 80  # -105 .. -26 dBm
        icao = icao0 + i
        if dbm_mode:
            frame, sig = P.enc_mode_s(df17(icao), i, dbm=d), ("dbm", P.dbm_byte(d))
        else:
            frame, sig = P.enc_mode_s(df17(icao), i, rssi=P.dbm_to_power(d)), ("power", P.dbm_to_power(d))
        modes[icao] = sig
        sent.append(sig)
        out = frame
        if i % 10 == 5:  # UAT, ADS-L and Remote ID too (readsbee decodes them even from feeds that didn't query)
            up = bool(bits and bits > 0 and bits & P.CAP_UAT_MODES_CLOCK)
            if dbm_mode:
                out += P.enc_uat("s", i, None, bytes(30), modes_clock=up, dbm=d)
                out += P.enc_adsl(ADSL_ONAIR, i, d, "a")
                out += P.enc_rid(ODID, 0, d, "b", MAC)
                sig = ("dbm", P.dbm_byte(d))
            else:
                b = P.dbm_to_power(d)
                out += P.enc_uat("s", i, b, bytes(30), modes_clock=up)
                out += P.enc_adsl(ADSL_ONAIR, i, None, "a", rssi=b)
                out += P.enc_rid(ODID, 0, None, "b", MAC, rssi=b)
                sig = ("power", b)
            sent += [sig, sig, sig]
        s.setblocking(True)
        s.sendall(out)
        s.setblocking(False)
        i += 1
        time.sleep(1 / rate)
    s.close()
    return sent, modes, bits


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
                body = f.body
                msg = body[7:]
                out[int.from_bytes(msg[1:4], "big")] = body[6]
        return out
    return s, drain


def test_feeder(tmp):
    cases = [("answer at once", {}, 0.0, True, "dbm"),
             ("answer after 1 s", {}, 1.0, True, "dbm"),
             ("answer after 6 s (timeout)", {}, 6.0, True, "plain"),
             ("server without bit 0", {"caps": "14"}, 0.0, True, "no_dbm"),
             ("feeder never queries", {}, 0.0, False, "plain")]
    for k, (name, opt, delay, query, mode) in enumerate(cases):
        rs = Readsb(tmp, [f"--readsbee-caps={opt['caps']}"] if "caps" in opt else [])
        try:
            out, drain = beast_out_levels(PORT_OUT)
            sent, modes, bits = feeder(rs, delay, query, icao0=0x700000 + k * 0x10000)
            got = rs.readings(len(sent), timeout=10)
            misread = sum(a != b for a, b in zip(got, sent)) + abs(len(got) - len(sent))
            n_dbm = sum(m == "dbm" for m, _ in sent)
            want_dbm = {"dbm": n_dbm > 0, "plain": n_dbm == 0, "no_dbm": n_dbm == 0}[mode]
            check(misread == 0 and want_dbm and (mode != "plain" or bits in (None, -1)),
                  f"feeder, {name}: {len(sent)} levels, {n_dbm} in dBm, misread {misread}, confirmed bits {bits}")
            # the Beast output carries each frame's level as a standard power byte
            time.sleep(1.5)
            levels = drain()
            out.close()
            bad = 0
            for icao, (m, b) in modes.items():
                if icao not in levels:
                    continue
                if m == "dbm":
                    lvl = 0 if b == 0x80 else min(1.0, 10 ** (0.075 * ((b - 256 if b > 127 else b) + 40)))
                else:
                    lvl = (b / 255) ** 2
                want = min(255, max(1, round(math.sqrt(lvl) * 255)))
                bad += abs(levels[icao] - want) > 1
            check(len(levels) > len(modes) * 0.9 and bad == 0,
                  f"feeder, {name}: Beast output levels {len(levels)}/{len(modes)} frames, {bad} off")
        finally:
            rs.stop()


def test_json(tmp):
    """aircraft.json: rssi stays dBFS, dbm only from dBm feeds; remoteid.json likewise."""
    rs = Readsb(tmp)
    try:
        a, b = 0x7A0001, 0x7A0002
        s = socket.create_connection(("127.0.0.1", PORT_IN))
        s.sendall(P.enc_uuid(UUID) + P.enc_caps("Q", 15))
        recv_some(s, 6, 1.0)
        s.sendall(P.enc_caps("C", 15) + b"".join(P.enc_mode_s(df17(a), i, dbm=-87) for i in range(8)))
        t = socket.create_connection(("127.0.0.1", PORT_IN))
        t.sendall(P.enc_uuid(UUID) + b"".join(P.enc_mode_s(df17(b), i, rssi=P.dbm_to_power(-87)) for i in range(8)))
        time.sleep(2.5)
        ac = {x["hex"]: x for x in json.loads((rs.jdir / "aircraft.json").read_text())["aircraft"]}
        da, db = ac.get(f"{a:06x}", {}), ac.get(f"{b:06x}", {})
        check(da.get("dbm") == -87 and abs(da.get("rssi", 0) - 0.75 * (-87 + 40)) < 0.2,
              f"aircraft.json, dBm feed: dbm {da.get('dbm')}, rssi {da.get('rssi')} dBFS")
        check("dbm" not in db and abs(db.get("rssi", 0) - 20 * math.log10(4 / 255)) < 0.2,
              f"aircraft.json, power-byte feed: no dbm, rssi {db.get('rssi')} dBFS")
        s.close()
        t.close()
    finally:
        rs.stop()


def test_captures(tmp, d):
    for name in ("beast.bin", "readsbee.bin"):
        data = (Path(d) / name).read_bytes()
        want = [f for f in P.Decoder().feed(data) if f.type in (0x31, 0x32, 0x33, 0xEC, 0xED, 0xEF)]
        rs = Readsb(tmp)
        try:
            s = socket.create_connection(("127.0.0.1", PORT_IN))
            for i in range(0, len(data), 8192):
                s.sendall(data[i:i + 8192])
                time.sleep(0.001)
            time.sleep(1)
            got = rs.readings(len(want), timeout=20)
            s.close()
            exp = [("power", f.body[6]) for f in want]
            n_ef = sum(f.type == 0xEF for f in want)
            check(got == exp, f"capture {name}: {len(got)}/{len(exp)} signal bytes read as power bytes ({n_ef} 0xEF)")
            if n_ef:
                time.sleep(1.5)
                rid = json.loads((rs.jdir / "remoteid.json").read_text())
                ids = [x.get("id") for x in rid.get("drones", [])]
                check(ids == ["ADSBEEBENCHA"] and all("dbm" not in x for x in rid["drones"]),
                      f"capture {name}: drones {ids}, levels as power bytes (no dbm)")
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
