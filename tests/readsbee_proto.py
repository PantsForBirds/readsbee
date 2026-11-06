#!/usr/bin/env python3
"""readsbee feed protocol v2: reference encoder/decoder.

Spec: FEED-PROTOCOL.md. Golden vectors: tests/vectors/feed_v2_vectors.json.
  python3 readsbee_proto.py           check against vectors.json -> "vectors ok"
  python3 readsbee_proto.py --write   regenerate vectors.json

Wire rules (all frames): 0x1a <type> [<msg type letter>] <body>. Every 0x1a in <body> is sent
twice. The type byte and the msg type letter are never escaped (and never 0x1a).
Integers are big-endian.
"""
from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

ESC = 0x1A

# ---- frame types (byte after 0x1a) ---------------------------------------------------------
T_MODE_AC = 0x31
T_MODE_S_SHORT = 0x32
T_MODE_S_LONG = 0x33
T_INGEST_ID = 0xE3       # readsb: 8-byte receiver id
T_UUID = 0xE4            # readsb: 36 ASCII chars
T_UAT = 0xEC             # ADSBee/readsb: UAT
T_ADSL = 0xED            # v2: ADS-L
T_RID = 0xEF             # v2: Remote ID (ODID)

MODE_LEN = {T_MODE_AC: 2, T_MODE_S_SHORT: 7, T_MODE_S_LONG: 14}

# Msg type letters. Lower case: timestamp NOT on the Mode S clock (unusable for MLAT).
# Upper case: timestamp on this connection's Mode S clock, 0 = not synced yet.
UAT_LEN = {"s": 30, "l": 48, "u": 552}                     # payload bytes, same for S/L/U
ADSL_CH = {"a": "868.2", "b": "868.4", "x": None}         # A/B/X: same, Mode S clock
RID_TR = {"b": "bt4_legacy", "c": "bt5_coded", "e": "bt5_ext_1m", "w": "wifi_beacon", "n": "wifi_nan"}

ADSL_MIN_L, ADSL_MAX_L = 1, 31      # on-air length byte (firmware: 12..31 today)
ODID_MSG = 25
ODID_PACK_MAX = 9
REP_UNKNOWN = 0xFF
DBM_NONE = -128                     # 0xED/0xEF signal: int8 dBm, -128 (0x80) = no level


def escape(body: bytes) -> bytes:
    return body.replace(b"\x1a", b"\x1a\x1a")


def _letter(ch: str, table: dict, modes_clock: bool) -> int:
    if ch.lower() not in table:
        raise ValueError(f"bad msg type {ch!r}")
    return ord(ch.upper() if modes_clock else ch.lower())


def _hdr(ts: int, rssi: int) -> bytes:
    """ts6 + Beast power byte (Mode S, UAT)."""
    return ts.to_bytes(6, "big") + bytes([rssi])


def _hdr_dbm(ts: int, dbm: int) -> bytes:
    """ts6 + signed int8 dBm (ADS-L, Remote ID), -128 = no level."""
    return ts.to_bytes(6, "big") + struct.pack("b", max(-128, min(127, dbm)))


# ---- encoders ------------------------------------------------------------------------------
def enc_mode_s(msg: bytes, ts: int, rssi: int) -> bytes:
    t = {2: T_MODE_AC, 7: T_MODE_S_SHORT, 14: T_MODE_S_LONG}[len(msg)]
    return bytes([ESC, t]) + escape(_hdr(ts, rssi) + msg)


def enc_uuid(uuid: str) -> bytes:
    return bytes([ESC, T_UUID]) + uuid.encode()


def enc_uat(kind: str, ts: int, rssi: int, payload: bytes, modes_clock: bool) -> bytes:
    """kind s/l/u. modes_clock=True sends S/L/U (READSBEE feeds only)."""
    k = _letter(kind, UAT_LEN, modes_clock)
    if len(payload) != UAT_LEN[chr(k).lower()]:
        raise ValueError("bad UAT length")
    return bytes([ESC, T_UAT, k]) + escape(_hdr(ts, rssi) + payload)


def enc_adsl(onair: bytes, ts: int, dbm: int, channel: str, repaired: int = REP_UNKNOWN,
             modes_clock: bool = True) -> bytes:
    """onair = bytes after the sync word: length byte L, then L bytes (header .. CRC-24).
    channel 'a' 868.2, 'b' 868.4, 'x' unknown."""
    if not (ADSL_MIN_L <= onair[0] <= ADSL_MAX_L) or len(onair) != 1 + onair[0]:
        raise ValueError("bad ADS-L on-air buffer")
    k = _letter(channel, ADSL_CH, modes_clock)
    return bytes([ESC, T_ADSL, k]) + escape(_hdr_dbm(ts, dbm) + bytes([repaired]) + onair)


def enc_rid(odid: bytes, ts: int, dbm: int, transport: str, addr: bytes,
            modes_clock: bool = False) -> bytes:
    """odid = one 25-byte ASTM F3411 message, or a message pack (first byte 0xF?, size 25,
    count 1..9, then count x 25). addr = 6-byte source MAC, display order."""
    if len(addr) != 6 or _odid_len(odid) != len(odid):
        raise ValueError("bad Remote ID frame")
    k = _letter(transport, RID_TR, modes_clock)
    return bytes([ESC, T_RID, k]) + escape(_hdr_dbm(ts, dbm) + addr + odid)


def _odid_len(head: bytes):
    """Length of an ODID message or pack from its first 3 bytes. None = need more, False = bad."""
    if not head:
        return None
    if head[0] >> 4 != 0xF:
        return ODID_MSG
    if len(head) < 3:
        return None
    size, count = head[1], head[2]
    if size != ODID_MSG or not 1 <= count <= ODID_PACK_MAX:
        return False
    return 3 + count * ODID_MSG


# ---- decoder -------------------------------------------------------------------------------
@dataclass
class Frame:
    type: int
    letter: str
    body: bytes                      # unescaped body (after the type / letter byte)
    raw: bytes                       # bytes as on the wire
    fields: dict = field(default_factory=dict)


class Decoder:
    """Incremental stream decoder: feed(bytes) -> list[Frame].
    Unknown type or msg type letter: skip to the next frame start (0x1a followed by anything
    but 0x1a), the readsbee rule. Skipped bytes are counted in .skipped, frames in .unknown."""

    def __init__(self):
        self.buf = bytearray()
        self.skipped = 0
        self.unknown = 0

    def _take(self, i: int, n: int):
        """n unescaped bytes from buf[i:] -> (bytes, next_i); None = incomplete; False = a
        lone 0x1a (frame start) inside."""
        out = bytearray()
        b = self.buf
        while len(out) < n:
            if i >= len(b):
                return None
            x = b[i]
            i += 1
            if x == ESC:
                if i >= len(b):
                    return None
                if b[i] != ESC:
                    return False
                i += 1
            out.append(x)
        return bytes(out), i

    def _skip_frame(self, i: int):
        """Index of the next frame start after buf[i] (= 0x1a of this frame), None if unknown yet."""
        b = self.buf
        j = i + 2
        while True:
            j = b.find(ESC, j)
            if j < 0 or j + 1 >= len(b):
                return None
            if b[j + 1] == ESC:
                j += 2
                continue
            return j

    def _body(self, t: int, p: int):
        """Parse one frame body starting at buf[p] (after the type byte).
        Returns (letter, body, next) / None (incomplete) / False (lone 0x1a) / 'unknown'."""
        b = self.buf
        if t in MODE_LEN:
            r = self._take(p, 7 + MODE_LEN[t])
            return r and ("", r[0], r[1])
        if t == T_UUID:
            return ("", bytes(b[p:p + 36]), p + 36) if len(b) >= p + 36 else None
        if t == T_INGEST_ID:
            r = self._take(p, 8)
            return r and ("", r[0], r[1])
        if t not in (T_UAT, T_ADSL, T_RID):
            return "unknown"
        if p >= len(b):
            return None
        k = chr(b[p])
        p += 1
        if t == T_UAT:
            if k.lower() not in UAT_LEN:
                return "unknown"
            r = self._take(p, 7 + UAT_LEN[k.lower()])
            return r and (k, r[0], r[1])
        if t == T_ADSL:
            if k.lower() not in ADSL_CH:
                return "unknown"
            r = self._take(p, 7 + 1 + 1)              # ts rssi rep L
            if not r:
                return r
            L = r[0][-1]
            if not ADSL_MIN_L <= L <= ADSL_MAX_L:
                return "unknown"
            r2 = self._take(r[1], L)
            return r2 and (k, r[0] + r2[0], r2[1])
        # Remote ID
        if k.lower() not in RID_TR:
            return "unknown"
        r = self._take(p, 7 + 6 + 1)                  # ts rssi addr6 odid[0]
        if not r:
            return r
        if r[0][-1] >> 4 == 0xF:
            r2 = self._take(r[1], 2)
            if not r2:
                return r2
            n = _odid_len(r[0][-1:] + r2[0])
            if n is False:
                return "unknown"
            r3 = self._take(r2[1], n - 3)
            return r3 and (k, r[0] + r2[0] + r3[0], r3[1])
        r2 = self._take(r[1], ODID_MSG - 1)
        return r2 and (k, r[0] + r2[0], r2[1])

    def feed(self, data: bytes) -> list[Frame]:
        self.buf += data
        out: list[Frame] = []
        b = self.buf
        i = 0
        while True:
            j = b.find(ESC, i)
            if j < 0:
                self.skipped += len(b) - i
                i = len(b)
                break
            self.skipped += j - i
            i = j
            if i + 1 >= len(b):
                break
            t = b[i + 1]
            if t == ESC:                    # stray escaped pair: skip it
                self.skipped += 2
                i += 2
                continue
            res = self._body(t, i + 2)
            if res is None:
                break                       # incomplete, wait for more
            if res is False:
                self.skipped += 1           # lone 0x1a inside: resync there
                i += 1
                continue
            if res == "unknown":
                nxt = self._skip_frame(i)
                if nxt is None:
                    break
                self.unknown += 1
                self.skipped += nxt - i
                i = nxt
                continue
            letter, body, nxt = res
            f = Frame(t, letter, body, bytes(b[i:nxt]))
            f.fields = parse_fields(t, letter, body)
            out.append(f)
            i = nxt
        del b[:i]
        return out


def parse_fields(t: int, k: str, body: bytes) -> dict:
    if t == T_UUID:
        return {"kind": "uuid", "uuid": body.decode(errors="replace")}
    if t == T_INGEST_ID:
        return {"kind": "ingest_id", "id": body.hex()}
    ts, rssi, p = int.from_bytes(body[:6], "big"), body[6], body[7:]
    common = {"ts": ts, "rssi": rssi}
    if t in (T_ADSL, T_RID):
        dbm = struct.unpack("b", body[6:7])[0]
        common = {"ts": ts, "dbm": None if dbm == DBM_NONE else dbm}
    if t in MODE_LEN:
        return {"kind": {0x31: "mode_ac", 0x32: "mode_s_short", 0x33: "mode_s_long"}[t], **common, "msg": p.hex()}
    clock = ("modes" if ts else "unsynced") if k.isupper() else "not_mlat"
    if t == T_UAT:
        return {"kind": "uat_" + k.lower(), "clock": clock, **common, "msg": p.hex()}
    if t == T_ADSL:
        return {"kind": "adsl", "clock": clock, **common, "channel": ADSL_CH[k.lower()],
                "repaired": None if p[0] == REP_UNKNOWN else p[0], "onair": p[1:].hex()}
    odid = p[6:]
    return {"kind": "rid", "clock": clock, **common, "transport": RID_TR[k.lower()], "addr": p[:6].hex(":"),
            "odid": odid.hex(), "odid_msgs": odid_types(odid)}


def odid_types(odid: bytes) -> list[int]:
    """ASTM F3411 message types (high nibble) in a message or pack."""
    if odid[0] >> 4 == 0xF:
        return [odid[3 + i * ODID_MSG] >> 4 for i in range(odid[2])]
    return [odid[0] >> 4]


def decode_all(data: bytes) -> tuple[list[Frame], Decoder]:
    d = Decoder()
    return d.feed(data), d


# ---- golden vectors ------------------------------------------------------------------------
def _odid_msg(mtype: int, fill: int) -> bytes:
    return bytes([mtype << 4 | 0x2]) + bytes([fill]) * 24


def build_vectors() -> list[dict]:
    ts = 0x01_23_45_1A_67_89                     # contains 0x1a on purpose
    adsl_body = bytes.fromhex("00" "02" "1a" "3c4d5e6f" "1a1a" "00112233445566778899aabb" "0102" "a1b2c3")
    adsl = bytes([len(adsl_body)]) + adsl_body    # L = 26 = 0x1a: the length byte itself is escaped
    pack = bytes([0xF2, 25, 3]) + _odid_msg(0, 0x1A) + _odid_msg(1, 0x11) + _odid_msg(4, 0x44)
    mac = bytes.fromhex("c0ffee1a0001")
    v = []

    def add(name, wire, note=""):
        frames, d = decode_all(wire)
        v.append({"name": name, "note": note, "hex": wire.hex(),
                  "decoded": [dict(type=f.type, **f.fields) for f in frames],
                  "skipped": d.skipped, "unknown": d.unknown})

    add("uuid", enc_uuid("0123abcd-0123-4567-89ab-0123456789ab"))
    add("mode_s_long", enc_mode_s(bytes.fromhex("8d4840d6202cc371c32ce0576098"), ts, 0x1A),
        "DF17, ts and rssi contain 0x1a")
    add("uat_s_old", enc_uat("s", 0x00_00_00_00_1A_1A, 200, bytes(range(0x10, 0x10 + 30)), modes_clock=False),
        "BEAST feed / old firmware: ts not on the Mode S clock")
    add("uat_S_modes", enc_uat("s", ts, 0x1A, bytes(range(0x10, 0x10 + 30)), modes_clock=True),
        "READSBEE feed: ts on the Mode S clock")
    add("uat_L_unsynced", enc_uat("l", 0, 150, bytes([0x1A]) * 48, modes_clock=True),
        "READSBEE feed, sub-GHz clock not synced yet: ts 0")
    add("uat_U_uplink", enc_uat("u", ts, 90, bytes((i * 7) & 0xFF for i in range(552)), modes_clock=True),
        "uplink, 552 bytes")
    add("adsl_868_4", enc_adsl(adsl, ts, -87, "b", repaired=2), "L = 0x1a escaped, 2 erasures repaired, -87 dBm")
    add("adsl_868_2_unsynced", enc_adsl(adsl, 0, -108, "a", repaired=0), "ts 0 = not synced, -108 dBm = 0x94")
    add("adsl_channel_unknown", enc_adsl(adsl, ts, DBM_NONE, "x", repaired=REP_UNKNOWN),
        "no level: 0x80")
    add("rid_bt4_single", enc_rid(_odid_msg(1, 0x1A), 0, -72, "b", mac),
        "Location message, BT4 legacy, no timestamp")
    add("rid_wifi_beacon_pack", enc_rid(pack, 0, -60, "w", bytes.fromhex("6a1a2b3c4d5e")),
        "message pack: Basic ID, Location, System")
    add("rid_bt5_coded", enc_rid(_odid_msg(0, 0x22), 0, -95, "c", mac))
    tail = enc_mode_s(bytes.fromhex("5d4840d6abcdef"), 2, 2)
    add("unknown_type", bytes([ESC, 0xF5, ord("q")]) + escape(b"\x1a\x33" + bytes(20)) + tail,
        "unknown type: skipped to the next frame start, the Mode S frame after it decodes")
    add("unknown_uat_letter", bytes([ESC, T_UAT, ord("z")]) + escape(bytes(7) + b"\x1a\x1a\x33" + bytes(9)) + tail,
        "known type, unknown letter: same skip")
    mixed = b"".join(bytes.fromhex(x["hex"]) for x in v) + enc_mode_s(bytes(7), 1, 1)
    add("mixed_stream", mixed, "all of the above back to back, then a short Mode S frame")
    return v


def check(path: Path) -> int:
    want = json.loads(path.read_text())
    got = build_vectors()
    bad = 0
    for w, g in zip(want, got):
        if w != g:
            print("MISMATCH", w["name"])
            bad += 1
    if len(want) != len(got):
        bad += 1
    # decoded frames re-assemble to the input, and byte-at-a-time feeding gives the same frames
    for g in got:
        wire = bytes.fromhex(g["hex"])
        frames, d = decode_all(wire)
        known = b"".join(f.raw for f in frames)
        if g["unknown"] == 0 and known != wire:
            print("RAW MISMATCH", g["name"])
            bad += 1
        d2 = Decoder()
        slow = [f for x in wire for f in d2.feed(bytes([x]))]
        if [f.raw for f in slow] != [f.raw for f in frames]:
            print("STREAMING MISMATCH", g["name"])
            bad += 1
    print("vectors ok" if not bad else f"{bad} failures")
    return 1 if bad else 0


if __name__ == "__main__":
    vp = Path(__file__).parent / "vectors" / "feed_v2_vectors.json"
    if "--write" in sys.argv:
        vp.write_text(json.dumps(build_vectors(), indent=1) + "\n")
        print("wrote", vp)
    else:
        sys.exit(check(vp))
