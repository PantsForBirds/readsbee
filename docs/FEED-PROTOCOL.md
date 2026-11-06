# readsbee feed protocol v2

One Mode S Beast TCP stream from an ADSBee to readsbee, carrying Mode S, UAT, ADS-L and Remote
ID. Status: **v2, implemented** in readsbee (`readsbee_ext.c`) and ADSBee firmware feeds set to
`READSBEE`. Servers may accept or refuse feeds by policy; this spec doesn't cover that.

v2 changes from the v1.x drafts: one Beast type per encapsulation in the ADSBee UAT style, no
`0xEE` umbrella, no text in the feed (hello and `0xE9` dropped), no proof frame.

Reference code: [`tests/readsbee_proto.py`](../tests/readsbee_proto.py)
(`python3 tests/readsbee_proto.py` → `vectors ok`, checks
[`tests/vectors/feed_v2_vectors.json`](../tests/vectors/feed_v2_vectors.json)). readsbee's own
decoder is tested against the same vectors (`beetests.c`, `tests/readsbee_net_test.py`).

## 1. Frame types

| Type | Name | After the type byte | Status |
|---|---|---|---|
| `0x32` / `0x33` | Mode S short / long | ts6 rssi1 + 7 / 14 | Beast |
| `0xE3` | readsb receiver ID | 8 | readsb |
| `0xE4` | readsb feed UUID | 36 ASCII | readsb |
| `0xEC` | UAT | letter `s l u` / **`S L U`**, ts6 rssi1 + 30 / 48 / 552 | ADSBee + readsb; upper case new |
| **`0xED`** | **ADS-L** | letter `A B X`, ts6 dbm1 rep1 + on-air (1 + L) | new |
| **`0xEF`** | **Remote ID** | letter `B C E W N`, ts6 dbm1 mac6 + ODID (25 or 3 + 25n) | new |

**Why these codes.** Re-checked free in readsb dev (`bf8f8fd`, current), dump1090-fa, mlat-client,
mlat-server, beast-splitter and ADSBee firmware (main and ADS-L branches): `E1 E2 E5–E7 EA ED
EF–FF`.
- `0xED` sits next to UAT `0xEC`: both are CC13xx sub-GHz packets with the same timestamp path.
- `0xEF` for Remote ID. `0xEE` is skipped on purpose: v1.x drafts used it with a different
  layout, and test captures may exist.
- FANET / OGN: nothing reserved. They'd take one free code each (`E5`–`E7`, `F0`+) with the
  same shape, and a decoder doesn't need to know them in advance (§3).

## 2. Wire rules

- `0x1a <type> <letter> <body>` for `0xEC`, `0xED`, `0xEF`; `0x1a <type> <body>` for the rest.
- Every `0x1a` in the body is sent as `1a 1a`. The type byte and the letter are never escaped and
  are never `0x1a`: letters are ASCII.
- Integers big-endian. ts6 is 6 bytes.
- Signal level:
  - `0x32`/`0x33` and UAT `0xEC` (`s l u` and `S L U`): **rssi1**, the Beast power byte
    (firmware `WriteRSSIdBmAsBeastPowerLevel`). It's amplitude, 255 at −40 dBm,
    round(255 × 10^(dBFS/20)), so it bottoms out at 1 near −100 dBm (0 = no level).
  - `0xED` ADS-L and `0xEF` Remote ID: **dbm1**, signed int8 dBm, e.g. −108 dBm = `0x94`.
    **`0x80` (−128) = no level.** ADS-L decodes down to about −108 dBm, below the power byte's
    floor, and both radios report dBm directly.
- **Letter case = clock.** Upper case: ts6 is on this connection's Mode S clock (the 12 MHz
  counter of its `0x32`/`0x33` frames), MLAT-grade; **ts6 = 0 means not synced yet** (about 2–3 s
  after boot, maybe after a `SUBG_MODE` switch). Lower case: ts6 isn't on the Mode S clock;
  never use it for MLAT.
- Every payload bounds itself, so there is no LEN byte (§3).
- Largest frames, escaped worst case: UAT `U` 1 + 2 + 2 × 559 = 1121 (unchanged), Remote ID
  pack 2 + 1 + 2 × 241 = 485, ADS-L 2 + 1 + 2 × 40 = 83.

## 3. Bounds and resync

| Type | Length known from |
|---|---|
| UAT | the letter: 30 / 48 / 552 |
| ADS-L | on-air length byte L (first payload byte): 1 + L bytes, L ≤ 31 |
| Remote ID | first ODID byte: high nibble ≠ `F` → 25; `F` → pack: next bytes size (= 25) and count n (1–9), 3 + 25n |

A decoder that meets an unknown type, an unknown letter, or a bound that fails (L > 31, pack size
≠ 25, n > 9) skips to the next frame start: the next `0x1a` not followed by `0x1a`. The escape
rule makes this safe; only that frame is lost. readsbee already skips unknown `0xE0`–`0xFF` types
this way.

## 4. ADS-L `0xED`

```
1a ED  A|B|X  ts6  dbm1  rep1  L  onair[L]
```

- **Letter = channel**: `A` 868.2 MHz, `B` 868.4 MHz, `X` unknown. Lower case `a b x` is
  defined (clock not Mode S) but ADS-L Beast output only exists in firmware with the sub-GHz
  clock fix, so it always sends upper case.
- **rep1**: Manchester erasures repaired against the CRC, 0–6 (0 best), `FF` unknown. It's a
  quality measure that doesn't fit the letter; one byte.
- **L + onair**: the bytes after the sync word, length byte first, through the CRC-24
  (`RawADSLPacket.buffer`). L counts network header + data + CRC (12–31 today).
- Not sent: CRC state (only CRC-valid packets leave the radio), protocol version (inside the
  packet).
- ts reference point: end of the sync word, as for UAT with that clock fix.

## 5. Remote ID `0xEF`

```
1a EF  B|C|E|W|N (b|c|e|w|n)  ts6  dbm1  mac6  odid[25 | 3+25n]
```

- **Letter = transport**: `B` BT4 legacy, `C` BT5 Coded (long range), `E` BT5 extended 1M,
  `W` Wi-Fi beacon, `N` Wi-Fi NaN. Needed to interpret the packet and for coverage per link type.
- **mac6**: source address in display order (BLE AdvA, Wi-Fi SA). Needed: BLE legacy carries one
  ODID message per packet, and the address is what ties a drone's Basic ID to its Location.
- **odid**: one ASTM F3411 25-byte message, or a message pack, as received.
- **Timestamp.** The ESP32 only has ms time, not the Mode S clock. Send lower case with
  **ts6 = 0**: readsbee stamps arrival time, which is good enough for Remote ID (no MLAT). Upper
  case is kept for a later firmware that can time Remote ID on the Mode S clock.
- Left out (minimal): BLE address type (public / random; collisions between drones are
  negligible), channel, ODID counter (dedupe only, firmware drops it today), CRC/version.

## 6. UAT `0xEC` and its timestamps

```
1a EC  s|l|u  ts6  rssi1  payload        today: ts6 = raw CC13xx radio ticks, not MLAT
1a EC  S|L|U  ts6  rssi1  payload        new: ts6 on the Mode S clock, 0 = not synced
```

**Upper-case UAT letters are the marker.** Firmware with
the sub-GHz clock fix sends `S L U` on READSBEE feeds and keeps `s l u` on BEAST feeds. readsbee
trusts UAT timestamps only from upper-case frames. Nothing is inferred from firmware versions,
and old firmware (lower case) is never trusted. Same payloads, so the decode is unchanged.

**Stock readsb and an unknown UAT letter** (readsb `net_io.c`, measured against stock readsb):
- The UAT frame is dropped, and the rest of it is scanned as garbage. Mode S decoding is unaffected.
- With `--net-ingest` (whereplane, most aggregators), **one `U` uplink or a burst of about 20
  `S` frames gets the feed closed** ("Garbage: Close"). Single `S` frames between Mode S frames
  pass. Without `--net-ingest`, nothing is closed.
- So upper-case UAT, like `0xED`/`0xEF`, only goes out on READSBEE feeds.

## 7. Opt-in

- **Per-feed protocol setting** (firmware `AT+FEED…`): `BEAST` (today) or `READSBEE`. Only
  READSBEE feeds send `0xED`, `0xEF` and upper-case UAT. This is the whole opt-in. Stock servers
  close feeds that get many unknown frames (§6), so never default to it.
- **No server → feeder signal.** Without a hello there's nothing to wait for; the user picks
  READSBEE for a readsbee server. A READSBEE feed pointed at a stock server degrades the way
  §6 shows: dropped frames, occasional closes, no corruption.
- readsbee treats BEAST and READSBEE feeds the same on input. The only difference it sees is
  which frames arrive.

## 8. Forwarding

- readsbee keeps stock output: `beast_out`, `beast_reduce_out` and `beast_reduce_plus_out` carry
  Mode S only, rebuilt from decoded messages. `0xED`, `0xEF` and `0xEC` never go upstream (the
  current code path; `tests/readsbee_net_test.py` checks that an upstream sink gets Mode S only).
- Later, opt-in only: a readsbee-to-readsbee output that relays the new frames verbatim with an
  `0xE3` prefix.
