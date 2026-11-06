# readsbee feed protocol v3.2

One Mode S Beast TCP stream from an ADSBee to readsbee, carrying Mode S, UAT, ADS-L and Remote
ID. Status: **approved by the admin 2026-11-06** with all eleven recommendations in §11 (item 11:
levels are an "uncalibrated estimate, 1 dB resolution", no ± figure). readsbee implements the
server side (`readsbee_ext.c`, README-readsbee.md). Servers may accept or refuse feeds by policy;
this spec doesn't cover that.

**v3.2 changes from v3.1** (admin, 2026-11-06: "query for the dBm capability, and if it doesn't
exist, feed all protocols in dBFS instead of dBm"; the conversion must be a lookup table):
- **Bit 0 now decides the signal byte of every frame type, `0xED` and `0xEF` included.** Bit 0
  confirmed: int8 dBm (`0x80` = no level). Otherwise: the Beast power byte (0 = no level).
  `0xED`/`0xEF` lose v2's fixed "always dBm" rule (§2, §4, §5). In power-byte mode they also
  get the −100 dBm floor and the −40 dBm ceiling: ADS-L below −100 dBm reads 1, Remote ID
  above −40 dBm reads 255.
- **Performance stated (§7.6):** the firmware's dBm → power byte is a 61-entry table (one clamp,
  one array read per frame, no math at runtime); dBm is a clamp and a cast. readsbee's power byte
  → level is one divide and one multiply today; its dBm path uses a 256-entry table built once.
- **Bit order (admin): the dBm capability is bit 0, the protocols follow:** bit 1 `0xED`
  ADS-L, bit 2 `0xEF` Remote ID, bit 3 upper-case UAT (v3.1 had ADS-L 0, Remote ID 1, UAT 2,
  dBm 3). All four bits is still `8F`. Bits 1–3 without dBm is `8E` (was `87`). Every
  query/answer/confirm vector changed accordingly.
- Vectors: power-byte variants of `0xED`/`0xEF` added. v2's single `0xED`/`0xEF` vectors keep
  their bytes and decoding, now tagged `signal_mode: dbm` (= after `C` with bit 0).
  `mixed_stream` keeps its bytes; its `0xED`/`0xEF` frames now decode as power bytes (no `C`).

**v3.1 changes from v3** (admin, 2026-11-06: "convert all packet power levels to signed dBm if
the server accepts this spec"):
- Capability **bit 0 = signal level in dBm** (bit 3 in v3.1; moved to bit 0 in v3.2). When both sides set it, the signal byte of
  `0x31`/`0x32`/`0x33` and UAT `0xEC` is **signed int8 dBm** (`0x80` = no level), like `0xED`/`0xEF`
  already are. Without it, nothing changes (§7.6).
- New **confirm frame `1a E5 'C' ver f0 f1`** (feeder → server, once, after the answer): the bits
  in effect from the next frame on. Needed because frames already in flight when the answer is
  sent still carry the power byte; readsbee switches at `C`, not at its answer (§7.1, §7.2).
- Stock servers: unchanged (they never answer, so they never get `C` or dBm). Not re-measured,
  except the feeder model (§10.3).

**v3 changes from v2** (admin, 2026-11-06, after reviewing PR #427): no READSBEE feed protocol.
Every TCP feed stays plain `BEAST` and starts with a 6-byte capabilities query (`0xE5 'Q'`, §7).
A server that answers (`0xE5 'A'`, readsbee) gets the v2 frames it accepts; any other server
gets today's Beast stream plus those 6 bytes. v2's frame definitions (§1–§6) are unchanged.

v2 changes from v1.2: one Beast type per encapsulation in the ADSBee UAT style, no `0xEE`
umbrella, no text in the feed (hello and `0xE9` dropped), no proof frame.

Reference code: [`tests/readsbee_proto.py`](../tests/readsbee_proto.py) (`python3 tests/readsbee_proto.py` → `vectors ok`, checks
[`tests/vectors/feed_vectors.json`](../tests/vectors/feed_vectors.json); vectors 1–15 are v2's, 16–28 v3's, 29–51 v3.1's, 52–60 v3.2's; see the v3.2 notes for the
`0xED`/`0xEF` ones). Stock-server measurements (§10: `test_caps_stock.py`, `results/`, v1.2 `results.txt`, v2
`results-uat-msgtype.txt`) were made outside this repo and aren't included.

## 1. Frame types

| Type | Name | After the type byte | Status |
|---|---|---|---|
| `0x32` / `0x33` | Mode S short / long | ts6 rssi1 + 7 / 14 | Beast |
| `0xE3` | readsb receiver ID | 8 | readsb |
| `0xE4` | readsb feed UUID | 36 ASCII | readsb |
| **`0xE5`** | **capabilities** | letter `Q` / `A` / `C`, ver1 bits2 (never `0x1a`) | new in v3 (§7); `C` new in v3.1 |
| `0xEC` | UAT | letter `s l u` / **`S L U`**, ts6 rssi1 + 30 / 48 / 552 | ADSBee + readsb; upper case new |
| **`0xED`** | **ADS-L** | letter `A B X`, ts6 sig1 rep1 + on-air (1 + L) | new |
| **`0xEF`** | **Remote ID** | letter `B C E W N`, ts6 sig1 mac6 + ODID (25 or 3 + 25n) | new |

**Why these codes.** Re-checked free in readsb dev (`bf8f8fd`; again for v3 at `e576cba`,
2026-11-06), dump1090-fa, mlat-client, mlat-server, beast-splitter and ADSBee firmware (main,
`ads-l`, `t0948-*`): `E1 E2 E5–E7 EA ED EF–FF`. v3 takes `0xE5`: next to `0xE4`, the other
connection-start frame.
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
- **Signal byte sig1 (v3.2)**, the same rule on every frame type (`0x31`–`0x33`, `0xEC`, `0xED`,
  `0xEF`), decided once per connection by bit 0 (§7.6):
  - **Bit 0 confirmed** (after `C`): **int8 dBm**, −127…+127, **`0x80` (−128) = no level**.
  - **Otherwise** (stock servers, before `C`, readsbee without bit 0): the **Beast power
    byte**, amplitude, round(255 × 10^(dBFS/20)) with dBFS = 0.75 × (dBm + 40): 255 at −40 dBm
    and above, 1 at −100 dBm and below, **0 = no level** (firmware `WriteRSSIdBmAsBeastPowerLevel`).
  - v2/v3.1 had `0xED`/`0xEF` always in dBm. v3.2 drops that: ADS-L (decodes to about
    −108 dBm) reads 1 below −100 dBm in power-byte mode, and Remote ID above −40 dBm reads 255.
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
this way (t-1061).

## 4. ADS-L `0xED`

```
1a ED  A|B|X  ts6  sig1  rep1  L  onair[L]        sig1: dBm or power byte, by bit 0 (§2)
```

- **Letter = channel**: `A` 868.2 MHz, `B` 868.4 MHz, `X` unknown. Lower case `a b x` is
  defined (clock not Mode S) but ADS-L Beast output only exists in firmware with the #409
  clock fix, so it always sends upper case.
- **rep1**: Manchester erasures repaired against the CRC, 0–6 (0 best), `FF` unknown. It's a
  quality measure that doesn't fit the letter; one byte.
- **L + onair**: the bytes after the sync word, length byte first, through the CRC-24
  (`RawADSLPacket.buffer`). L counts network header + data + CRC (12–31 today).
- Not sent: CRC state (only CRC-valid packets leave the radio), protocol version (inside the
  packet).
- ts reference point: end of the sync word, as for UAT after #409.

## 5. Remote ID `0xEF`

```
1a EF  B|C|E|W|N (b|c|e|w|n)  ts6  sig1  mac6  odid[25 | 3+25n]    sig1: by bit 0 (§2)
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

**Recommendation: upper-case UAT letters are the marker** (chat-105's proposal). Firmware with
the #409 clock fix sends `S L U` on feeds whose server accepted it (§7, bit 3) and `s l u`
everywhere else. readsbee
trusts UAT timestamps only from upper-case frames. Nothing is inferred from firmware versions,
and old firmware (lower case) is never trusted. Same payloads, so the decode is unchanged.

**Stock readsb and an unknown UAT letter** (`net_io.c:5760-5797`, measured: `results-uat-msgtype.txt`):
- The UAT frame is dropped, and the rest of it is scanned as garbage. Mode S decoding is unaffected.
- With `--net-ingest` (whereplane, most aggregators), **one `U` uplink or a burst of about 20
  `S` frames gets the feed closed** ("Garbage: Close"). Single `S` frames between Mode S frames
  pass. Without `--net-ingest`, nothing is closed.
- So upper-case UAT, like `0xED`/`0xEF`, only goes out after the server accepted it (§7).

## 7. Capabilities check (new in v3; replaces v2's READSBEE opt-in)

Every ADSBee **TCP** Beast feed (`BEAST`, `BEAST_NO_UAT`, `BEAST_NO_UAT_UPLINK`) asks the server
once per connection what it accepts. Only an answer turns on `0xED`, `0xEF`, upper-case UAT and
(v3.1) dBm signal levels.
No answer = today's Beast. UDP feeds, MQTT and USB/serial Beast never query (no back channel)
and stay plain. The `READSBEE` value of `AT+FEED` goes away; #427 is reworked after approval.

### 7.1 Frames

```
query   feeder -> server   1a E5 'Q' ver f0 f1      6 bytes, sent once, right after 0xE4
answer  server -> feeder   1a E5 'A' ver f0 f1      6 bytes, sent once, only in reply to a query
confirm feeder -> server   1a E5 'C' ver f0 f1      6 bytes, sent once, after the answer (v3.1):
                                                    the bits in effect from the next frame on
        ver = 0x80 | version (1 -> 0x81)
        f0  = 0x80 | feature bits 0-6,   f1 = 0x80 | feature bits 7-13
```

| bit | Feature | In the query (feeder can send) | In the answer (server accepts) |
|---|---|---|---|
| **0** | **signal level in dBm** (v3.1; first bit since v3.2) | always (every ADSBee path has dBm) | reads the signal byte of **every** frame (`0x31`–`0x33`, `0xEC`, `0xED`, `0xEF`) as int8 dBm after `C`; without it, all are power bytes |
| 1 | `0xED` ADS-L | sub-GHz radio in ADS-L mode with #409 clock | decodes `0xED` |
| 2 | `0xEF` Remote ID | Remote ID receive on | decodes `0xEF` |
| 3 | `0xEC` upper-case `S L U` | firmware with #409 clock fix | trusts / accepts `S L U` |
| 4–13 | reserved | 0 | 0; ignored by the feeder |

- After an answer the feeder sends **query bits AND answer bits** (known bits only). An answer of
  `81 80 80` (nothing) is valid: plain Beast. A newer version may add bits; each side uses what
  it knows. A higher `ver` doesn't change the frame size.
- **Never contains `0x1a`, never escaped:** the letter is ASCII, every other byte has the high
  bit set. So no escape state is needed on either side, the frame can't end in a half escape,
  and dump1090-fa's one-byte resync (§10) can't land inside it.
- **Can't be mistaken for anything else:** `0xE5` is unused (§1); Beast data frames are
  `0x31`–`0x35`, readsb commands `P` `W` (and `1` in its output-port reader); `E5` is none of these.
  `Q`/`A` keeps one code for both directions and tells an answer from a reflected query.
- One query per connection. A server answers the first query only; later ones are ignored.
- **Confirm (v3.1):** right after it reads the answer, before its next frame, the feeder sends
  `C` with query bits AND answer bits (also when that is 0). It's the only switch point: frames
  before `C` use today's encoding (power byte, `s l u`, no `0xED`/`0xEF`), frames after it use
  the confirmed bits. Bits 1–3 are visible in the frames themselves; bit 0 isn't (the same byte
  means something else), so readsbee must switch on `C`, never on the time it answered or on
  the values. Only one `C` per connection; it never reaches a stock server (they never answer).

### 7.2 Sequence

```
ADSBee (feeder)                                        server
   | TCP connect                                          |
   |-- 1a E4 <uuid 36>  1a E5 Q 81 8F 80 --------------->|  one send(): E4, then the query
   |-- Beast as today (0x32/0x33, UAT s l u) ----------->|
   |                                                      |  readsbee: replies at once
   |<----------------------------- 1a E5 A 81 8F 80 -----|  stock readsb: skips 6 bytes, no reply
   |-- (frames already in flight: power byte) ---------->|
   |-- 1a E5 C 81 8F 80 -------------------------------->|  switch point (v3.1)
   |-- + 0xED, 0xEF, UAT S L U, dBm levels (agreed bits)>|
   |                                                      |
   no answer within 5 s: plain Beast until this connection closes
```

- **Query after `0xE4`, not before.** The firmware already insists the stream starts with
  `0xE4` (`comms_ip.cpp` `FinishFeedSocketConnect`): readsb ingest keys the feed on it, and a
  `Garbage: Close` (never expected here) would then still name the feed. Same `Write()`, so both
  go in one TCP segment.
- **Waiting:** up to **5 s** (`CAPS_ANSWER_TIMEOUT_S`, same as the TCP connect timeout). Mode S
  and lower-case UAT go out as usual from the first moment. `0xED`/`0xEF` frames produced while
  waiting are dropped, not queued (a few seconds of drone/glider data; no extra RAM). An answer
  after the timeout is ignored.
- **Reconnect:** every new connection queries again. Nothing is cached across connections or
  servers (the hostname may move, a readsbee may be replaced by stock readsb).
- **Old servers see exactly today's stream plus those 6 bytes.** No other byte changes: no
  extension frames, UAT stays lower case, same order and timing.

### 7.3 What comes back from servers that don't answer

The feeder must read and skip whatever else a server sends on the feed socket:

| Server | Sends to a Beast-input client | Source |
|---|---|---|
| readsb, `--net-receiver-id`, no `--net-ingest` | ping `1a 50 p2 p1 p0` (escaped) every 5 s, for 20 s unless answered | `net_io.c:1383-1407`, `readsb.c:2123` |
| readsb `--net-ingest` | nothing, unless the feeder sent `1a 57 4f` ("W O") | `net_io.c:1398` |
| readsb plain, dump1090-fa | nothing | measured (§10) |

Rule (reference `AnswerScanner` in `readsbee_proto.py`): scan for `0x1a`; `1a 1a` is an escaped
byte, skip both; `1a E5` + 4 bytes is a candidate, valid only if the letter is `A` and the other
three have the high bit set; anything else, skip to the next `0x1a`. A `0x1a` inside the 4 bytes
starts a new frame. After the answer (or the timeout), keep draining the socket and drop the bytes,
so pings can't fill the receive window.

### 7.4 Firmware sketch (for the #427 rework, not part of this approval)

- `FinishFeedSocketConnect`: append the query to the `0xE4` frame for TCP Beast feeds.
- Per feed: `caps_state` (waiting / answered / plain), `caps_t0`, `caps_enabled` (16 bits), the
  scanner (1 state byte + 4 bytes). In `IPWANTask`, for each connected TCP feed:
  `recv(sock, buf, 64, MSG_DONTWAIT)` until `EAGAIN`, feed the scanner while waiting, drop the
  bytes otherwise; after 5 s without an answer → plain.
- Reporting: `0xED` only if bit 1, `0xEF` only if bit 2, UAT letter upper case only if bit 3,
  dBm signal byte only if bit 0 (§7.6). The `NO_UAT` variants still decide whether UAT goes out.
- On the answer: queue `C` into that feed's send buffer before its next frame, then move the
  feed to its new reporting group. The per-feed send buffer is FIFO, so the order holds even
  with a backlog.

### 7.5 readsbee side

- `readBeast`: new branch for `0xE5`: wait for 4 bytes; if valid `Q` and first on this
  connection, store the offered bits, queue `1a E5 A 81 <accept>` and flush. No garbage counted
  for a valid frame. `C` (v3.1): store `c->caps_active = bits & accept`, once; from the next frame
  on, read the signal byte as dBm if bit 0 is set. `A` from a client, a second `C`, or a
  malformed frame: skip like an unknown type.
- `accept` = all known bits by default (option to narrow it per server, e.g. Remote ID only).
- Input is still treated the same for every feed (v2 rule): extension frames from a feed that
  didn't query are decoded anyway. The answer only steers what an ADSBee sends.
- `0xE5` is never forwarded (outputs are rebuilt from decoded messages, §8).

### 7.6 Signal level: dBm or power byte (bit 0; v3.1, all frame types since v3.2)

**Encoding.** After `C` with bit 0, the signal byte of **every** frame (`0x31`/`0x32`/`0x33`,
`0xEC` all letters, `0xED`, `0xEF`) is signed int8 dBm: `round(sigs_dbm)` clamped to −127…+127,
**`0x80` (−128) = no level** (firmware `INT16_MIN`). Without bit 0 (stock servers, before `C`, a
readsbee that didn't accept it) every one of them, `0xED`/`0xEF` included, carries the Beast power
byte, **0 = no level**. Same position, same frame lengths; only the byte's meaning changes.
ADSBee levels are about −110…0 dBm in practice.

| Mode | Mode S, UAT | ADS-L `0xED` | Remote ID `0xEF` | No level |
|---|---|---|---|---|
| bit 0 confirmed | int8 dBm | int8 dBm | int8 dBm | `0x80` |
| otherwise | power byte | **power byte** (new in v3.2) | **power byte** (new in v3.2) | `0` (firmware sends 1 today, §11 item 10) |

Power-byte limits for the new frames: ADS-L decodes down to about −108 dBm, so everything at or
below −100 dBm reads 1 (vector `adsl_868_2_power_floor`). In the t1069 capture, Remote ID levels
were −85…−34 dBm, so the strongest drones read 255 (`rid_bt4_power_saturated`).

**Performance (admin requirement: lookup table).**
- **Firmware, power byte (today, unchanged):** `WriteRSSIdBmAsBeastPowerLevel`
  (`beast_utils.cpp:93`) clamps `sigs_dbm` to −100…−40 and reads `kRSSIdBmToRSSIdBFS[61]`
  (uint8, `beast_tables.hh`, generated offline by `generate_beast_tables.py`). That's one clamp
  and one array read per frame, no floating point or `pow`/`log` at runtime, on the RP2040 and the
  ESP32. v3.2 reuses it as is for `0xED`/`0xEF` in power-byte mode.
- **Firmware, dBm:** a clamp to −127…+127 and a cast (`INT16_MIN` → `0x80`). Cheaper than the table.
- **readsbee, power byte → level:** `(b / 255)²`, one divide and one multiply
  (`net_io.c:4540-4541`, `:5063-5065`); no `pow`, nothing to change. It could be a 256-entry table
  too, but there's nothing to gain.
- **readsbee, dBm → level:** `10^(0.075 × (d + 40))` would be a `pow` per frame, so readsbee builds
  a **256-entry `double` table once at startup**, indexed by the raw byte (`0x80` → 0, capped at
  1.0). Per frame that's one array read, the same cost as today. Reference:
  `signal_level_from_dbm` in `readsbee_proto.py`.
- **Output** (unchanged): readsb rebuilds the power byte with `sqrt` per output frame
  (`:1813`) and clamps it to 1…255 (`:1814-1817`).

**Escaping.** The byte is part of the body, so the existing rule covers it: `0x1a` (+26 dBm,
impossible in practice) goes out as `1a 1a` (vector `mode_s_dbm_plus26_escaped`). Nothing new:
the power byte is already `0x1a` for real signals (byte 26 ≈ −66 dBm), so worst-case frame
lengths don't change.

**Calibration.** The levels are the firmware's existing estimates: an **uncalibrated estimate,
1 dB resolution** (approved wording, item 11). Levels from one unit and one radio path are
comparable with each other; across units, or across radio paths (1090 MHz Mode S, the sub-GHz
UAT/ADS-L radio, BLE/Wi-Fi Remote ID), they are separate estimates. dBm doesn't make levels more
accurate. It stops the firmware from throwing away resolution and range.

**Conversion.** Firmware table (`beast_tables.hh`, from `generate_beast_tables.py`): 0.75 dBFS
per dB, 0 dBFS at −40 dBm.

```
power byte from dBm (today):  d' = clamp(d, -100, -40);  dBFS = 0.75 * (d' + 40)
                              b  = round(255 * 10^(dBFS / 20))       (255 at -40, 1 at -100)
dBm from power byte:          d  = -40 + 20 * log10(b / 255) / 0.75  (b >= 1; 0 = no level)
                              b = 255 means "-40 dBm or stronger", b = 1 "about -100 or weaker"
readsbee, dBm byte -> power:  signalLevel = min(1, 10^(0.075 * (d + 40)))   (0x80 -> 0)
```

`readsbee_proto.py`: `dbm_to_power`, `power_to_dbm`, `dbm_byte`, `signal_level_from_dbm`.
`FW_POWER_TABLE` matches `beast_tables.hh` exactly.

| | Power byte (today) | dBm (bit 0) |
|---|---|---|
| Range | −100 … −40 dBm; all stronger signals read 255 | −127 … +127 dBm |
| Steps | 61 dBm values map to only 47 distinct bytes. Bytes 1–2 cover −100…−94 (byte 2 alone spans 6 dB), so the round trip is off by up to 4 dB near the floor | 1 dB everywhere |
| No level | firmware sends **1** (`INT16_MIN` clamps to the first table entry); Beast convention is 0 | `0x80` |

**Where a dBm-mode feed's frames go (readsbee `8fe0e98`).** readsbee turns the byte into
`mm->signalLevel` (power, 0…1) in exactly two places, and everything else reads that value:

| Place | Code | v3.1 |
|---|---|---|
| Mode S input | `net_io.c:4540-4550` `decodeBinMessage` | if the connection confirmed bit 0: the 256-entry dBm table, else today's `(b/255)²` |
| UAT `0xEC` input | `net_io.c:5063-5098` `decodeEncapsulatedUAT` | same |
| `0xED` / `0xEF` input (readsbee phase 2, not written yet) | new | same rule: power byte unless bit 0 was confirmed (v3.2) |
| Beast outputs (`beast_out`, `beast_reduce_out`, `beast_reduce_plus_out`, garbage out) | `:1772`, `:1813` `sig = sqrt(signalLevel) * 255` | unchanged: always a standard power byte (clamped to 255 at `:1816`). The 1.0 cap on the dBm table keeps JSON/stats at ≤ 0 dBFS, as with power-byte feeds |
| `--write-binary` / dump | `:2135` | unchanged (power byte) |
| SBS field 23, aircraft JSON `rssi`, stats peak / strong (> −3 dBFS = −36 dBm), track | `:3910`, `json_out.c:973`, `stats.c:106,537,881`, `track.c:864` | unchanged dBFS. Mixed feeds stay comparable: a dBm feed gives the same dBFS as the power byte would have, just unrounded |

- **mlat:** mlat-client reads readsbee's rebuilt Beast output (power byte). mlat-server never
  sees the feed. Unaffected.
- **readsbee-to-readsbee relay (§8, later):** the relaying readsbee is the feeder on that link and
  runs its own capabilities check. It sends dBm only if that link confirmed bit 0, and rebuilt
  power bytes otherwise. Rule: **a dBm byte only crosses a connection whose two ends confirmed
  bit 0.** The same applies to `0xE3`-prefixed frames.
- **Conversion is by connection:** readsbee keeps the confirmed bits on the client and never
  guesses from values (−87 dBm = `0xa9` = power byte 169 is a valid level both ways).
- To expose the gain, readsbee can store `mm->sig_dbm` and add a new JSON field (e.g. `dbm`)
  next to `rssi` (open question 9).

**Firmware cost.**
- The value exists on every path: Mode S `packet.raw.sigs_dbm` (`RawModeSPacket`,
  `mode_s_packet.hh:64`), UAT ADS-B and uplink `sigs_dbm` (`uat_packet.hh:70`, `:386`). All are
  `int16` with `INT16_MIN` = no level. ADS-L and Remote ID have dBm too.
- Writer: a `WriteRSSIdBmAsInt8` next to `WriteRSSIdBmAsBeastPowerLevel` (`beast_utils.cpp:93`):
  clamp, `INT16_MIN` → `0x80`, `WriteBufferWithBeastEscapes`. The three builders
  (`BuildModeSBeastFrame`, `BuildUATADSBBeastFrame`, `BuildUATUplinkBeastFrame`) and #427's
  `0xED`/`0xEF` builders take a signal-mode argument that defaults to power, so the RP2040's
  USB/serial Beast and stock feeds don't change. (#427 writes dBm for `0xED`/`0xEF` today; in
  v3.2 they call `WriteRSSIdBmAsBeastPowerLevel` unless bit 0 was confirmed.)
- **Per-connection switch:** `ReportBeast` builds one batch per protocol and sends it to every
  sink of that protocol (`comms_reporting.cpp:239-252`, `:487-547`). Feeds must be grouped by
  (protocol, confirmed bits 0 and 3): usually 2 groups (stock servers, readsbee), at most 4 per
  protocol. That's one more batch build per reporting tick when both kinds are connected (a
  Mode S frame is about 26 bytes). No extra RAM: the scratch batch buffer is reused. This is the
  group #427 already adds for READSBEE feeds.

## 8. Forwarding

- readsbee keeps stock output: `beast_out`, `beast_reduce_out` and `beast_reduce_plus_out` carry
  Mode S only, rebuilt from decoded messages. `0xED`, `0xEF` and `0xEC` never go upstream (the
  current code path; tested in t-1061: the sink received no extension frames).
- Later, opt-in only: a readsbee-to-readsbee output that relays the new frames verbatim with an
  `0xE3` prefix.

## 9. chat-105 points

| # | Point | Answer |
|---|---|---|
| 1 | Channel in the letter; erasure count needs a home | Letter `A`/`B`/`X`; rep1 byte before L |
| 2 | ts6 = 0 = not synced | Kept for every upper-case frame (§2) |
| 3 | UAT clock marker in the frame | Upper-case `S L U` (§6), only after the server accepted it (§7): stock readsb closes ingest feeds on them |
| 4 | Per-feed READSBEE setting | **Replaced in v3** by the capabilities check (§7); the setting goes away |

## 10. Stock servers and the query

### 10.1 readsb's garbage rule (wiedehopf/readsb dev `e576cba`, 2026-11-06; lines are `net_io.c`)

Only the Beast **input** reader (`readBeast`) counts garbage; that's what reads the feeder's
query. The answer goes the other way, to the feeder; readsb never receives one. `readBeastcommand`
(`:5382`) reads commands from clients of readsb's Beast *outputs* (`1a 31`, `W`, `P` only), skips
anything else one byte at a time and counts nothing.

| What | Where | Rule |
|---|---|---|
| Counter | `net_io.h:141`, `:5213` | `c->garbage`, uint64, **per connection**, starts at 0, counts bytes |
| Bytes before a `0x1a` | `:5613-5615` | all count |
| Unknown type after `0x1a` | `:5871-5880` | skip `1a` + type, +2; the rest up to the next `0x1a` counts via `:5614` → **a frame costs its length** |
| Lone `0x1a` inside a known frame | `:5903`, `:5719` | bytes so far count, resync there |
| Good frame | `:5936-5938` | −128, **only while the counter is above 128**; never goes below that by decay |
| Leftover at end of a read | `:5962-5967` | > 600 bytes (> 256 before v3.16.9) count |
| Buffer full | `:5236` | whole buffer counts |
| Close | `:6191-6205`, `readsb.h:343` | after each read: **≥ 512 with `--net-ingest`**, else ≥ 1 MiB. Log: `Garbage: Close: <host> port <p> sample: <hex>`, plus `disc: garb.` with ingest / receiver-id (`:1257-1266`) |
| Stats | `stats.c:834` | `readsb_network_malformed_beast_bytes` (+6 per query) |
| First bytes | `:6045-6065` | only special in the first 5 s: PROXY v1 header, five heartbeats; no stricter limit |
| Rate limit | `:5332-5357` | ingest: > 5420 msg/s marks messages, doesn't close; the query isn't a message |
| Options | — | no option changes the 512 / 1 MiB limits; `--net-garbage` is an output port for bad-position messages |
| Other closes | `:5639-5676`, `:1523` | `0xE8` closes ingest feeds; RTT > 15 s (`readsb.h:335`) |

**History** (`git log -S`): unknown-type +2 and skip both bytes since `85c4ed3` (2021-03-07);
threshold 512 since at least 2021 (history pruned 2021-01-02); −128 per good frame unchanged
since 2022 (in v3.14.1593). One change matters: **before v3.14.1650 (`3aba77a`, 2025-03-16) every
Beast input closed at 512**, not only `--net-ingest`. `0xEC` UAT is only parsed since v3.16.2
(`44daf02`, 2025-09-06). So every readsb since 2021, on any aggregator, treats a 6-byte unknown
frame the same way: 6 bytes of garbage, nothing else.

**What the query costs:** 6 of 512 (1.2 %). It stays at 6 for the whole connection (below 128 it
never decays), the same as 6 bytes of line noise. Other garbage still needs 506 bytes, between two
good frames, to close the feed.

### 10.2 Other software (one unknown frame at connect)

| Software | Effect | Source |
|---|---|---|
| dump1090-fa v11.1+ (`465e063`) | Skips the `0x1a` only, rescans; no counter, never closes. The query has no `0x1a` inside, so nothing can be misread | `net_io.c:2296-2337` |
| beast-splitter (`82ba366`) | Not a feed target: its inputs connect out (`--net`, `--serial`); `--listen` sockets are outputs whose reader only acts on `1a 31 <option>` and ignores the rest | `beast_output.cc:60-90` |
| mlat-client (wiedehopf `28ae4f7`) | Would drop the input ("Lost sync … unexpected message type"), but never sees the query: it reads from readsb / dump1090, which don't forward unknown frames, and ADSBee has no Beast TCP server (listen code commented out, `adsbee_server.cpp:669`) | `modes_reader.c:704-729` |
| USB / serial Beast | No query is sent there | — |

### 10.3 Measured (`test_caps_stock.py`, `results/results.txt`)

Real ADSBee BEAST capture (t1069 `beast.bin`, 1090U, live sky): 20 000 frames at 2 000 frames/s;
readsb at dev `e576cba`, v3.16.21, v3.14.1638 (before the ingest-only change), v3.14.1593 (2022),
each with and without `--net-ingest --net-receiver-id`, and dump1090-fa. Baseline = `0xE4` +
capture; query = `0xE4` + query + same capture.

| Test | readsb ingest (all 4 versions) | readsb plain | dump1090-fa |
|---|---|---|---|
| Mode S lost vs. baseline (Mode S only feed) | **0** | **0** | **0** |
| Mode S lost vs. baseline (capture with UAT) | **0** ¹ | **0** ¹ | **0** |
| Feed closed by the query | **no** | **no** | **no** |
| Garbage counter after the query (instrumented dev) | **6** (+2, +4), 6 at close | 6 | — |
| Back-to-back queries before a close | **86** (85 ok: counter 510) | 86 on ≤ 3.14.1638, never on ≥ 3.16 | never |
| Query before every Mode S frame (6 000) | no close | no close | — |
| One oversized unknown frame (`1a E5 Q` + filler), then a pause | closes at 512 bytes on ≤ 3.14.1638; ≥ 3.16.21: not even at 600 ² | same on ≤ 3.14.1638 | never |
| 30 reconnects × 1 s, query each time | 0 closes, Mode S identical | — | 0 closes, identical |
| Bytes sent back to the feeder | 0 (ingest), 25 with `W O`: 5 pings | 20: 4 pings (receiver-id) | 0 |
| Pings mistaken for an answer | no | no | — |

¹ readsb older than v3.16.2 closes this capture **with and without** the query at the same frame:
it doesn't know `0xEC` and counts a UAT uplink as garbage. That's today's behavior
(`BEAST_NO_UAT_UPLINK` exists for it), not caused by the query.
² From v3.16.9 the tail of a frame with no `0x1a` after it is counted only when the next read
arrives, and good frames in that read take 128 each off first. Not something to rely on: the
burst row is the real limit (85 × 6 = 510).

The stock-server runs above used v3's query bytes `1a e5 51 81 87 80`. A v3.2 feeder sends
`1a e5 51 81 8f 80`: same length, every byte after the letter still ≥ `0x80`, so the same garbage
cost (6) applies.

**v3.2 feeder model** (re-run 2026-11-06, `results/results.json` `feeder`): ADS-L and Remote ID now
follow bit 0 as well. With a v3 server (bits 1–3), all 18,398 frames, `0xED`/`0xEF` included,
went out with power bytes. With bits 0–3: 0 levels misread before or after `C`.

**v3.1 feeder model** (re-run 2026-11-06, `results/results.json` `feeder`): the feeder offers
bits 0–3, re-encodes the captured levels as dBm after `C`, and the simulated readsbee decodes by
connection. Answer after 12 ms or 1 s: 0 levels misread. With the 1 s delay, frames sent after
the answer still arrived with power bytes before `C` (in-flight), which is why `C` exists. A v3
server (no bit 0): the feeder keeps power bytes. Answer after 6 s: plain. Stock readsb ingest:
plain, no close. The stock-server runs weren't repeated: stock servers never answer, so they
never see `C` or dBm.

v3 feeder model against a simulated readsbee (`t_feeder`): answer after 12 ms or 1 s → extensions
on, `0xED`/`0xEF`/`S` only after the answer; answer after 6 s → ignored, plain Beast until the
connection closes; stock readsb ingest → plain after the timeout, no close, Mode S intact.

Not run: beast-splitter (no Boost here; reader read instead, §10.2), hardware. The ADSBee's
own reconnect interval is 10 s (`kTCPSocketReconnectIntervalMs`), slower than the 1 s loop above,
and the counter is per connection, so reconnects never add up.

## 11. Open questions (with recommendations)

1. **Type code `0xE5`?** Recommended: yes (free everywhere checked, next to `0xE4`). Other free
   codes: `E1 E2 E6 E7 EA`.
2. **Feature bits in the query too (what the feeder can send)?** Recommended: yes. Same 6 bytes,
   and readsbee can log and show what each feeder could send.
3. **Answer timeout 5 s, late answers ignored?** Recommended: yes. Real answers take one round
   trip (< 1 s even on cellular); a fixed cut-off keeps the firmware state simple.
4. **Drop or buffer `0xED`/`0xEF` while waiting?** Recommended: drop. A few seconds after each
   connect; buffering would need RAM the non-PSRAM units don't have.
5. **A per-feed switch to turn the query off?** Recommended: no for now. Measured harmless on
   every server type; add one only if a server is ever found that objects.
6. **readsbee: decode extension frames from feeds that didn't query?** Recommended: yes (v2
   rule; costs nothing and keeps other feeders working).
7. **Upper-case UAT behind bit 3 rather than always?** Recommended: behind bit 3. Stock readsb
   ingest closes on `S L U` (§6).

v3.1:

8. **Confirm frame `C` as the switch point?** Recommended: yes. Without it readsbee would have
   to switch when it answers, and misread the frames already in flight (one round trip of
   traffic; seen in the feeder model). Alternative: no `C`, and dBm on its own new type codes
   (costs 3–4 more codes and doubles the decoders).
9. **readsbee JSON:** keep `rssi` as dBFS and add a new `dbm` field? Recommended: yes. tar1090 and
   aggregator tools expect dBFS ≤ 0. Alternative: switch `rssi` to dBm for dBm feeds (breaks
   them).
10. **Power byte for "no level"** (now on `0xED`/`0xEF` too in power-byte mode): the firmware sends 1 today (`INT16_MIN` clamps to the first
    table entry). Fix it to 0 separately? Recommended: yes, as its own small firmware fix. It's
    not part of this spec's switch.
11. **Calibration wording:** "uncalibrated, ±2.5 dB absolute, 1 dB resolution". Please confirm
    the ±2.5 dB figure; I couldn't find it in the repos or the library.

Still open from v2: Remote ID ts6 (keep 0, recommended); readsbee phase 2 scope (`S L U`,
`0xED`, `0xEF`, now plus the `0xE5` answer); sub-GHz clock jitter (t-1056); BLE address type.
