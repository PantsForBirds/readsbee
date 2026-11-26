# ADSBee Beast extensions (2026-11-06)

One Mode S Beast TCP stream from an ADSBee to readsbee, carrying Mode S, UAT, ADS-L and Remote
ID. Status: **approved by the admin 2026-11-06** with all eleven recommendations in §11; items 8,
9 and 11 (dBm levels, the confirm frame) were withdrawn on 2026-11-07, see History. readsbee implements the
server side (`readsbee_ext.c`, README-readsbee.md). Servers may accept or refuse feeds by policy;
this spec doesn't cover that.

**History.** Agreed with the admin on 2026-11-06 after several drafts (the drafts are in git
history; this document has no version number). Rules that came out of the review:
- No `READSBEE` feed protocol: every TCP feed stays plain `BEAST` and starts with a 6-byte
  capabilities query (`0xE5 'Q'`, §7). A server that answers (`0xE5 'A'`, readsbee) gets the
  extension frames it accepts; any other server gets today's Beast stream plus those 6 bytes.
- **The signal byte of every frame type is the Beast power byte** (0 = no level), `0xED` and
  `0xEF` included, with its −100 dBm floor and −40 dBm ceiling: ADS-L below −100 dBm reads 1,
  Remote ID above −40 dBm reads 255 (§2).
- Bit 0 is GPS time sync (`0xE6`, §12); the protocols are bits 1–3: bit 1 `0xED` ADS-L, bit 2 `0xEF` Remote ID,
  bit 3 upper-case UAT. All four is `8F`.
- The feeder sends the agreed frames (query bits AND answer bits) as soon as it has read the
  answer. Every frame says what it is, so frames in flight can't be misread and there is no
  switch point (§7.1).
- One Beast type per encapsulation in the ADSBee UAT style, no `0xEE` umbrella, no text in the
  feed, no proof frame.
- **2026-11-07 (admin): dBm signal levels and the confirm frame `C` removed.** Every signal byte
  is the power byte; capability bit 0 and the letter `C` are reserved, bits 1–3 keep their place.
- **2026-11-26 (admin): capability bit 0 = GPS time sync frames `0xE6` (§12).** Bit 0 was briefly dBm signal levels
  before 2026-11-07 (never deployed). Mode S timestamps stay 12 MHz; an `0xE6 'P'` frame per PPS edge puts them on
  UTC.

Reference code: [`tests/readsbee_proto.py`](../tests/readsbee_proto.py) (`python3 tests/readsbee_proto.py` → `vectors ok`, checks
[`tests/vectors/feed_vectors.json`](../tests/vectors/feed_vectors.json): 47 vectors; the `stream_query_answer*` vectors carry
both directions in `exchange`: query, answer, then the agreed frames). Stock-server measurements (§10:
`test_caps_stock.py`, `results/`, `results.txt`, `results-uat-msgtype.txt`) were made outside this
repo and aren't included.

## 1. Frame types

| Type | Name | After the type byte | Status |
|---|---|---|---|
| `0x32` / `0x33` | Mode S short / long | ts6 rssi1 + 7 / 14 | Beast |
| `0xE3` | readsb receiver ID | 8 | readsb |
| `0xE4` | readsb feed UUID | 36 ASCII | readsb |
| **`0xE5`** | **capabilities** | letter `Q` / `A` (`C` reserved), ver1 bits2 (never `0x1a`) | new (§7) |
| **`0xE6`** | **GPS time sync** | letter `P`, ts6 sub1 utc5 flags1 rate3 (flags never `0x1a`) | new (§12) |
| `0xEC` | UAT | letter `s l u` / **`S L U`**, ts6 rssi1 + 30 / 48 / 552 | ADSBee + readsb; upper case new |
| **`0xED`** | **ADS-L** | letter `A B X`, ts6 sig1 rep1 + on-air (1 + L) | new |
| **`0xEF`** | **Remote ID** | letter `B C E W N`, ts6 sig1 mac6 + ODID (25 or 3 + 25n) | new |

**Why these codes.** Re-checked free in readsb dev (`bf8f8fd`; again for the capabilities check at `e576cba`,
2026-11-06), dump1090-fa, mlat-client, mlat-server, beast-splitter and ADSBee firmware (main,
`ads-l`, `t0948-*`): `E1 E2 E7 EA EE F0–FF` (`E5`, `E6`, `ED`, `EF` taken). The capabilities check takes `0xE5`: next to `0xE4`, the other
connection-start frame.
- `0xE6` for GPS time sync, next to `0xE5`: both are per-connection control frames, not packets. Re-checked free
  2026-11-24 in readsb dev `88877b9`, dump1090-fa `465e063`, mlat-client (wiedehopf `28ae4f7`, mutability `fe70767`),
  mlat-server `c2d35b7` (no Beast parser) and beast-splitter `82ba366`. Also free in ADSBee firmware main.
- `0xED` sits next to UAT `0xEC`: both are CC13xx sub-GHz packets with the same timestamp path.
- `0xEF` for Remote ID. `0xEE` is skipped on purpose: early drafts used it with a different
  layout, and test captures may exist.
- FANET / OGN: nothing reserved. They'd take one free code each (`E5`–`E7`, `F0`+) with the
  same shape, and a decoder doesn't need to know them in advance (§3).

## 2. Wire rules

- `0x1a <type> <letter> <body>` for `0xEC`, `0xED`, `0xEF`; `0x1a <type> <body>` for the rest.
- Every `0x1a` in the body is sent as `1a 1a`. The type byte and the letter are never escaped and
  are never `0x1a`: letters are ASCII.
- Integers big-endian. ts6 is 6 bytes.
- **Signal byte sig1**, the same on every frame type (`0x31`–`0x33`, `0xEC`, `0xED`, `0xEF`): the
  **Beast power byte**, amplitude, round(255 × 10^(dBFS/20)) with dBFS = 0.75 × (dBm + 40): 255 at
  −40 dBm and above, 1 at −100 dBm and below, **0 = no level** (firmware
  `WriteRSSIdBmAsBeastPowerLevel`: one clamp and one read of the 61-entry `kRSSIdBmToRSSIdBFS`
  table in `beast_tables.hh`, no floating point at runtime). There is no dBm mode.
  - ADS-L decodes down to about −108 dBm, so everything at or below −100 dBm reads 1 (vector
    `adsl_868_2_power_floor`). In the t1069 capture Remote ID levels were −85…−34 dBm, so the
    strongest drones read 255 (`rid_bt4_power_saturated`).
  - The table has no `0x1a` (−66 dBm is `0x1b`), so the signal byte is never escaped; a decoder
    unescapes it like any body byte anyway. readsbee turns it into a level as readsb does,
    `(b / 255)²`.
- **Letter case = clock.** Upper case: ts6 is on this connection's Mode S clock (the 12 MHz
  counter of its `0x32`/`0x33` frames), MLAT-grade (Remote ID: same clock, coarser, §5);
  **ts6 = 0 means not synced yet** (about 2–3 s after boot, maybe after a `SUBG_MODE` switch). Lower case: ts6 isn't on the Mode S clock;
  never use it for MLAT.
- Every payload bounds itself, so there is no LEN byte (§3).
- Largest frames, escaped worst case: UAT `U` 1 + 2 + 2 × 559 = 1121 (unchanged), Remote ID
  pack 2 + 1 + 2 × 241 = 485, ADS-L 2 + 1 + 2 × 40 = 83, GPS time `P` 2 + 1 + 2 × 15 + 1 = 34.

## 3. Bounds and resync

| Type | Length known from |
|---|---|
| UAT | the letter: 30 / 48 / 552 |
| ADS-L | on-air length byte L (first payload byte): 1 + L bytes, L ≤ 31 |
| Remote ID | first ODID byte: high nibble ≠ `F` → 25; `F` → pack: next bytes size (= 25) and count n (1–9), 3 + 25n |
| GPS time | fixed: 16 bytes after the letter `P`; the flags byte (13th) must have its high bit set |

A decoder that meets an unknown type, an unknown letter, or a bound that fails (L > 31, pack size
≠ 25, n > 9) skips to the next frame start: the next `0x1a` not followed by `0x1a`. The escape
rule makes this safe; only that frame is lost. readsbee already skips unknown `0xE0`–`0xFF` types
this way (t-1061).

## 4. ADS-L `0xED`

```
1a ED  A|B|X  ts6  sig1  rep1  L  onair[L]        sig1: power byte (§2)
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
1a EF  B|C|E|W|N (b|c|e|w|n)  ts6  sig1  mac6  odid[25 | 3+25n]    sig1: power byte (§2)
```

- **Letter = transport**: `B` BT4 legacy, `C` BT5 Coded (long range), `E` BT5 extended 1M,
  `W` Wi-Fi beacon, `N` Wi-Fi NaN. Needed to interpret the packet and for coverage per link type.
- **mac6**: source address in display order (BLE AdvA, Wi-Fi SA). Needed: BLE legacy carries one
  ODID message per packet, and the address is what ties a drone's Basic ID to its Location.
- **odid**: one ASTM F3411 25-byte message, or a message pack, as received.
- **Timestamp.** When the ESP32 is synced to the Mode S clock (adsbee #428, shared SYNC pulse):
  **upper case**, ts6 = the packet's time on this connection's Mode S 12 MHz clock (the 48 MHz
  MLAT counter / 4, low 48 bits, wrapping like the Mode S frames'). Wi-Fi beacons use the MAC's
  receive timestamp (about 2–4 µs); BLE has none, so it's the callback time (about 1 ms after the
  air time). It orders Remote ID against Mode S but is **not MLAT-grade**. Not synced
  yet: **lower case with ts6 = 0**, and readsbee stamps arrival time. The firmware doesn't send
  upper case with ts6 = 0 for Remote ID. Vectors `rid_bt4_modes_clock_power`,
  `rid_wifi_beacon_pack_modes_clock`, `rid_bt4_modes_clock_wrap_power`.
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

## 7. Capabilities check (replaces the READSBEE opt-in)

Every ADSBee **TCP** Beast feed (`BEAST`, `BEAST_NO_UAT`, `BEAST_NO_UAT_UPLINK`) asks the server
once per connection what it accepts. Only an answer turns on `0xED`, `0xEF` and upper-case UAT.
No answer = today's Beast. UDP feeds, MQTT and USB/serial Beast never query (no back channel)
and stay plain. The `READSBEE` value of `AT+FEED` goes away; #427 is reworked after approval.

### 7.1 Frames

```
query   feeder -> server   1a E5 'Q' ver f0 f1      6 bytes, sent once, right after 0xE4
answer  server -> feeder   1a E5 'A' ver f0 f1      6 bytes, sent once, only in reply to a query
        letter 'C' reserved (was the confirm frame): never sent; a server skips it as one
              6-byte frame, no garbage
        ver = 0x80 | version (1 -> 0x81): a protocol field of the 0xE5 frame, not a
              version of this document
        f0  = 0x80 | feature bits 0-6,   f1 = 0x80 | feature bits 7-13
```

| bit | Feature | In the query (feeder can send) | In the answer (server accepts) |
|---|---|---|---|
| 0 | `0xE6` GPS time sync (§12) | GNSS enabled on a board with a PPS input | decodes `0xE6`, wants UTC |
| 1 | `0xED` ADS-L | sub-GHz radio in ADS-L mode with #409 clock | decodes `0xED` |
| 2 | `0xEF` Remote ID | Remote ID receive on | decodes `0xEF` |
| 3 | `0xEC` upper-case `S L U` | firmware with #409 clock fix | trusts / accepts `S L U` |
| 4–13 | reserved | 0 | 0; ignored by the feeder |

- After an answer the feeder sends **query bits AND answer bits** (known bits only),
  **from the moment it has read the answer**, with no confirm frame. Frames in flight need no
  switch point: `0xED`, `0xEF` and `S L U` say what they are, readsbee decodes them from any feed
  (§11 item 6), and the signal byte means the same before and after. An answer of
  `81 80 80` (nothing) is valid: plain Beast. A newer version may add bits; each side uses what
  it knows. A higher `ver` doesn't change the frame size.
- **Never contains `0x1a`, never escaped:** the letter is ASCII, every other byte has the high
  bit set. So no escape state is needed on either side, the frame can't end in a half escape,
  and dump1090-fa's one-byte resync (§10) can't land inside it.
- **Can't be mistaken for anything else:** `0xE5` is unused (§1); Beast data frames are
  `0x31`–`0x35`, readsb commands `P` `W` (and `1` in its output-port reader); `E5` is none of these.
  `Q`/`A` keeps one code for both directions and tells an answer from a reflected query.
- One query per connection. A server answers the first query only; later ones are ignored.

### 7.2 Sequence

```
ADSBee (feeder)                                        server
   | TCP connect                                          |
   |-- 1a E4 <uuid 36>  1a E5 Q 81 8E 80 --------------->|  one send(): E4, then the query
   |-- Beast as today (0x32/0x33, UAT s l u) ----------->|
   |                                                      |  readsbee: replies at once
   |<----------------------------- 1a E5 A 81 8E 80 -----|  stock readsb: skips 6 bytes, no reply
   |-- + 0xED, 0xEF, UAT S L U (agreed bits) ----------->|  from the moment A is read
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
- Reporting: `0xED` only if bit 1, `0xEF` only if bit 2, UAT letter upper case only if bit 3.
  `0xE6` only if bit 0, one per labeled PPS edge (§12.1).
  The `NO_UAT` variants still decide whether UAT goes out. The signal byte is the power byte on
  every feed, so feeds are grouped by protocol and bit 3 only.
- On the answer: the feed's bits become query AND answer, in effect for the next frame.

### 7.5 readsbee side

- `readBeast`: new branch for `0xE5`: wait for 4 bytes; if valid `Q` and first on this
  connection, store the offered bits and `offered AND accept` (shown in readsbee.json), queue
  `1a E5 A 81 <accept>` and flush. No garbage counted for a valid frame. `A` from a client, a
  second `Q`, the reserved `C`: skipped as one 6-byte frame. Malformed: skip like an unknown type.
- `accept` = bits 0–3 by default once `0xE6` is decoded (bits 1–3 until then) (`--readsbee-caps` narrows it,
  e.g. 4 = Remote ID only).
- Input is still treated the same for every feed : extension frames from a feed that
  didn't query are decoded anyway. The answer only steers what an ADSBee sends.
- `0xE5` is never forwarded (outputs are rebuilt from decoded messages, §8).

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
| 4 | Per-feed READSBEE setting | **Replaced** by the capabilities check (§7); the setting goes away |

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

The stock-server runs above used an earlier draft's query bytes `1a e5 51 81 87 80`. The feeder sends
`1a e5 51 81 8e 80`: same length, every byte after the letter still ≥ `0x80`, so the same garbage
cost (6) applies.

**Feeder model, power bytes and no confirm** (re-run 2026-11-07, `tests/readsbee_caps_test.py`
against readsbee): the feeder sends the agreed frames from the moment it reads the answer. Answer
seen at once or after 1 s: bits 1–3 agreed, every Mode S power byte came back unchanged in
readsbee's Beast output, the drones' rssi matched their power byte. Answer seen after 6 s: plain.
Server answering 4: Remote ID only, no ADS-L, lower-case UAT. No connection closed.

Feeder model, capabilities check only, against a simulated readsbee (`t_feeder`): answer after 12 ms or 1 s → extensions
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
6. **readsbee: decode extension frames from feeds that didn't query?** Recommended: yes (costs nothing and keeps other feeders working).
7. **Upper-case UAT behind bit 3 rather than always?** Recommended: behind bit 3. Stock readsb
   ingest closes on `S L U` (§6).

Added with the dBm capability (withdrawn 2026-11-07, kept for the numbering):

8. ~~Confirm frame `C` as the switch point?~~ Withdrawn 2026-11-07: it only existed to switch
   the signal byte to dBm. The letter stays reserved.
9. ~~readsbee JSON `dbm` field?~~ Withdrawn 2026-11-07 with dBm: `rssi` stays dBFS, no `dbm`.
10. **Power byte for "no level"** (on `0xED`/`0xEF` too): the firmware sent 1 (`INT16_MIN`
    clamped to the first table entry). Fix it to 0? Recommended: yes; done in #427.
11. ~~Calibration wording for dBm levels~~ Withdrawn 2026-11-07 with dBm.

Still open: readsbee phase 2 scope (`S L U`,
`0xED`, `0xEF`, now plus the `0xE5` answer); sub-GHz clock jitter (t-1056); BLE address type.

## 12. GPS time sync `0xE6` (capability bit 0)

Mode S timestamps stay on the feed's 12 MHz counter. A feeder whose counter is measured against a GNSS PPS sends,
for each PPS edge it can label, the 12 MHz count of that edge and its UTC second. A server can then put every
timestamp on that connection on UTC.

**Why 12 MHz + a sync frame, not 1 GHz timestamps:**
- wiedehopf mlat-server doesn't use the GPS shortcut (the same-epoch identity predictor is commented out), so 1 GHz
  stamps buy little.
- 12 MHz rounding is 24 ns rms (83.3 ns / √12), the size of the ADSBee's PPS fit (adsbee #462).
- No existing frame changes, and there's no per-connection timestamp mode.
- Any feeder with a PPS-measured sample counter can send it.

### 12.1 Frame

```
1a E6  P  ts6  sub1  utc5  flags1  rate3          16 bytes after the letter, escaped except flags
```

| Field | Bytes | Meaning |
|---|---|---|
| `P` | 1 | letter (PPS): on this connection's Mode S clock. Other letters are reserved and skipped like an unknown type |
| ts6 | 6 | 12 MHz count of the PPS edge of second utc5, on the clock of this connection's `0x32`/`0x33` frames (low 48 bits, wrapping like them) |
| sub1 | 1 | fraction of a tick in 1/256 (0.33 ns): the edge is at **ts6 + sub1/256** ticks |
| utc5 | 5 | POSIX seconds (UTC since 1970, no leap seconds) of that edge, unsigned |
| flags1 | 1 | `0x80` always set (so never `0x1a`, never escaped). `0x01` **step**: the fit restarted or was re-anchored since the last frame, so don't derive a rate across it. Other bits reserved: 0, ignored |
| rate3 | 3 | signed ppb: one GNSS second = 12 000 000 × (1 + rate × 10⁻⁹) ticks (±8 388 607). `80 00 00` = unknown, for feeders that don't measure one |

- **When.** One frame per labeled PPS edge while the feeder's fit is in sync, on connections that agreed bit 0 (§7).
  Nothing else: no frame means no new information. ADSBee sends it after the RMC that labels the edge, 0.1 to about
  1 s after the edge.
- **Wire.** ts6, sub1, utc5 and rate3 are escaped (§2): 19 to 34 bytes. Mode S frames stamped after an edge may arrive
  before its `0xE6`; nothing depends on the order.
- **Choices.** sub1 keeps the edge finer than the fit with one scale. utc5 needs no epoch or leap-second table and
  doesn't wrap in 2106. rate3 covers crystals (±200 ppm) 40 times over; 1 ppb over a second is 1 ns.

### 12.2 Capability bit 0

- **The feeder sets bit 0 while GNSS is enabled in its settings, on a board with a PPS input.** A feeder that never
  gets a PPS simply sends no frames.
- A change to the GNSS setting reconnects the TCP Beast feeds, so the query is asked again (ADSBee: add
  `gnss_enabled` to `FeedConfigCRC`).
- **Servers** answer bit 0 only if they decode `0xE6`. Stock readsb, dump1090-fa and mlat-client never answer (§7), so
  they never see it. That matters: stock readsb `--net-ingest` counts `0xE6` as garbage and, with a quiet sky,
  **closes the feed after 28 frames**; dump1090-fa's one-byte resync could find a bogus `1a 32` inside it.

### 12.3 How a server uses it

For a frame stamped `ts` on the same connection, from the latest `0xE6` (ts6, sub1, utc5, rate3):

```
d   = (ts - ts6) as a signed 48-bit difference            # the counter wraps every 271.5 days
s   = (d - sub1/256) / (12e6 × (1 + rate3 × 1e-9))
UTC = utc5 + s                                            # valid while |s| ≤ 4
```

- **4 s.** A frame is good for 4 s around its edge. After that the connection has relative 12 MHz time only, until
  the next frame.
- **Truncation.** Frame timestamps are truncated (ADSBee: floor of 48 MHz / 4), so a frame was on average half a tick
  (41.7 ns) after ts. Add it for absolute time; between receivers with the same convention it cancels.
- **Consecutive frames** n, n+1 without `step`: (ts6 + sub1/256)ₙ₊₁ − (ts6 + sub1/256)ₙ must equal
  (utc5ₙ₊₁ − utc5ₙ) × 12e6 × (1 + rate × 10⁻⁹) within 1 µs, else drop the pair (a mislabeled second). With rate
  `80 00 00` this difference is the rate, so the server needs two frames before the first conversion.
- **step**: start the rate estimate again; don't use the pair across it.
- **Leap seconds**: utc5 is POSIX, so frames stop for a couple of seconds around one and the next has `step`.

The instant is unchanged: UTC is the time of the instant the Beast timestamp marks (ADSBee: dump1090's, adsbee
#308). It applies to every upper-case extension frame and every `0x32`/`0x33` frame on the connection (ADSBee 1090U:
UAT and ADS-L add the CC1312 sync, 0.11 µs rms; Remote ID is ordering only, as §5), not to lower-case or ts6 = 0
frames (§2).

### 12.4 Firmware sketch (ADSBee 1090, for after approval)

- **RP2040 → ESP32.** One struct in `RP2040DeviceStatus`, the status the RP2040 already writes about every 100 ms:
  ```
  struct __attribute__((packed)) PPSTime {
      uint64_t edge_mlat_48mhz_counts;  // the fit's edge of utc_seconds on the MLAT counter (48 MHz)
      uint16_t edge_sub_counts;         // + /1024 of a count
      uint64_t utc_seconds;             // POSIX
      int32_t rate_ppb;                 // PPSClock::GetRateErrorPPB()
      uint8_t step;                     // fit restarted or re-anchored since the previous seq
      uint8_t seq;                      // + 1 per labeled edge while in sync
  };
  ```
  `GNSSReceiver` fills it when an RMC labels an edge and the fit is in sync (the fit's edge, as `MLATCountsToUTC`
  uses), and bumps `seq`.
- **ESP32.** In `IPWANTask`, on a new `seq`, `BeastReporter::WriteGPSTimeFrame` builds the frame once, with
  ts6 = (E >> 12) mod 2⁴⁸ and sub1 = (E >> 4) & 0xFF for E = edge × 1024 + sub (the same `>> 2` as Mode S), and
  appends it to each TCP Beast feed whose agreed bits have bit 0. Nothing otherwise.
- Add `kBeastCapGPSTime = 1 << 0` to `kBeastCapsKnown`/`kBeastCapsSendable`; `BeastCapsToOffer()` sets it while
  `gnss_enabled`. No change to any other frame.

### 12.5 readsbee side (sketch)

- `readBeast` decodes `0xE6 'P'`, keeps the latest two frames per connection and shows them in `readsbee.json`.
  Frames from a feed that didn't agree bit 0 are decoded too (§11 item 6). `0xE6` is never forwarded (§8).
- Today's readsbee already skips `0xE6` whole without counting garbage, and answers `8E`, so no frame is sent to it.

### 12.6 Open points

1. Using `0xE6` in our MLAT server (absolute time, or only rate) is a later step.
