# readsbee

readsb with a UUID ingest filter and ADS-L / Remote ID decoding, for aggregators that take
Beast feeds. A small fork of
[wiedehopf/readsb](https://github.com/wiedehopf/readsb) (GPL-3.0-or-later, all credit for readsb
to its authors).

Branches: `dev` mirrors upstream, `readsbee` = `dev` + the files below. Merge upstream with
`git merge dev` on `readsbee`. readsbee code lives in `readsbee.c/.h` and `readsbee_ext.c`
(feed protocol v3.2 frames); upstream files only get short hooks.

## UUID filter

Applies to Beast input ports (`--net-bi-port`, with `--net-receiver-id`). Off unless one of
these is given:

| option | |
|---|---|
| `--net-uuid-require` | data only from connections that sent a UUID (0xE4) |
| `--net-uuid-policy=<path.so>` | policy plugin decides per UUID (implies require) |
| `--net-uuid-config=<path>` | settings below, reloaded on change |
| `--net-uuid-timeout=<s>` | close connections without UUID after this (default 15 s) |
| `--net-uuid-allow-file=<path>` | UUIDs accepted, skips the policy |
| `--net-uuid-deny-file=<path>` | UUIDs blocked, wins over everything |
| `--net-uuid-status-dir=<dir>` | write `readsbee.json` here |

Config file (`key = value`, `#` comments):

| key | |
|---|---|
| `max_sources` | distinct source addresses per UUID at once, 0 = off (default) |
| `reuse_action` | `reject` (default) or `flag` when over `max_sources` |
| `policy_arg` | string passed to the plugin |

- **Before the UUID**: data is dropped (no buffering).
- **No UUID** after the timeout: connection closed.
- **Rejected**: connection stays open, data dropped, nothing sent back. An allow-file edit
  accepts it without a reconnect; a deny-file edit cuts an accepted one.
- **Loopback** (127.0.0.0/8, ::1, unix sockets) is exempt, e.g. mlathub to `localhost:30004`.
  A PROXY v1 header from a loopback peer (local proxy) names the source; from anyone else it is
  ignored. It can end the exemption, never grant it.
- **Lists**: one UUID per line, `#` comments, dashes optional. Files are polled every 2 s
  (mtime, size, inode), so atomic rename works. Missing list = empty.
- **Logs**: one line per rejected connection, each UUID at most every 10 min, 20 lines/min max.

## Policy plugins

A shared object with the C ABI in `readsbee_policy.h`:

```c
int readsbee_policy_abi(void);                               // return READSBEE_POLICY_ABI
int readsbee_policy_check(const char *uuid, int64_t now_ms); // 0 accept, >0 reject code
int readsbee_policy_init(const char *arg);                   // optional
void readsbee_policy_reload(const char *arg);                // optional, config changed
```

`policy/example.c` accepts UUIDs starting with `policy_arg`. Build with `make policy/example.so`,
or any plugin with `cc -O2 -fPIC -shared -I. plugin.c -o plugin.so` against the same libc as
readsbee. readsb exits if the plugin can't be loaded.

## Feed protocol v3.2

ADSBee TCP Beast feeds ask the server what it accepts; readsbee answers, and the feeder then adds
these frames and dBm signal levels. Every payload bounds itself; `0x1a` in a body is doubled.
Full spec: [docs/FEED-PROTOCOL.md](docs/FEED-PROTOCOL.md).

| frame | after `0x1a <type>` | |
|---|---|---|
| `0xE5` capabilities | `Q` / `A` / `C`, ver1, bits2 (high bit set, never escaped) | query answered once, confirm switches the connection |
| `0xEC` UAT | `s l u` / `S L U`, ts6, sig1, 30 / 48 / 552 bytes | decoded as upstream; upper case = ts on the feed's Mode S clock |
| `0xED` ADS-L | `A B X` (868.2, 868.4, unknown), ts6, sig1, repaired1, L, L bytes | decoded into the aircraft table |
| `0xEF` Remote ID | `B C E W N` (BT4, BT5 coded, BT5 1M, Wi-Fi beacon, NaN), ts6, sig1, MAC6, ODID message or pack | decoded into the drone table |

- **Capabilities.** On `1a E5 Q ver f0 f1` (first one per connection) readsbee sends
  `1a E5 A 81 <bits>` back on the same socket: bit 0 dBm signal levels, 1 ADS-L, 2 Remote ID,
  3 upper-case UAT. `--readsbee-caps=<bits>` narrows it (default 15). The feeder's
  `1a E5 C ver f0 f1` is the switch point: from the next frame on, the confirmed bits (AND what
  readsbee answered) apply. A later `Q` or `C`, an `A` from a feeder and anything malformed are
  ignored. Nothing is sent to a client that doesn't query, so stock clients see no change.
- **Signal byte (sig1)**, the same rule for `0x31`–`0x33`, `0xEC`, `0xED`, `0xEF`: after a `C`
  with bit 0, int8 dBm (`0x80` = none), turned into readsb's signal level with a 256-entry table
  built at startup (0.75 dBFS per dB, 0 dBFS at −40 dBm, capped at 0 dBFS). Otherwise the Beast
  power byte, as upstream (0 = none). Levels are the receiver's uncalibrated estimate, 1 dB
  resolution.
- Outputs are unchanged: `rssi` stays dBFS everywhere, Beast outputs carry standard power bytes.
  `aircraft.json` / `/re-api/` add `"dbm"` (last level from a dBm feed, kept 60 s); drones get
  `rssi` (dBFS) and, from dBm feeds, `dbm`.
- Frames from feeds that never queried are decoded too (power-byte levels).
- Lower case letters: ts is not on the Mode S clock (never MLAT); upper case with ts 0: not
  synced yet. The last timed frame of each connection (ts, clock, epoch: +1 when ts drops back
  to 0, i.e. the sub-GHz clock was re-based) is kept for a later MLAT path.
- Unknown letters, failed bounds (L > 31, pack size ≠ 25, count > 9), bad ADS-L CRC: that frame
  is skipped and counted as `bad`. Other `0xE0`-`0xFF` types are skipped up to the next frame
  start without counting as garbage, counted per type. Frames over 576 escaped bytes are garbage.
- Nothing readsbee decodes itself goes to any output (`beast_out`, `beast_reduce_plus_out`,
  SBS, ...), and `0xE5` is never forwarded. readsbee has no readsbee-to-readsbee relay, so no dBm
  byte leaves it. UAT stays as upstream: converted to ADS-R-style DF18 messages like any readsb.
- Feeds blocked by the UUID filter: frames are dropped, not decoded.
- Reference decoder and golden vectors: `tests/readsbee_proto.py`, `tests/vectors/feed_vectors.json`.
  Tests: `beetests` (vectors, caps frames, dBm table) and `tests/readsbee_caps_test.py`
  (vectors through a running readsb, answers per `--readsbee-caps`, a simulated feeder with
  0 / 1 / 6 s answer delays). `READSBEE_SIGNAL_LOG=<file>` makes readsb log each frame's signal
  byte as read, for these tests.

### ADS-L

Traffic payloads (EASA ADS-L 4 SRD-860 Issue 2, M-band, key 0 or clear, CRC checked) become
aircraft like SBS input (`type` `other`, which stock tar1090 shows as "Other"):

- address: AMT 5 (ICAO) uses the ICAO address, so it merges with the aircraft's Mode S / ADS-B
  record; every other address table (random, FLARM, OGN, FANET, ...) goes to the non-ICAO space
  (`~xxxxxx`), like TIS-B / ADS-R non-ICAO addresses.
- position, `alt_geom` (WGS-84), `gs`, `track`, `geom_rate`, ground / airborne, emergency.
- `category` from the ADS-L aircraft category: light / heavy fixed wing A1 / A3, rotorcraft,
  eVTOL, gyro A7, glider B1, balloon B2, parachutist B3, ultralight, paraglider, hang glider,
  paramotor B4, UAS / model B6.
- `aircraft.json` and `/re-api/` add `"adsl":{"amt":5,"cat":4,"ch":868.4,"dbm":-91,"seen":0.4}`
  while ADS-L was heard in the last 60 s (`dbm` only from a dBm feed). `filter_uuid` works as for Mode S (positions).
- Status payloads are counted only.

### Remote ID

ODID messages (Basic ID, Location, Self-ID, System, Operator ID; Auth counted only) and packs
build one entry per drone, keyed by UAS ID (serial preferred over CAA, session, UTM IDs) and
linked to the MACs it was heard from (BLE legacy sends one message per packet). Each drone has a
stable non-ICAO `hex` (hash of its ID). Drones are listed for `--readsbee-rid-timeout` (300 s).

| output | where | operator location / ID |
|---|---|---|
| `remoteid.json` | `--write-json` dir (web root) | only with `--readsbee-rid-operator` |
| `/re-api/?remoteid[&filter_uuid=<uuid>]` | API port | only with `--readsbee-rid-operator` |
| `remoteid-full.json` | `--net-uuid-status-dir` (staff) | always, plus MACs and receiver UUIDs |

Drone fields: `hex id id_type ua_type id2 id2_type transports lat lon seen_pos status alt_geom_m
alt_baro_m height_m height_ref gs_mps vrate_mps track self_id class_type eu_category eu_class rssi dbm
messages seen first receivers`, plus `operator{lat lon loc_type alt_geom_m} operator_id`.
Drones are not in `aircraft.json` or the globe unless `--readsbee-rid-globe` is given (then:
`type` `other`, `category` B6, `"rid":{"seen":…}`).

### Counts

Per type: `adsl`, `rid`, `uat`, `uat_mlat` (upper case with ts ≠ 0), `bad`.
- `stats.json`: `remote.readsbee` in each period (`last1min`, `total`, ...).
- `readsbee.json`: `frames` in total and per receiver (with `since` = connection start and
  `last_timed`), `drones` = drones listed now. Each receiver also has the `clients.json` columns
  without addresses: `conn_s`, `kbps`, `messages_s`, `positions_s` (averages over the
  connection), `messages`, `positions`, and for feeders that queried
  `caps` = `{"offered":15,"active":15,"confirmed":true}` (bits offered, bits in effect).

| option | |
|---|---|
| `--readsbee-caps=<bits>` | feature bits answered to a capabilities query (15: dBm levels, ADS-L, Remote ID, upper-case UAT) |
| `--readsbee-rid-operator` | operator location / ID in public outputs (default off) |
| `--readsbee-rid-globe` | drones also as aircraft |
| `--readsbee-rid-timeout=<s>` | drones listed this long after the last message (300) |

## Status

`readsbee.json` in `--net-uuid-status-dir`, every 10 s: settings, counters per reason,
`rejected` (UUID, reason, plugin code, open connections, first / last seen, kept 24 h) and
`receivers` (UUID, state, code, sources, flagged, dropped messages, extension frame counts,
frame counts, capabilities). No addresses. It's meant for staff: keep the directory out of any web root
(tar1090 serves `--write-json` as `/data/`). Filter details stay out of `stats.json` and
`clients.json`; `remoteid-full.json` is written next to `readsbee.json`.

## Image

`ghcr.io/pantsforbirds/readsbee` (`docker/Dockerfile`): ultrafeeder with readsb replaced by
readsbee built `WITH_UUIDS=yes`. Same env vars as ultrafeeder; add the options above to
`READSB_EXTRA_ARGS` and mount the plugin and files. Tags: version (git tag `readsbee-vX.Y.Z`),
`sha-<commit>`, `pr-<n>`, `latest`.

## Tests

```
make test WITH_UUIDS=yes                                        # includes beetests
python3 tests/readsbee_net_test.py ./readsb policy/example.so   # end to end over TCP
python3 tests/readsbee_caps_test.py ./readsb [--captures DIR]   # feed spec v3.2: answers, signal byte per connection
python3 tests/gen_bee_vectors.py                                # after editing tests/vectors/*.json
```

Build on a Raspberry Pi without Docker or system packages: unpack `libzstd-dev` into a folder
(`apt-get download libzstd-dev && dpkg -x libzstd-dev_*.deb root`), then
`C_INCLUDE_PATH=root/usr/include LIBRARY_PATH=root/usr/lib/aarch64-linux-gnu make -j4 WITH_UUIDS=yes DISABLE_INTERACTIVE=yes`.

`tests/vectors/feed_vectors.json` and `tests/readsbee_proto.py` are the spec's reference vectors
and code (`python3 tests/readsbee_proto.py` checks them). `tests/vectors/odid_vectors.json` comes from the Open Drone ID core library (`tests/odid_gen.c`).
