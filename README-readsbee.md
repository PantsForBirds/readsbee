# readsbee

readsb for ADSBee feeds. A small fork of [wiedehopf/readsb](https://github.com/wiedehopf/readsb)
(GPL-3.0-or-later, all credit for readsb to its authors).

Branches: `dev` mirrors upstream, `readsbee` = `dev` + the files below. Merge upstream with
`git merge dev` on `readsbee`. readsbee code lives in `readsbee.c/.h`; upstream files only get
short hooks.

## Ingest filter

| option | |
|---|---|
| `--net-require-adsbee-uuid` | Beast input only from ADSBee UUIDs |
| `--net-uuid-timeout=<s>` | close connections without UUID after this (default 15 s) |
| `--net-uuid-allow-file=<path>` | extra UUIDs allowed |
| `--net-uuid-deny-file=<path>` | UUIDs blocked, even ADSBees |

Applies to Beast input ports (`--net-bi-port`, ingest). Needs `--net-receiver-id` (0xE4 UUIDs).

- **ADSBee UUID**: `bee0XXXX-XXXX-XXXX-bee0-XXXXXXXXXXXX`, halves equal, 48-bit value
  < 10^13, digits `YYYMMDDVVXXXX` a real date from 2022 to next year.
- **Before the UUID**: data is dropped. ADSBees send the UUID first, so nothing real is lost,
  and nothing has to be buffered.
- **No UUID** after the timeout: connection closed.
- **Rejected UUID**: connection stays open, data dropped. An allow-file edit accepts it
  without a reconnect; a deny-file edit cuts an accepted one.
- **Loopback** (127.0.0.0/8, ::1, unix sockets) is exempt: mlathub feeds `localhost:30004`
  without a UUID. A PROXY v1 header with a remote source cancels the exemption.
- **Lists**: one UUID per line, `#` comments, dashes optional. Polled every 2 s (mtime, size,
  inode), so atomic rename works. Missing file = empty list. Deny wins over allow.
- **Logs**: one line per rejected connection, each UUID at most every 10 min, 20 lines/min max.

## Extension frames

Unknown Beast types `0xE0`-`0xFF` (`0xE9` ADSBee info, `0xEE` ADS-L / Remote ID, ...) are
skipped up to the next frame start, without counting as garbage (stock readsb with
`--net-ingest` drops a feed once they outnumber Mode S frames about 5:1). They are counted per type, `0xEE` also per subtype,
and never forwarded. `0xEC` UAT is decoded as upstream. Frames longer than 576 escaped bytes
count as garbage.

## Output

- `readsbee.json` in `--write-json` (every 10 s, no IPs): filter settings, counters,
  `rejected` (UUID, reason, open connections, first/last seen, kept 24 h),
  `receivers` (UUID, state, dropped messages, extension frame counts).
- `stats.json`: `readsbee` object with the same counters.
- `clients.json`: last column `bee` = `ok`, `pending`, `exempt`, `off`, or the reject reason
  (`format`, `date`, `denied`).

## Image

`ghcr.io/pantsforbirds/readsbee` (`docker/Dockerfile`): ultrafeeder with readsb replaced by
readsbee built `WITH_UUIDS=yes`. Same env vars as ultrafeeder; add the options above to
`READSB_EXTRA_ARGS`. Tags: version (git tag `readsbee-vX.Y.Z`), `sha-<commit>`, `pr-<n>`,
`latest`.

## Tests

```
make test WITH_UUIDS=yes                       # includes beetests
python3 tests/readsbee_net_test.py ./readsb    # end to end over TCP
```
