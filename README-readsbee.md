# readsbee

readsb with a UUID ingest filter, for aggregators that take Beast feeds. A small fork of
[wiedehopf/readsb](https://github.com/wiedehopf/readsb) (GPL-3.0-or-later, all credit for readsb
to its authors).

Branches: `dev` mirrors upstream, `readsbee` = `dev` + the files below. Merge upstream with
`git merge dev` on `readsbee`. readsbee code lives in `readsbee.c/.h`; upstream files only get
short hooks.

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
  A PROXY v1 header with a remote source cancels the exemption and is the source address.
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

## Extension frames

Unknown Beast types `0xE0`-`0xFF` (`0xE9`, `0xEE`, ...) are skipped up to the next frame start
without counting as garbage (stock readsb with `--net-ingest` drops a feed once they outnumber
Mode S frames about 5:1). They are counted per type, `0xEE` also per subtype, and never
forwarded. `0xEC` UAT is decoded as upstream. Frames over 576 escaped bytes count as garbage.

## Status

`readsbee.json` in `--net-uuid-status-dir`, every 10 s: settings, counters per reason,
`rejected` (UUID, reason, plugin code, open connections, first / last seen, kept 24 h) and
`receivers` (UUID, state, code, sources, flagged, dropped messages, extension frame counts).
No addresses. It's meant for staff: keep the directory out of any web root (tar1090 serves
`--write-json` as `/data/`). Nothing is added to `stats.json` or `clients.json`.

## Image

`ghcr.io/pantsforbirds/readsbee` (`docker/Dockerfile`): ultrafeeder with readsb replaced by
readsbee built `WITH_UUIDS=yes`. Same env vars as ultrafeeder; add the options above to
`READSB_EXTRA_ARGS` and mount the plugin and files. Tags: version (git tag `readsbee-vX.Y.Z`),
`sha-<commit>`, `pr-<n>`, `latest`.

## Tests

```
make test WITH_UUIDS=yes                                        # includes beetests
python3 tests/readsbee_net_test.py ./readsb policy/example.so   # end to end over TCP
```
