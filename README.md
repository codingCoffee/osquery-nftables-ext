# osquery-nftables-ext

An [osquery](https://osquery.io) extension that adds an `nftables` table to a
vanilla `osqueryd` on Linux, written in Go.

## Why

Core osquery's built-in `iptables` table reads `/proc/net/ip_tables_names`,
which the modern **nf_tables** kernel backend does not populate. On nftables
systems that table returns nothing. This extension fills the gap: it shells out
to `nft -j list ruleset` (read-only, structured JSON) and flattens the result
into a queryable table.

```sql
SELECT * FROM nftables;
```

The extension **never modifies firewall state**. The only external command it
ever runs is `nft -j list ruleset`, invoked with a fixed argument slice — no
shell, no string building, no injection surface.

## Table schema

All columns are `TEXT` (osquery extension columns are strings; integers are
rendered as text).

| Column       | Meaning                                                            |
|--------------|-------------------------------------------------------------------|
| `kind`       | `table`, `chain`, `rule`, `set`, `map`, … — what the row describes |
| `family`     | `ip`, `ip6`, `inet`, `arp`, `bridge`, `netdev`                    |
| `table_name` | nftables table name                                               |
| `chain`      | chain name (empty for table/set/map rows)                         |
| `handle`     | rule / chain / table handle                                       |
| `type`       | base-chain type: `filter`/`nat`/`route` (else empty)              |
| `hook`       | `input`/`output`/`forward`/`prerouting`/`postrouting` (base chains)|
| `priority`   | base-chain priority (number, or compact JSON if name/offset form) |
| `policy`     | `accept`/`drop` (base chains)                                     |
| `rule_json`  | the **raw JSON object** for this row — nothing is lost            |

### Row model

`nft -j list ruleset` returns one JSON array under the `nftables` key, where
each element is a single-key object (`table`, `chain`, `rule`, `set`, `map`,
`metainfo`, …). We emit **one row per object**, skipping `metainfo`:

- `kind=table` — one row per table.
- `kind=chain` — one row per chain; base chains fill `type`/`hook`/`priority`/`policy`.
- `kind=rule`  — one row per rule; the owning chain is in `chain`, the full rule
  (including its match/verdict expression list) is preserved in `rule_json`.
- `kind=set` / `kind=map` — one row each.

`rule_json` always holds the raw object, so any detail the dedicated columns
don't expose can be recovered by re-parsing it (e.g. with osquery's
`json_extract`).

## Build

Requires Go 1.21+ and (the first time, with network access) the osquery Go SDK.

```sh
# one-time: resolve modules and populate go.sum
make deps          # == go mod tidy

# produce the static binary ./nftables.ext
make build
```

`make build` sets `CGO_ENABLED=0`, producing a single fully static binary named
`nftables.ext` with no runtime dependencies. Run `make test` for the unit tests
and `make clean` to remove the artifact.

## Install

osquery refuses to load an extension that is group- or world-writable, so
ownership and mode matter.

```sh
sudo install -o root -g root -m 0755 nftables.ext /usr/local/bin/nftables.ext
```

Create the autoload manifest listing the binary path:

```sh
# /etc/osquery/extensions.load
/usr/local/bin/nftables.ext
```

```sh
sudo install -o root -g root -m 0644 /dev/stdin /etc/osquery/extensions.load <<'EOF'
/usr/local/bin/nftables.ext
EOF
```

### osqueryd flags

As command-line flags:

```sh
sudo osqueryd \
  --extensions_autoload=/etc/osquery/extensions.load \
  --extensions_timeout=10 \
  --extensions_socket=/var/osquery/osquery.em
```

Equivalently, as lines in `/etc/osquery/osquery.flags`:

```
--extensions_autoload=/etc/osquery/extensions.load
--extensions_timeout=10
--extensions_socket=/var/osquery/osquery.em
```

> Reading the **full** ruleset requires root (`CAP_NET_ADMIN`). `osqueryd`
> normally runs as root, so this is fine in production. If `nft` exits non-zero
> for lack of privilege, the extension logs a clear message and returns zero
> rows rather than crashing.

### Sample `osquery.conf` schedule

```json
{
  "schedule": {
    "nftables_ruleset": {
      "query": "SELECT * FROM nftables;",
      "interval": 300
    }
  }
}
```

## Standalone / test mode

You can run the extension by hand against a running `osqueryi` without
installing anything. Start `osqueryi` and let it advertise an extensions
socket, then point the extension at that socket:

```sh
# Terminal 1: start an interactive shell with a known socket path.
osqueryi --nodisable_extensions --extensions_socket=/tmp/osq.em
```

```sh
# Terminal 2: run the extension against that socket (root to read the ruleset).
sudo ./nftables.ext --socket=/tmp/osq.em
```

Back in the `osqueryi` prompt:

```sql
osquery> SELECT kind, family, table_name, chain, handle FROM nftables;
osquery> SELECT * FROM nftables WHERE kind = 'rule';
```

On a host that has nftables rules loaded, these return rows. On a host with an
empty ruleset (or where `nft` is missing) you get zero rows and a log line —
never a crash.

### `NFT_BIN` override

By default the extension finds `nft` on `PATH` via `exec.LookPath`. Set
`NFT_BIN` to use a specific binary (useful for testing or non-standard
installs):

```sh
sudo NFT_BIN=/usr/sbin/nft ./nftables.ext --socket=/tmp/osq.em
```

## Failure handling

Each of these is logged with a clear message and yields an **empty result set**
(the extension keeps running):

- `nft` binary not found on `PATH` (and `NFT_BIN` unset),
- `nft` exits non-zero (e.g. permission denied without root),
- empty or malformed JSON output.

## Testing

Unit tests feed a committed fixture (`testdata/ruleset.json`, a captured
`nft -j list ruleset` sample) into the flattening logic and assert the rows are
correct. They **never** shell out to a real `nft`.

```sh
make test
```

## Docker

A multi-stage [`Dockerfile`](Dockerfile) builds the static binary and bakes it
into a `debian:bookworm-slim` image that ships `osqueryd` + `nft`, with the
extension autoloaded.

```sh
docker compose build
docker compose up -d
docker compose logs -f osquery-nftables
```

**To read the *host's* nftables ruleset**, the daemon must run `nft` inside the
host network namespace and hold `CAP_NET_ADMIN`. The compose file does exactly
that:

```yaml
network_mode: host        # see the host's ruleset, not the container's
cap_add: [ NET_ADMIN ]    # capability nft needs to read it (narrower than privileged)
```

Without `network_mode: host` the extension only sees the container's own (empty)
ruleset.

Run an ad-hoc query against the loaded extension by execing into the container:

```sh
docker exec -it osquery-nftables \
  osqueryi --extensions_autoload=/etc/osquery/extensions.load \
           --extensions_timeout=10 \
           "SELECT kind, family, table_name, chain, handle FROM nftables;"
```

Override the osquery version at build time:

```sh
docker compose build --build-arg OSQUERY_VERSION=5.13.1
```

> The bundled `.deb` URL targets **amd64**. On arm64 hosts, adjust the filename
> in the `Dockerfile` (`...linux_arm64.deb`).

## Dependencies

Standard library plus the official [`github.com/osquery/osquery-go`](https://github.com/osquery/osquery-go)
SDK only. The SDK pulls in Apache Thrift transitively; `go mod tidy` resolves
everything.

## License

Apache-2.0. See [LICENSE](LICENSE).
