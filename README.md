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

## Install on NixOS (declarative)

The repo ships a [`flake.nix`](flake.nix) that packages the extension with
`buildGoModule` (unit tests run in the build's `checkPhase`, so a broken build
never installs) and provides a NixOS module that wires it into the upstream
`services.osquery` daemon. This is the idiomatic path: the binary lives in
`/nix/store` — already root-owned and non-writable, exactly what osquery's
extension safety check wants — so there is nothing to `chown`/`chmod`.

### One-time: pin `vendorHash`

`buildGoModule` needs the hash of the module dependencies. `flake.nix` ships
`vendorHash = pkgs.lib.fakeHash` as a placeholder; build once, then paste the
real hash Nix reports:

```sh
nix build .#osquery-nftables-ext
# error: hash mismatch ... got: sha256-XXXX...
# -> replace fakeHash in flake.nix with that sha256-XXXX... and rebuild
```

### Try it without installing

```sh
nix build .#osquery-nftables-ext
./result/bin/nftables.ext --help     # the static extension binary
```

### Add to your system configuration

In a flake-based NixOS config, add this flake as an input and import its module:

```nix
{
  inputs.osquery-nftables.url = "github:codingoffee/osquery-nftables-ext";

  outputs = { nixpkgs, osquery-nftables, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        osquery-nftables.nixosModules.default
        {
          # Builds the extension, enables services.osquery, autoloads the
          # extension, schedules `SELECT * FROM nftables;`, and grants osqueryd
          # CAP_NET_ADMIN so it can read the full ruleset.
          services.osqueryNftables.enable = true;
          # services.osqueryNftables.interval = 300;  # optional, seconds
        }
      ];
    };
  };
}
```

Rebuild and verify:

```sh
sudo nixos-rebuild switch
journalctl -u osqueryd -f | grep -i 'Registering extension'
```

### Wiring it yourself (without the bundled module)

If you'd rather drive `services.osquery` directly:

```nix
{ config, pkgs, ... }:
let
  ext = (builtins.getFlake "github:codingcoffee/osquery-nftables-ext")
        .packages.${pkgs.stdenv.hostPlatform.system}.default;
in {
  services.osquery = {
    enable = true;
    flags = {
      extensions_autoload =
        toString (pkgs.writeText "extensions.load" "${ext}/bin/nftables.ext");
      extensions_timeout = "10";
    };
    settings.schedule.nftables_ruleset = {
      query = "SELECT * FROM nftables;";
      interval = 300;
    };
  };
  # Reading the full ruleset over netlink needs this capability.
  systemd.services.osqueryd.serviceConfig.AmbientCapabilities = [ "CAP_NET_ADMIN" ];
}
```

> **If osqueryd logs that the extension path is "not safe":** that is osquery's
> permission check, not NixOS. Store paths are normally fine (root-owned,
> mode `0555`). As a last resort add `allow_unsafe = "true";` to
> `services.osquery.flags`, but understand it relaxes osquery's extension
> trust model — prefer fixing the path's ownership/mode instead.

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

Run an ad-hoc query against the loaded extension by execing into the container.
Use **interactive** `osqueryi` (no trailing query argument):

```sh
docker exec -it osquery-nftables \
  osqueryi --extensions_autoload=/etc/osquery/extensions.load --extensions_timeout=10
```
```sql
osquery> SELECT kind, family, table_name, chain, handle FROM nftables;
```

> **Don't pass the SQL as a one-shot argument** (`osqueryi "SELECT ... FROM
> nftables;"`). One-shot mode can execute the query *before* the autoloaded
> extension finishes registering, giving a spurious `no such table: nftables`.
> Interactive mode (above) waits for registration, and the scheduled
> `osqueryd` path is unaffected. The container name is
> `osquery-nftables-ext-osquery-nftables-1` unless you set `container_name`.

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
