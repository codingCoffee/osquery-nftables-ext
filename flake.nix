{
  description = "osquery extension exposing the live nftables ruleset as a table";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # Nix has no access to git tags, so we stamp the commit instead:
      # "dev-g<shortrev>" (shortRev appends "-dirty" for an uncommitted tree).
      # Tagged GitHub Release artifacts get their real semver from GoReleaser.
      version = "dev-g${self.shortRev or self.dirtyShortRev or "unknown"}";
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # The extension package. `go test` runs in the build's checkPhase, so the
      # unit tests gate every build.
      packages = forAllSystems (pkgs: rec {
        osquery-nftables-ext = pkgs.buildGoModule {
          pname = "osquery-nftables-ext";
          inherit version;
          src = ./.;

          # Hash of the vendored Go module dependencies. Regenerate whenever
          # go.mod/go.sum change: set this to pkgs.lib.fakeHash, run
          # `nix build .#osquery-nftables-ext`, and paste the reported "got:" hash.
          vendorHash = "sha256-8LbImEhxNXpsFkxVczKGgLHw/m5hsdCZAQSzdBSLEzI=";

          # Fully static, no cgo — matches the GoReleaser build.
          env.CGO_ENABLED = "0";
          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
          ];

          # `go install` names the binary after the module's last path element
          # (osquery-nftables-ext). osquery convention wants the .ext suffix, and
          # the binary must be root-owned + non-writable, which every /nix/store
          # path already is.
          postInstall = ''
            mv "$out/bin/osquery-nftables-ext" "$out/bin/nftables.ext"
          '';

          meta = with pkgs.lib; {
            description = "osquery extension exposing the live nftables ruleset";
            license = licenses.asl20;
            platforms = platforms.linux;
            mainProgram = "nftables.ext";
          };
        };
        default = osquery-nftables-ext;
      });

      # `nix flake check` runs this VM test. It boots a NixOS guest with the
      # module enabled and a real nftables ruleset loaded, then asserts the
      # daemon registers the extension and that NONE of the two regression
      # symptoms appear in its journal:
      #   - "Extension socket directory missing" (Bug 1: socket dir)
      #   - "vtable constructor failed" / "nft ... not found" (Bug 2: nft PATH)
      # and finally that `SELECT * FROM nftables` returns without that error.
      checks = forAllSystems (pkgs: {
        nixos-module = pkgs.testers.runNixOSTest {
          name = "osquery-nftables-module";
          nodes.machine =
            { ... }:
            {
              imports = [ self.nixosModules.default ];
              services.osqueryNftables.enable = true;

              # A non-empty ruleset so the table actually returns rows.
              networking.nftables.enable = true;
              networking.nftables.ruleset = ''
                table inet filter {
                  chain input {
                    type filter hook input priority 0; policy accept;
                  }
                }
              '';
            };
          testScript = ''
            machine.wait_for_unit("nftables.service")
            machine.wait_for_unit("osqueryd.service")

            # Bug 1: the socket and its directory must exist.
            machine.wait_for_file("/run/osquery/osquery.em")

            # Give the autoloaded extension time to register its table.
            machine.wait_until_succeeds(
                "journalctl -u osqueryd | grep -i 'Registering extension'", timeout=60
            )

            log = machine.succeed("journalctl -u osqueryd")
            assert "Extension socket directory missing" not in log, log
            assert "vtable constructor failed" not in log, log
            assert "nft binary not found" not in log, log

            # Bug 2 + end-to-end: the table resolves and returns without the
            # constructor failure. osqueryi reuses the daemon's running socket;
            # interactive (piped) mode waits for extension registration.
            out = machine.succeed(
                "echo 'SELECT count(*) AS n FROM nftables;' | "
                "osqueryi --connect /run/osquery/osquery.em 2>&1"
            )
            assert "vtable constructor failed" not in out, out
            assert "no such table" not in out, out
          '';
        };
      });

      # NixOS module: `services.osqueryNftables.enable = true;` wires the
      # extension into the upstream `services.osquery` daemon.
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.osqueryNftables;
          ext = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          autoload = pkgs.writeText "extensions.load" "${ext}/bin/nftables.ext";
        in
        {
          options.services.osqueryNftables = {
            enable = lib.mkEnableOption "the nftables osquery extension";
            interval = lib.mkOption {
              type = lib.types.int;
              default = 300;
              description = "Seconds between scheduled `SELECT * FROM nftables` runs.";
            };
          };

          config = lib.mkIf cfg.enable {
            services.osquery = {
              enable = true;
              flags = {
                extensions_autoload = toString autoload;
                extensions_timeout = "10";

                # osqueryd defaults --extensions_socket to /var/osquery/osquery.em,
                # but on NixOS only /var/lib/osquery (StateDirectory) and
                # /run/osquery (RuntimeDirectory) exist. With the default the daemon
                # logs "Extension socket directory missing: /var/osquery/osquery.em"
                # and the extension never registers ("no such table: nftables").
                # Put the socket in /run/osquery, a dir the unit already manages.
                # mkDefault so an explicit user-supplied socket still wins.
                extensions_socket = lib.mkDefault "/run/osquery/osquery.em";
              };
              settings.schedule.nftables_ruleset = {
                query = "SELECT * FROM nftables;";
                inherit (cfg) interval;
              };
            };

            systemd.services.osqueryd.serviceConfig = {
              # osqueryd must run as root with CAP_NET_ADMIN to read the full
              # ruleset over netlink. The upstream module already runs it as root;
              # this makes the capability explicit and survives sandboxing.
              AmbientCapabilities = [ "CAP_NET_ADMIN" ];

              # The extension shells out to `nft`, but the osqueryd unit's PATH is
              # a minimal Nix PATH without nftables, so it logs
              # 'exec: "nft": executable file not found in $PATH' and the table
              # constructor fails ("vtable constructor failed: nftables").
              # Pin the absolute path via NFT_BIN (honoured by nftBinary()) so the
              # lookup never depends on PATH. mkDefault lets a user override.
              Environment = lib.mkDefault [ "NFT_BIN=${pkgs.nftables}/bin/nft" ];
            };

            # Belt-and-suspenders: also put nft on the unit's PATH, so a bare
            # exec.LookPath("nft") (NFT_BIN unset/overridden empty) still resolves.
            systemd.services.osqueryd.path = [ pkgs.nftables ];
          };
        };
    };
}
