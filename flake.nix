{
  description = "osquery extension exposing the live nftables ruleset as a table";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      version = "0.1.0";
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

          # Replace with the hash Nix prints on the first build. Until then use
          #   vendorHash = pkgs.lib.fakeHash;
          # build once, and copy the "got:" hash from the error into here.
          vendorHash = pkgs.lib.fakeHash;

          # Fully static, no cgo — matches `make build`.
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
              };
              settings.schedule.nftables_ruleset = {
                query = "SELECT * FROM nftables;";
                inherit (cfg) interval;
              };
            };

            # osqueryd must run as root with CAP_NET_ADMIN to read the full
            # ruleset over netlink. The upstream module already runs it as root;
            # this makes the capability explicit and survives sandboxing.
            systemd.services.osqueryd.serviceConfig.AmbientCapabilities = [ "CAP_NET_ADMIN" ];
          };
        };
    };
}
