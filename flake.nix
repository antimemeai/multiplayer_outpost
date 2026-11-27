{
  description = "mp-outpost — standalone E2EE P2P sidecar, daemon, and MCP stdio server for multiplayer.tech";

  # Drop-in root flake.nix for https://github.com/antimeme-ai/multiplayer_outpost.
  # Requires Rust >= 1.91 (edition 2024); nixos-unstable provides a compatible toolchain.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          inherit (pkgs) lib;
        in
        {
          mp-outpost = pkgs.rustPlatform.buildRustPackage {
            pname = "mp-outpost";
            version = "0.4.0";

            src = self;

            cargoLock = {
              lockFile = "${self}/Cargo.lock";
            };

            cargoBuildFlags = [
              "--package"
              "outpost-cli"
              "--bin"
              "mp-outpost"
            ];

            # Pure Rust stack (rustls + ring + iroh v1.5.0); no OpenSSL or C deps required.
            doCheck = false;
            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              "$out/bin/mp-outpost" --version | grep -q "mp-outpost"
              runHook postInstallCheck
            '';

            meta = with lib; {
              description = "Standalone E2EE sidecar CLI, daemon, and MCP server for multiplayer.tech";
              homepage = "https://multiplayer.tech";
              changelog = "https://github.com/antimeme-ai/multiplayer_outpost/releases/tag/v0.4.0";
              license = licenses.mit;
              mainProgram = "mp-outpost";
              platforms = supportedSystems;
            };
          };

          default = self.packages.${system}.mp-outpost;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.mp-outpost}/bin/mp-outpost";
        };
      });
    };
}
