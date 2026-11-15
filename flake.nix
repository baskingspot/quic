{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.follows = "baskingspot/flake-parts";
    baskingspot = {
      url = "github:baskingspot/nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # imports and inputsFrom below mirror each other, including the
      # toolchain version: pick that once, in the import.
      imports = with inputs.baskingspot.flakeModules; [
        base
        zig."0.17"
      ];

      perSystem =
        {
          pkgs,
          config,
          lib,
          ...
        }:
        {
          devShells.default = pkgs.mkShell {
            inputsFrom = [
              config.devShells.base
              config.devShells."zig-0-17"
            ];

            # Project-specific tools. The quic-tls module builds
            # baskingspot/tls, which translates its libcrypto bindings at
            # compile time and links libcrypto: the default build needs them,
            # and without these the translate step cannot find a header.
            # Only `-Dno-tls` builds without them.
            packages = with pkgs; [
              openssl
              pkg-config
              # The foreign peers in tools/interop_go*: quic-go and x/net/quic.
              go
            ];
            shellHook = ''
              export PKG_CONFIG_PATH="${lib.makeSearchPathOutput "dev" "lib/pkgconfig" [ pkgs.openssl ]}"
              # A crashing test must not drop a 55 MB core file into the tree.
              # One did, and it was committed and pushed before anyone noticed.
              ulimit -c 0
            '';
          };
        };
    };
}
