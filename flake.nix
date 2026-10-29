{
  description = "Description for the project";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ nixpkgs, flake-parts, rust-overlay, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        # To import an internal flake module: ./other.nix
        # To import an external flake module:
        #   1. Add foo to inputs
        #   2. Add foo as a parameter to the outputs function
        #   3. Add here: foo.flakeModule

      ];
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { config, self', inputs', pkgs, system, ... }:
      let
        rustBin = rust-overlay.lib.mkRustBin {} pkgs;
        toolchain = rustBin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
      in rec {
        # Per-system attributes can be defined here. The self' and inputs'
        # module parameters provide easy access to attributes of the same
        # system.

        packages.components = pkgs.callPackage ./trustmee-components.nix { inherit rustPlatform; };
        apps.components-test = let
          tests = pkgs.callPackage ./trustmee-components-test.nix {
            inherit rustPlatform;
            trustmee-components = packages.components;
          };
          test-quote = ./tdx-quote.bin;
        in {
          type = "app";
          program = pkgs.writeShellApplication {
            name = "test-tdx";
            text = ''
            "${tests}/bin/tdx-verifier-test" --component "${packages.components}/lib/tdx_verifier_component.wasm" --quote ${../tdx_quote.bin}
            "${tests}/bin/snp-verifier-test" --component "${packages.components}/lib/snp_verifier_component.wasm" --report ${../snp_report_v3_real.bin}
            '';
          };
        };
      };
      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.

      };
    };
}
