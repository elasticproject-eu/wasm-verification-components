{ pkgs ? import <nixpkgs> {
  overlays = [
    ( import (builtins.fetchTarball {
      url = "https://github.com/oxalica/rust-overlay/archive/19ecdd08213836b36c4296a3a4f4af5a3d5308db.tar.gz";
      sha256 = "sha256:1x5jxzm82v4h2y39d28clnva8h2l7xdincr2xbvs9h8yhxzx96dv";
    }))
  ];
} }:
let
  toolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
in
pkgs.callPackage ./trustmee-components.nix { inherit rustPlatform; }
