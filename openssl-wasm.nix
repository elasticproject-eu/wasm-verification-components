{ lib, pkgs, stdenv, perl, zig, fetchzip, fetchFromGitHub }:
let
  wasi-sdk = pkgs.callPackage ./wasi-sdk.nix {};
in
stdenv.mkDerivation {

  name = "openssl-wasm";

  #src = fetchFromGitHub {
  #        owner = "jedisct1";
  #        repo = "openssl-wasm";
  #        rev = "fe926b5006593ad2825243f97e363823cd56599f";
  #        fetchSubmodules = true;
  #        hash = "sha256-5CkekfHbeC3puws3tpXOGg7Irlod8bC1wXeceGLGQmM=";
  #};

  src = fetchFromGitHub {
    owner = "openssl";
    repo = "openssl";
    tag = "openssl-3.5.4";
    hash = "sha256-tFs6yry9I4p8KNnx1C7592NwF5ag3+bGlmWm1NKjxa8=";
  };

  nativeBuildInputs = [ perl zig ];

  patchPhase = ''
  runHook prePatch
  patchShebangs Configure config util
  runHook postPatch
  '';

  configurePhase = ''
  runHook preConfigure
  WASI_SDK_PATH=${wasi-sdk} \
  CC=${wasi-sdk}/bin/wasm32-wasip2-clang \
  AR=${wasi-sdk}/bin/llvm-ar \
  RANLIB=${wasi-sdk}/bin/llvm-ranlib \
  NM=${wasi-sdk}/bin/llvm-nm \
  CFLAGS="-O3 -msimd128" \
  CXXFLAGS="-O3 -msimd128" \
  perl ./Configure gcc \
        --prefix="$out" \
        --openssldir="$out/ssl" \
        no-shared no-dso no-asm \
        no-apps no-tests \
        no-sock no-dgram \
        no-threads no-async \
        no-engine no-secure-memory \
        no-ui-console no-autoload-config
  runHook postConfigure
  '';

  buildPhase = ''
  runHook preBuild
  CC=${wasi-sdk}/bin/wasm32-wasip2-clang \
  AR=${wasi-sdk}/bin/llvm-ar \
  RANLIB=${wasi-sdk}/bin/llvm-ranlib \
  NM=${wasi-sdk}/bin/llvm-nm \
  CFLAGS="-O3 -msimd128" \
  CXXFLAGS="-O3 -msimd128" \
  make -j"$(nproc)" 
  runHook postBuild
  '';

  installPhase = ''
  runHook preInstall
  mkdir -p $out
  make install_sw
  runHook postInstall
  '';

  doChecks = false;

}
