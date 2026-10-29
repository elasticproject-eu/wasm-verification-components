{ lib, callPackage, rustPlatform, fetchzip }:
let
  openssl-wasm = callPackage ./openssl-wasm.nix {};
  wasi-sdk = callPackage ./wasi-sdk.nix {};
  build-env = "RUSTFLAGS='-C target-feature=+simd128' OPENSSL_DIR=\"${openssl-wasm}\" WASI_SDK_PATH=\"${wasi-sdk}\" ";
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "wasm-verification-components";
  version = "0.1.0";
  src = ./.;
  
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "sev-7.1.0" = "sha256-MCjCoZ6rni/3awq02R3L0yXOEmf70SAzNF6v77OnBr8=";
    };
  };

  env = {
    WASI_SDK_PATH = "${wasi-sdk}";
  };

  buildPhase = ''
  runHook preBuild
  ${build-env} cargo build -p snp-verifier-component --release --target wasm32-wasip2
  cargo build -p tdx-verifier-component -p sgx-verifier-component -p recfa-verifier-component --release --target wasm32-wasip2
  runHook postBuild
  '';

  installPhase = ''
  runHook preInstall
  install -Dm644 target/wasm32-wasip2/release/snp_verifier_component.wasm -t $out/lib
  install -Dm644 target/wasm32-wasip2/release/tdx_verifier_component.wasm -t $out/lib
  install -Dm644 target/wasm32-wasip2/release/sgx_verifier_component.wasm -t $out/lib
  install -Dm644 target/wasm32-wasip2/release/recfa_verifier_component.wasm -t $out/lib
  runHook postInstall
  '';

  doCheck = false;

  meta = {
    description = "Verification components for TrustMee";
    homepage = "https://github.com/elasticproject-eu/trustmee";
    licence = lib.licences.asl20;
    maintainers = [];
  };
})

