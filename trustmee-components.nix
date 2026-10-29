{ lib, callPackage, rustPlatform, fetchzip }:
let
  openssl-wasm = callPackage ./openssl-wasm.nix {};
  wasi-sdk = callPackage ./wasi-sdk.nix {};
  build-env = "RUSTFLAGS='-C target-feature=+simd128' OPENSSL_DIR=\"${openssl-wasm}\" WASI_SDK_PATH=\"${wasi-sdk}\" ";
  component_packages = [ "tdx" "sgx" "snp" "recfa" "kata-policy" ];
in
rustPlatform.buildRustPackage (finalAttrs:
  let package_names = (builtins.map (name: (name + "-verifier-component")) component_packages); in{
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

  buildPhase = let
    package_name_args = builtins.concatStringsSep " " (builtins.map (package: ("-p " + package)) package_names); in
  ''
  runHook preBuild
  ${build-env} cargo build ${package_name_args} --release --target wasm32-wasip2
  runHook postBuild
  '';

  installPhase = let
    install_components = builtins.concatStringsSep "\n" (builtins.map
      (package: "install -Dm644 target/wasm32-wasip2/release/${builtins.replaceStrings ["-"] ["_"] package}.wasm -t $out/lib")
      package_names); in
  ''
  runHook preInstall
  ${install_components}
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

