{ lib, rustPlatform, openssl, pkg-config, trustmee-components }:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "trustmee-components-test";
  version = "0.1.0";
  src = lib.fileset.toSource {
          root = ../.;
          fileset = lib.fileset.difference
                      ../.
                        (lib.fileset.unions [
                          (lib.fileset.maybeMissing ./result)
                          (lib.fileset.fileFilter (file: file.hasExt "nix") ./.)]);
        };
  
  cargoHash = "sha256-i5XxxA0BGQ7Oqln4z44C/LereYUaHnXMuo2onvmfZ8U=";
  #cargoLock = {
  #  lockFile = ../Cargo.lock;
  #};

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];

  buildPhase = ''
  runHook preBuild
  cargo build -p tdx-verifier-test -p snp-verifier-test
  #env -u OPENSSL_NO_PKG_CONFIG CFLAGS= CXXFLAGS=  cargo build -p snp-verifier-test
  runHook postBuild
  '';

  installPhase = ''
  runHook preInstall
  mkdir -p $out/bin
  install -m 755 -t $out/bin target/debug/tdx-verifier-test target/debug/snp-verifier-test
  runHook postInstall
  '';

  doCheck = false;

  meta = {
    description = "Verification component tests for TrustMee";
    homepage = "https://github.com/elasticproject-eu/trustmee";
    licence = lib.licences.asl20;
    maintainers = [];
  };
})

