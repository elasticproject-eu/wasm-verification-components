{ stdenv, fetchzip, autoPatchelfHook, zlib, libxml2, ncurses }:
stdenv.mkDerivation {
  pname = "wasi-sdk";
  version = "34.0";
  src = fetchzip {
    url = "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz";
    hash = "sha256-gIP10iJ2+q70w2868jGkTkjDj/nJafs90MbN7zgb+KU=";
  };
  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib zlib libxml2 ncurses ];
  dontConfigure = true;
  dontBuild = true;
  installPhase = "cp -r . $out";
}
