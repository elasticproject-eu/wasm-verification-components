# Getting real ReCFA evidence: exact steps

What you need to produce, and what you already have.

| Input to the verifier | Status | Where it comes from |
|---|---|---|
| policy `F` (`binfo.*`) | **already in the repo** (`policy/F/`, 23 files) | patched typearmor — already run by the authors |
| policy `M` (`*.filtered.map`) | **already in the repo** (`policy/M/`, 26 files) | csfilter |
| the SPEC binaries | **already in the repo** (`spec_gcc/O0/`, `spec_llvm/O0/`) | — |
| `.asm` disassembly | **you generate** | `objdump -d`, binutils ≤ 2.34 |
| `.dot` CFG | **you generate** | `bin/preCFG`, needs Dyninst 10.1 |
| runtime trace (`*_instru-re`) | **you download** | authors' Google Drive |
| folded trace (`*_instru-re_folded`) | **you generate** | `./compress.sh`, no Dyninst needed |

**You do not need typearmor, and you do not need the Ubuntu 16.04 VM.** The README
tells you to build patched typearmor with Dyninst 9.3.1 to produce policy `F`, but
I checked the shipped files and all 23 already contain the patched-typearmor
`Indirectstar0x…` lines (2214 of them for bzip2). That whole step is done. You
only need Dyninst **10.1** for `preCFG`.

---

## Step 0 — clone upstream ReCFA

Everything below runs against a checkout of the upstream repo: `bin/preCFG`,
`src/preCFG/`, `policy/F/`, `policy/M/`, `compress.sh` and `lib/libfold.so` all
come from it. Get it first, or later steps will fail with "No such file or
directory".

```bash
mkdir -p ~/work && cd ~/work
git clone --depth 1 https://github.com/suncongxd/ReCFA.git ReCFA   # ~185 MB
```

The container mounts this directory at `/work`, so keep the Dockerfile from step 2
wherever you like — but mount **the checkout**:

```bash
docker run -it --rm -v ~/work/ReCFA:/work recfa-dyninst bash
```

## Step 1 — download the traces

Two files, both requiring a Google sign-in (which is why I could not fetch them):

* **`re-gcc.zip`** → https://drive.google.com/file/d/10WiR7L3w_sRVK1JG6Tu8OKVNexhmwhB6/view?usp=sharing
* **`re-llvm.zip`** → https://drive.google.com/file/d/1aoc1BppBAKIRDSAT0wsxq9WbkZ_rz_jS/view?usp=sharing

Easiest is the browser. From a shell:

```bash
pip install gdown
gdown 10WiR7L3w_sRVK1JG6Tu8OKVNexhmwhB6 -O re-gcc.zip
gdown 1aoc1BppBAKIRDSAT0wsxq9WbkZ_rz_jS -O re-llvm.zip
```

**The archives are flat** — no `spec_gcc/` prefix inside, and both gcc and llvm
traces are mixed together in each. Unzipping alone therefore leaves them in the
wrong place, and `compress.sh` will silently skip every benchmark (see below). Sort
them afterwards:

```bash
cd ~/work/ReCFA
unzip -o /path/to/re-gcc.zip
unzip -o /path/to/re-llvm.zip
mv -v *.gcc_O0_instru-re  spec_gcc/O0/
mv -v *.llvm_O0_instru-re spec_llvm/O0/
ls spec_gcc/O0/*_instru-re | wc -l    # expect 11
```

The path each script demands is exactly
`spec_<cp>/O0/<name>_base.<cp>_O0_instru-re`.

> **Silent-skip warning.** `compress.sh` prints the benchmark name *before* testing
> whether the trace exists:
>
> ```bash
> file_path=$event_root/$name"_base."$CP"_"$OL"_instru-re"
> echo $name
> if [[ -f $file_path ]]; then …
> ```
>
> So a run that lists all 11 names and produces nothing means it found nothing.
> Always confirm with `ls spec_gcc/O0/*_instru-re_folded`, never by the log.

These are the *raw* event streams. Step 4 folds them into what the verifier eats.

---

## Step 2 — build Dyninst 10.1 (Docker, Ubuntu 18.04)

Docker keeps this off your real machine and pins the two versions that matter:
boost 1.65 (matching the sonames the prebuilt `bin/preCFG` wants) and binutils
2.30 (which still prints `callq`).

Save as `Dockerfile.recfa`:

```dockerfile
FROM ubuntu:18.04

# Do NOT rewrite sources.list to old-releases.ubuntu.com: bionic is not there
# (every dist 404s). Despite being EOL, bionic is still served by the default
# archive.ubuntu.com / security.ubuntu.com, so the image's own sources work.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake m4 flex bison git wget ca-certificates \
      zlib1g-dev libboost-all-dev libelf-dev libiberty-dev \
      binutils zstd python3 unzip \
 && rm -rf /var/lib/apt/lists/*
# NOTE 1: deliberately NOT installing libdwarf-dev — upstream says it breaks the build.
# NOTE 2: deliberately NOT installing libtbb-dev — bionic ships 2017~U7, below the
#         2018.6 minimum Dyninst 10.1 requires, so Dyninst fetches its own copy.

WORKDIR /opt
RUN git clone --depth 1 --branch v10.1.0 https://github.com/dyninst/dyninst.git dyninst-10.1.0
# Dyninst fetches and builds matching elfutils/TBB itself, so keep the network on
# and do NOT set STERILE_BUILD.
RUN mkdir -p /opt/dyninst-10.1.0/install && cd /opt/dyninst-10.1.0/install \
 && cmake .. -DCMAKE_INSTALL_PREFIX=/opt/dyninst-10.1.0/install \
 && make -j"$(nproc)" && make install

ENV DYNINST_HOME=/opt/dyninst-10.1.0
ENV DYNINST_INCLUDE=$DYNINST_HOME/install/include
ENV DYNINST_LIB=$DYNINST_HOME/install/lib
ENV DYNINSTAPI_RT_LIB=$DYNINST_LIB/libdyninstAPI_RT.so
ENV LD_LIBRARY_PATH=$DYNINST_LIB
WORKDIR /work
```

Build it and get a shell with your ReCFA checkout mounted:

```bash
docker build -f Dockerfile.recfa -t recfa-dyninst .
docker run -it --rm -v ~/work/ReCFA:/work recfa-dyninst bash
```

**The image already contains a built Dyninst** — the `cmake`/`make install` above
runs at image-build time. Once `docker build` succeeds there is nothing left to
compile, so do not run `cmake` yourself inside the container. Confirm and move on:

```bash
ls /opt/dyninst-10.1.0/install/lib/libparseAPI.so*   # should exist
echo "$DYNINST_LIB"                                  # /opt/dyninst-10.1.0/install/lib
```

The Dyninst build takes a while (tens of minutes) and needs a few GB of disk.

### What this build downloads, and why it can fail

Dyninst 10.1 pulls two dependencies itself, because bionic's versions are too old.
Both URLs were still live when this was written:

| dependency | URL | note |
|---|---|---|
| elfutils 0.176 | `https://sourceware.org/elfutils/ftp/0.176/elfutils-0.176.tar.bz2` | bionic has 0.170, below Dyninst's 0.173 minimum |
| TBB `2018_U6` | `https://github.com/01org/tbb/archive/2018_U6.tar.gz` | redirects to `oneapi-src/oneTBB`; bionic has 2017~U7 |

So keep the network up during `make`, and do **not** set `-DSTERILE_BUILD=ON`
(that forbids fetching and the build then fails on elfutils). If `make` dies
mid-download, just rerun `make -j"$(nproc)"` — it resumes.

If `sourceware.org` is unreachable from your network, build elfutils yourself and
point Dyninst at it instead:

```bash
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/dyninst-10.1.0/install \
         -DElfUtils_ROOT_DIR=/usr/local
```

---

## Step 3 — generate `.dot` and `.asm` (inside the container)

Try the prebuilt binary first; with Dyninst 10.1 and boost 1.65 present it should
now resolve:

```bash
cd /work
ldd bin/preCFG | grep -E "not found" || echo "preCFG: all libraries resolved"
```

If anything is still "not found", rebuild it from source — this is the reliable
path, and the Makefile already uses `$DYNINST_INCLUDE` / `$DYNINST_LIB`:

```bash
cd /work/src/preCFG && make && make install && cd /work
```

Now generate both files for every gcc benchmark. I am deliberately **not** using
`./prepare_csfiltering.sh`, because it also reruns csfilter and would overwrite
the `policy/M/` files you already have:

```bash
cd /work
for b in spec_gcc/O0/*_base.gcc_O0; do
  case "$b" in *.filtered|*.asm|*.dot|*.map|*_instru*) continue ;; esac
  echo "== $b"
  ./bin/preCFG "$b" > "$b.dot"
  objdump -d   "$b" > "$b.asm"
done
```

Repeat with `spec_llvm/O0/*_base.llvm_O0` if you want the llvm set too.

### Verify before you trust them

This is the check that matters most. `check.cpp` matches the literal strings
`callq`, `jmpq   *%rax` and `retq`. binutils ≥ 2.35 prints `call`, `jmp`, `ret`
without the `q`, and the failure is **silent**: no call sites are found, `|F|`
comes out 0, and every trace trivially "passes". I confirmed binutils 2.38
produces zero matches on the shipped bzip2 binary.

```bash
objdump --version | head -1                                   # want <= 2.34
grep -c 'callq'          spec_gcc/O0/bzip2_base.gcc_O0.asm     # must be > 0
grep -c 'jmpq   \*%rax'  spec_gcc/O0/bzip2_base.gcc_O0.asm     # want > 0 for gcc
grep -c '<main>:'        spec_gcc/O0/bzip2_base.gcc_O0.asm     # must be 1
grep -cE '^\s*"\[[0-9a-f]{6},[0-9a-f]{6}' spec_gcc/O0/bzip2_base.gcc_O0.dot  # must be > 0
grep -c 'color=blue'     spec_gcc/O0/bzip2_base.gcc_O0.dot     # must be > 0
```

Addresses must be exactly 6 hex digits — the regexes hardcode `{6}`. The shipped
SPEC binaries are non-PIE at `0x4xxxxx`, so this holds; a PIE binary would not
work without changing upstream.

---

## Step 4 — fold the traces (no Dyninst needed)

```bash
cd /work
export LD_LIBRARY_PATH=/work/lib:$LD_LIBRARY_PATH
./compress.sh gcc
ls -la spec_gcc/O0/*_instru-re_folded
```

`compress.sh` also produces `_folded_gr` and `_folded_gr.zst`. **The verifier
consumes `_folded`**, not those — `verify.sh` passes `_folded`, and the greedy and
zstd stages exist only to measure transmission size in the paper.

Sanity-check that upstream's own verifier is happy before handing anything over:

```bash
./bin/check \
  spec_gcc/O0/bzip2_base.gcc_O0.asm \
  spec_gcc/O0/bzip2_base.gcc_O0.dot \
  policy/F/binfo.bzip2_base.gcc_O0 \
  policy/M/bzip2_base.gcc_O0.filtered.map \
  spec_gcc/O0/bzip2_base.gcc_O0_instru-re_folded \
  2 gcc
```

Expect `|M|=` and `|F|=` both non-zero, then
`No events left unprocessed.Progarm is secure`.

That trailing `2` is the number of executions of `main` in the trace, and it is
per-benchmark. From `verify.sh`:

| benchmark | `num_executions` | | benchmark | `num_executions` |
|---|---|---|---|---|
| bzip2 | 2 | | libquantum | 1 |
| gobmk | 2 | | lbm | 1 |
| perlbench | 7 | | sphinx_livepretend | 1 |
| gcc | 1 | | h264ref | 1 |
| mcf | 1 | | hmmer | 1 |
| milc | 1 | | | |

Getting it wrong makes a legitimate trace fail, so pass the same value to the
component in `recfa-config`.

---

## Step 5 — what to hand back

Per benchmark you want tested (bzip2 is the smallest, start there), four files:

```
spec_gcc/O0/bzip2_base.gcc_O0.asm
spec_gcc/O0/bzip2_base.gcc_O0.dot
spec_gcc/O0/bzip2_base.gcc_O0_instru-re_folded
policy/F/binfo.bzip2_base.gcc_O0            # already in the repo
policy/M/bzip2_base.gcc_O0.filtered.map     # already in the repo
```

Drop them somewhere in this folder and I will wire them into
`recfa-verifier/test_data/spec/` and run the component against them, plus a parity
run against unmodified upstream `check` on the same inputs.

Then it is one command:

```bash
../../target/debug/recfa-verifier-test \
  --component ../../target/wasm32-wasip2/release/recfa_verifier_component.wasm \
  --disassembly bzip2_base.gcc_O0.asm \
  --cfg         bzip2_base.gcc_O0.dot \
  --policy-f    binfo.bzip2_base.gcc_O0 \
  --policy-m    bzip2_base.gcc_O0.filtered.map \
  --trace       bzip2_base.gcc_O0_instru-re_folded \
  --compiler gcc --num-executions 2 --expect secure
```

---

## Can you run the attester yourself?

**Yes — no special hardware at all.** ReCFA needs no TEE, no TPM, no secure
enclave, and no attestation-capable CPU. It is ordinary x86-64 Linux userspace
plus Dyninst static binary rewriting. The paper's trust anchor (kernel + Intel
MPK) is an *assumption*, not something the artifact implements, so you do not even
need an MPK-capable CPU to reproduce the results.

What you need depends on what you want:

**Replay existing evidence** — nothing beyond the verifier. That is exactly what
the Wasm component now does, and it runs anywhere, including inside the TrustMee
sandbox.

**Generate new evidence** — the same Ubuntu 18.04 + Dyninst 10.1 container from
step 2, then:

```bash
cd /work
./instrument.sh gcc                    # writes spec_gcc/O0/<name>_instru
./spec_gcc/O0/bzip2_base.gcc_O0_instru <your workload>   # appends events to a file
./compress.sh gcc
```

Two practical notes. First, reproducing the *paper's* traces requires the SPEC
CPU2006 workloads, which are licensed and not redistributable — that is precisely
why the authors published the traces on Drive. Second, you do not actually need
SPEC: `bin/mutator` will instrument any suitable non-PIE x86-64 ELF, so the
cheapest way to get a genuinely end-to-end trace of your own is to compile a small
C program with `gcc -O0 -no-pie`, instrument it, and run it.

That is exactly what [`custom-e2e/`](custom-e2e/) does, including policy `F` from
the patched typearmor pass: `custom-e2e/attester/Dockerfile.typearmor` builds the
Ubuntu 16.04 + Dyninst 9.3.1 toolchain as a container, so no VM is involved and
no policy file is written by hand. `bash custom-e2e/build.sh --test` runs the
whole chain and then verifies the resulting evidence with the Wasm component.

> **Compile the mutatee with `-g`.** `bin/mutator` injects its `fopen` call by
> resolving the DWARF `FILE` type (`appImage->findType("FILE")`). Without debug
> info the lookup returns null and the mutator **segfaults** inside
> `createAndInsertFopen` — after printing its `Num of iJmps/iCalls/rets/dCalls`
> counts, so it looks like it got most of the way through. The shipped SPEC
> binaries fail identically, which makes it easy to blame your own binary. Add
> `-g`; nothing else about the pipeline changes.

Upstream notes that instrumentation of `sjeng` fails, so skip that one.
