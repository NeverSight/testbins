# testbins

`testbins` is the versioned binary corpus consumed by NeverD integration tests.
It owns the source snapshots, purpose-built probes, compilers, validation,
manifests, and generated binaries. NeverD treats the repository as read-only
test data and does not rebuild these binaries.

Every binary is compiled from the sources in this repository by GitHub Actions.
Nothing is uploaded from a developer's machine.

## Product lines

| Line | Formats | Manifest | Schema | Workflow |
|---|---|---|---|---|
| `windows-eh` | PE | `manifests/windows-eh.json` | `schema/windows-eh-manifest.schema.json` | `build-windows-eh.yml` |
| `rust-eh` | ELF, PE, Mach-O | `manifests/rust-eh.json` | `schema/rust-eh-manifest.schema.json` | `build-rust-eh.yml` |

Both follow the same shape: sources pinned in the repository, a matrix script, a
per-cell build script, a fragment merge, a strict JSON Schema, a verifier that
re-derives every claim from the bytes on disk, and a four-stage workflow where
only a `push` to `main` is granted `contents: write`.

## Windows exception corpus

The Windows producer covers Microsoft SEH and C++ exception metadata across
two toolchains and four canonical PE architectures:

| Toolchain | Architecture | C++ EH format | Cookie | Optimization | Cells |
|---|---|---|---|---|---:|
| MSVC | x86-64 | EH3, EH4 | `/GS-`, `/GS` | `/Od`, `/O2` | 8 |
| clang-cl | x86-64 | EH3 | `/GS-`, `/GS` | `/Od`, `/O2` | 4 |
| MSVC | x86, ARM32, ARM64 | native | `/GS-`, `/GS` | `/Od`, `/O2` | 12 |
| clang-cl | x86, ARM64 | native | `/GS-`, `/GS` | `/Od`, `/O2` | 8 |

The complete matrix contains 32 cells. Twenty-four full-capability cells contain
six PE files each. The eight host-native clang-cl x86/x86-64 cells contain three
PE files each, for a canonical total of 168 artifacts.

`x86` is the canonical name for the 32-bit i386 target; the corpus does not
duplicate it under two names. EH4 is the compressed Microsoft x64 C++ EH
format and is produced only by MSVC. MSVC EH3 is forced with `/d2FH4-`, EH4 is
forced with `/d2FH4`, and the resulting runtime personality is verified.
clang-cl emits EH3 for the x64 Microsoft ABI and receives an explicit target
triple for every architecture. Non-x64 targets use their native Windows
exception ABI and are not mislabeled as EH3 or EH4.

Official clang-cl supports SEH `__try` on Windows x86, x86-64, and ARM64, but
not ARM32; its ARM32 backend also rejects C++ funclet EH. The producer therefore
does not advertise an ARM32 clang-cl exception cell. MSVC supplies the ARM32 SEH
and C++ EH artifacts. The capability-specific matrix is enforced by both the
producer and the complete-matrix verifier.

`/GS` and the C++ EH format are independent controls. The manifest records both
axes. Focused `/GS` probes must expose a nonzero, writable security cookie via
the PE Load Config directory; personality evidence is validated independently.

## Test inputs

Every full-capability cell builds:

- `xcpt4`, `nested_collided`, `xframe_eh_exe`, and `xframe_eh_dll` from the
  pinned [Microsoft Windows SEH tests](https://github.com/microsoft/windows_seh_tests);
- `seh_probe`, which exercises nested `__try`, `__except`, `__finally`, and a
  buffer-protected function;
- `cxx_eh_probe`, which exercises typed and base catches, cleanup actions,
  nested regions, rethrow, and a buffer-protected catch.

The host-native clang-cl x86 and x86-64 cells omit `xcpt4` and the `xframe` DLL/
EXE pair because those executables do not pass their own runtime tests under
clang-cl. `nested_collided` and both focused probes are still built and
executed. Cross-target clang-cl ARM64 retains all structurally validated images.

The imported source snapshot is pinned by full commit and per-file SHA-256 in
`sources/windows-seh-tests/UPSTREAM.json`. Its license is retained in the
snapshot and under `LICENSES/`.

## Artifact names

Both the directory and filename repeat every build axis. For example:

```text
corpus/windows-eh/msvc/x86_64/fh4/gs/o2/abi-probe/
  cxx_eh_probe-msvc-x86_64-fh4-gs-o2.exe

corpus/windows-eh/clang-cl/aarch64/native/no-gs/o0/abi-probe/
  cxx_eh_probe-clang-cl-aarch64-native-no-gs-o0.exe
```

The canonical manifest is `manifests/windows-eh.json`. Schema version 2 records
the exact compiler and linker identities per artifact, target triple, flags,
execution status, hash, size, structural PE evidence, and NeverD validation
level.

## Validation levels

- `exception-graph`: x64 artifacts must produce non-malformed normalized SEH or
  C++ exception graphs with the declared personalities and minimum graph size.
- `unwind-only`: ARM32 and ARM64 must produce bounded, non-malformed table
  unwind records. Their language payload normalization is tracked separately.
- `load-only`: x86 must load with the correct architecture. Its registration-
  chain language metadata is not falsely reported as table-based reconstruction.

x86 and x86-64 executables run on the hosted x64 Windows runner before
publication. ARM32 and ARM64 are cross-built and are not claimed to have run
natively; the producer instead verifies COFF machine values, exception
directories, `.pdata` runtime-function entries, referenced unwind-data bodies
(including payloads merged by the linker into `.rdata`),
Load Config security-cookie pointers, sections, imports, hashes, and manifest
consistency. `llvm-readobj --unwind`
provides an additional independent producer check for ARM artifacts.

## Rust exception corpus

Rust has no unwind table format of its own. On every non-MSVC target it emits an
Itanium LSDA with `rust_eh_personality`, and on `*-pc-windows-msvc` it emits the
same `__CxxFrameHandler3` tables C++ uses. The Rust producer therefore varies the
target first, because the target is what changes the format:

| Target | Object format | Unwind metadata | Runner | Executable runs? |
|---|---|---|---|---|
| `x86_64-unknown-linux-gnu` | ELF | `.eh_frame` + `.gcc_except_table` | `ubuntu-24.04` | yes |
| `aarch64-unknown-linux-gnu` | ELF | `.eh_frame` + `.gcc_except_table` | `ubuntu-24.04` | cross-built |
| `x86_64-pc-windows-msvc` | PE | `.pdata` + MSVC C++ EH tables | `windows-2022` | yes |
| `x86_64-apple-darwin` | Mach-O | `__unwind_info` + `__eh_frame` | `macos-15` | cross-built |
| `aarch64-apple-darwin` | Mach-O | `__unwind_info` + `__eh_frame` | `macos-15` | yes |

Each target is crossed with two panic strategies (`unwind`, `abort`) and two
optimization levels (`-C opt-level=0`, `-C opt-level=2`), giving 20 cells. Every
cell builds both crates, for a canonical total of 40 artifacts.

`aarch64-unknown-linux-gnu` is linked with `gcc-aarch64-linux-gnu`;
`x86_64-apple-darwin` needs no extra tooling because the macOS SDK carries both
slices. Neither can be executed on its runner, and neither claims to have been.

The toolchain is pinned to an exact release in `rust-toolchain.toml`, and the
manifest records the `rustc -vV` release, commit hash, commit date, and LLVM
version that produced every artifact. Builds pass `--remap-path-prefix`, and the
verifier fails if the remapped checkout path is still findable in a published
binary.

### Test inputs

Two dependency-free `std` crates under `sources/rust-eh/`, compiled by `rustc`
directly rather than through Cargo, so CI needs no registry and every flag in
the manifest is a flag the producer actually passed:

- `rust_eh_probe` (`bin`) holds a `Drop` value across a panicking call, calls
  `std::panic::catch_unwind`, nests drop scopes, crosses `extern "C"` and
  `extern "C-unwind"` boundaries, and reaches four distinct `core::panicking`
  entry points: an explicit `panic!`, an `unwrap()` on `None`, an integer
  overflow, and both an array index and a range slice out of bounds.
- `rust_eh_cdylib` (`cdylib`) puts the same machinery behind C-ABI exports,
  which is where the `extern "C"` abort-on-unwind guard actually matters.

`-C overflow-checks=on` is passed at every optimization level, because rustc
otherwise ties overflow checks to debug assertions and drops the arithmetic
panic once optimizing.

### The aborting builds are negative controls

`-C panic=abort` compiles the producer's own frames with no landing pads at all,
which is what `neverd.expect_no_landing_pads` asserts and what every zeroed
minimum in those artifacts records.

It does not empty the image. The prebuilt standard library was compiled to
unwind, so an aborting artifact still carries `.eh_frame`, an except table,
`rust_eh_personality`, and `_Unwind_Resume`. Exactly one thing disappears:
`_Unwind_RaiseException` is referenced only by the `panic_unwind` runtime, which
an aborting build does not link. The manifest claims that absence and nothing
more, and the verifier proves it from the symbol table.

### Validation levels

- `panic-graph`: unwinding artifacts must produce classified Rust landing pads
  with the declared personality, including a `catch_unwind` boundary.
- `unwind-only`: aborting artifacts must produce bounded, non-malformed unwind
  records, and no Rust panic semantics are claimed for them.

The MSVC minimums are deliberately lower than the Itanium ones. A Rust frame on
`*-pc-windows-msvc` is spelled with the same tables as a C++ frame, and the only
thing that separates them is a catch naming the unmangled `rust_panic` type
descriptor. A frame that merely runs `Drop` glue is therefore not attributable
to Rust, so drop-glue frames, abort guards, and panic sites are not claimed
there. The `rust_panic` descriptor itself is asserted as a required string,
because it is the one piece of Rust identity a stripped PE still carries.

### Artifact names

Both the directory and the filename repeat every build axis:

```text
corpus/rust-eh/x86_64-unknown-linux-gnu/unwind/o2/bin/
  rust_eh_probe-x86_64-unknown-linux-gnu-unwind-o2

corpus/rust-eh/aarch64-apple-darwin/abort/o0/cdylib/
  rust_eh_cdylib-aarch64-apple-darwin-abort-o0.dylib
```

Linux and macOS executables have no extension, so `.gitattributes` marks the
generated artifact directories as binary by path rather than by suffix.

## Repository layout

```text
.github/workflows/        Build, assemble, and publish workflows
corpus/windows-eh/        Committed generated PE files
corpus/rust-eh/           Committed generated ELF, PE, and Mach-O files
manifests/                Canonical machine-readable contracts
schema/                   Manifest schemas
scripts/                  Matrices, builders, mergers, verifiers, and tests
sources/msvc-exceptions/  Focused ABI probes
sources/rust-eh/          Rust panic and unwinding probes
sources/windows-seh-tests Pinned official source snapshot
rust-toolchain.toml       The exact rustc release the Rust corpus is built with
LICENSES/                 Third-party license notices
```

## Producer checks

Cross-platform checks:

```bash
python3 -m unittest discover -s scripts/tests -v
python3 -m py_compile \
  scripts/windows_matrix.py \
  scripts/verify_windows_corpus.py \
  scripts/Merge-WindowsCorpus.py \
  scripts/rust_matrix.py \
  scripts/object_readers.py \
  scripts/json_schema_check.py \
  scripts/verify_rust_corpus.py \
  scripts/merge_rust_corpus.py \
  scripts/build_rust_corpus.py
python3 -m json.tool schema/windows-eh-manifest.schema.json >/dev/null
python3 -m json.tool schema/rust-eh-manifest.schema.json >/dev/null
python3 scripts/windows_matrix.py --json
python3 scripts/rust_matrix.py --json
```

On Windows with the required Visual Studio target tools and LLVM components,
one Windows cell can be built with PowerShell 7:

```powershell
./scripts/Build-WindowsCorpus.ps1 `
  -Toolchain msvc `
  -Architecture x86_64 `
  -Optimization o0 `
  -SecurityCookie off `
  -CxxFormat fh3 `
  -OutputRoot ./staging
```

```bash
python3 scripts/verify_windows_corpus.py \
  manifests/windows-eh.json \
  --root . \
  --require-complete-matrix
```

One Rust cell can be built anywhere the pinned toolchain and the cell's linker
are available:

```bash
python3 scripts/build_rust_corpus.py \
  --target aarch64-apple-darwin \
  --panic-strategy unwind \
  --optimization o2 \
  --output-root ./staging
```

`--describe-only` resolves the same cell without building anything, which is how
the producer tests check all 20 cells on a machine with no Rust installed.

```bash
python3 scripts/verify_rust_corpus.py \
  manifests/rust-eh.json \
  --root . \
  --require-complete-matrix
```

## CI publication

**Build and publish Windows EH corpus** and **Build and publish Rust EH corpus**
each run their complete matrix when their producer source, schema, scripts, or
workflow changes. They are independent, and each publishes only its own tree.

- Pull requests build and validate with read-only repository permissions.
- A successful producer change on `main` assembles and re-verifies the complete
  corpus, then a dedicated job receives `contents: write`.
- The Windows publish job synchronizes only `corpus/windows-eh` and
  `manifests/windows-eh.json`; the Rust publish job synchronizes only
  `corpus/rust-eh` and `manifests/rust-eh.json`. Each creates a bot commit only
  when its own files changed, and pushes it to `main`.
- Generated-only paths do not trigger either producer workflow. Concurrency and
  trigger-revision checks prevent an older run from publishing over newer
  producer source.

Repository settings must allow GitHub Actions to write contents and must permit
this generated-file bot commit on `main`.

### Empty-repository bootstrap

An empty remote cannot run a workflow it does not contain. The first publication
therefore has this order:

1. Review the source snapshots, probes, scripts, schemas, workflows, and docs.
2. The repository owner makes the first source/workflow commit and pushes it to
   `main`.
3. Each workflow builds and pushes its first generated corpus commit.
4. NeverD records that reviewed `testbins` commit as its submodule gitlink.

## NeverD integration

The intended NeverD location is `unittests/corpus`:

```bash
git submodule add \
  https://github.com/NeverSight/testbins.git \
  unittests/corpus
git submodule update --init --recursive unittests/corpus
```

After the canonical generated commit exists, enable the focused consumer tests:

```bash
cmake -S . -B build-corpus \
  -DBUILD_TESTING=ON \
  -DNEVERD_ENABLE_BINARY_CORPUS_TESTS=ON
cmake --build build-corpus \
  --target check-neverd-windows-eh-corpus \
  --parallel 4
cmake --build build-corpus \
  --target check-neverd-rust-eh-corpus \
  --parallel 4
```

Configuration fails immediately if the pinned submodule revision does not
contain the manifest a target consumes. NeverD verifies hashes and parses every
image as data through its public loader; it never executes corpus binaries.
