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
| `cxx-itanium-eh` | ELF, Mach-O, PE | `manifests/cxx-itanium-eh.json` | `schema/cxx-itanium-eh-manifest.schema.json` | `build-cxx-itanium-eh.yml` |
| `objc-eh` | Mach-O | `manifests/objc-eh.json` | `schema/objc-eh-manifest.schema.json` | `build-objc-eh.yml` |
| `ada-d-eh` | ELF | `manifests/ada-d-eh.json` | `schema/ada-d-eh-manifest.schema.json` | `build-ada-d-eh.yml` |

Each line follows the same shape: sources pinned in the repository, a matrix
script, a per-cell build script, a fragment merge, a strict JSON Schema, a
verifier that re-derives every claim from the bytes on disk, and a four-stage
workflow where only the publish job on a `main` push or manual `main` dispatch
is granted `contents: write`.

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

## C++ Itanium exception corpus

The Itanium C++ ABI is one exception model with three containers and two
producers, and the point of this line is that those combinations disagree with
each other. The producer therefore varies the (toolchain, target) pair first,
because that pair is what changes the format:

| Toolchain | Target | Unwind metadata | Personality | Runner | Executables run? |
|---|---|---|---|---|---|
| gcc | `x86_64-linux-gnu` | `.eh_frame` + `.gcc_except_table` | `__gxx_personality_v0` | `ubuntu-24.04` | yes |
| gcc | `aarch64-linux-gnu` | `.eh_frame` + `.gcc_except_table` | `__gxx_personality_v0` | `ubuntu-24.04` | cross-built |
| gcc | `armv7-linux-gnueabihf` | `.ARM.exidx` + `.ARM.extab` | `__gxx_personality_v0` | `ubuntu-24.04` | cross-built |
| gcc | `x86_64-w64-mingw32` | `.pdata` + `.xdata` | `__gxx_personality_seh0` | `ubuntu-24.04` | cross-built |
| clang | `x86_64-linux-gnu` | `.eh_frame` + `.gcc_except_table` | `__gxx_personality_v0` | `ubuntu-24.04` | yes |
| clang | `aarch64-linux-gnu` | `.eh_frame` + `.gcc_except_table` | `__gxx_personality_v0` | `ubuntu-24.04` | cross-built |
| clang | `armv7-linux-gnueabihf` | `.ARM.exidx` + `.ARM.extab` | `__gxx_personality_v0` | `ubuntu-24.04` | cross-built |
| clang | `x86_64-apple-darwin` | `__unwind_info` + `__gcc_except_tab` | `__gxx_personality_v0` | `macos-15` | cross-built |
| clang | `arm64-apple-darwin` | `__unwind_info` + `__gcc_except_tab` | `__gxx_personality_v0` | `macos-15` | yes |

Each of the nine cells builds the same eight variants, for a canonical total of
72 artifacts: the main probe at `-O0` and `-O2`, with and without symbols; the
exception-free control; the shared object at both optimization levels; and the C
probe.

Three of those differences are the reason the line exists. 32-bit ARM replaces
the DWARF chain outright, so there is no `.eh_frame` and no `.gcc_except_table`
anywhere -- the language specific data area is emitted inline in `.ARM.extab`,
indexed by `.ARM.exidx`. mingw-w64 keeps Itanium language semantics but
dispatches them through Windows SEH, so the frames live in `.pdata`/`.xdata` and
the personality is spelled `seh0`. Mach-O prefers compact unwind records and
keeps `__eh_frame` only for the frames that encoding cannot describe, so its
presence is not something the producer's flags decide and the manifest does not
claim it.

The corpus deliberately carries no `-fsjlj-exceptions` axis. The setjmp/longjmp
model is a configure-time property of the toolchain rather than a flag a
distribution compiler reliably honours, so a cell for it would be red more often
than it was informative. It is the obvious next axis if a producer that
guarantees it is ever pinned here.

The Linux cells pin GCC 13 and Clang 18 through the versioned apt packages they
install; the macOS cells pin Apple clang 17 by selecting a specific Xcode before
building. Every artifact records the release its driver actually reported, and
the verifier rejects a manifest whose recorded release is outside the pinned
series. Builds pass `-ffile-prefix-map` and `-g0`, and the verifier fails if the
remapped checkout path is still findable in a published binary.

### Test inputs

Three sources under `sources/cxx-itanium-eh/`, with no dependency beyond the C
and C++ standard libraries:

- `cxx_eh_probe.cpp` covers every shape one LSDA can take: catch by value, by
  const reference, and by pointer; a four-clause ladder; `catch (...)`; a bare
  `throw;`; single and array cleanups; nested try; a base catch for a derived
  throw and the same through virtual inheritance; a throw through a lambda and
  through a `std::function`; a `noexcept` body that can throw; `return` from
  inside a try; a try inside a loop; and a function-scope static whose
  initializer can throw.
- `cxx_eh_shared.cpp` puts the same machinery behind a shared-object boundary,
  including an entry that calls back out and catches what comes back.
- `c_eh_probe.c` is C compiled with `-fexceptions` and
  `__attribute__((cleanup))`, which produces a `__gcc_personality_v0` table with
  cleanup actions and no type table at all. It links the shared object, so a C++
  exception really does travel through its frames.

### The exception-free build is the negative control

`cxx_eh_probe_noexc` is the same source as `cxx_eh_probe` compiled with
`-fno-exceptions`, so everything that disappears disappeared because of one
flag. Everything that raises sits behind `CXX_EH_PROBE_EXCEPTIONS`, including
the exception types, so the control has neither an except table nor the RTTI
that would identify one. It still passes `-fasynchronous-unwind-tables`: without
frame records there would be no metadata left to validate, and `cfi-only` would
be a claim about an empty image.

What it claims to lack is scoped to what the flag decides. On ELF and Mach-O it
asserts no except table and no `__cxa_throw`, because the C++ runtime is on the
other side of a dynamic dependency. The mingw cell links a static `libstdc++`
and therefore claims nothing: an except table there could belong to the runtime
rather than to the producer.

### Validation levels

- `lsda-graph`: a decoded call-site table, action chain, and type table reached
  through `.gcc_except_table`, `__gcc_except_tab`, or the SEH handler data.
- `ehabi`: the same graph reached through an `.ARM.exidx` index and an inline
  `.ARM.extab` entry.
- `cfi-only`: bounded, non-malformed frame records, and nothing about exception
  semantics.

### Artifact names

Both the directory and the filename repeat every build axis:

```text
corpus/cxx-itanium-eh/gcc/armv7-linux-gnueabihf/o2/symtab/exe/
  cxx_eh_probe-gcc-armv7-linux-gnueabihf-o2-symtab

corpus/cxx-itanium-eh/clang/arm64-apple-darwin/o0/symtab/shared/
  libcxx_eh_shared-clang-arm64-apple-darwin-o0-symtab.dylib
```

A stripped artifact keeps no name of anything the producer compiled, so its
evidence is the mangled name of the type it throws: RTTI is data, and
`15CxxEhProbeError` survives a strip that removes every function name.

## Objective-C exception corpus

Objective-C uses an Itanium language-specific data area but gives its type-table
slots Apple runtime semantics. A class catch names an `objc_typeinfo`, `@catch
(id)` names `OBJC_EHTYPE_id`, and `@catch (...)` is the null catch-all entry.
The product line fixes that interpretation to Apple's non-fragile runtime and
crosses it with both Mach-O architectures produced by the pinned Xcode:

| Runtime | Target | Unwind metadata | Personality | Runner | Executables run? |
|---|---|---|---|---|---|
| Apple | `arm64-apple-darwin` | `__unwind_info` + `__eh_frame` + `__gcc_except_tab` | `__objc_personality_v0` | `macos-15` | yes |
| Apple | `x86_64-apple-darwin` | `__unwind_info` + `__gcc_except_tab` | `__objc_personality_v0` | `macos-15` | cross-built |

Each cell builds six executables, for a canonical total of 12 artifacts: the
ARC exception probe at `-O0` and `-O2`, each with and without local symbols; an
`-O2` manual-retain/release control; and an `-O2 -fno-objc-exceptions` control.
All six arm64 executables must print `objc-eh probe passed` before their
fragment can be uploaded. The x86_64 cell is never reported as run.

The architecture-specific `__eh_frame` contract is measured rather than
assumed. Under the pinned Apple clang 17/Xcode 16.4 line, arm64 keeps a
well-formed DWARF frame chain beside compact unwind, while x86_64 encodes these
frames entirely in `__unwind_info`. The verifier requires the arm64 chain and
rejects an x86_64 chain, and independently walks the compact-unwind table for
both.

### Test input and controls

`sources/objc-eh/objc_eh_probe.m` defines a local `NSException` subclass and
covers class, framework-class, `id`, and ellipsis catches; a multi-clause catch
ladder; nested tries; `@finally`; rethrow; cleanup-only frames;
`@synchronized`; `@autoreleasepool`; and an ARC strong local held across a
throwing call. Every probe is externally visible and `noinline` so the symbol
inventory and exception shapes survive optimization.

The MRR variant changes only `-fobjc-arc` to `-fno-objc-arc`. Its binary must
lack the ARC return-value handshake import that both ARC optimization levels
and the exception-free ARC control retain. The exception-free variant changes
only `-fobjc-exceptions` to `-fno-objc-exceptions`; it must lack
`__gcc_except_tab`, `__objc_personality_v0`, and `objc_exception_throw`, while
still carrying valid unwind metadata.

Mach-O adds an underscore to C symbols in its raw nlist. Manifests deliberately
use source spellings such as `objc_exception_throw` and
`__objc_personality_v0`; `object_readers.py` exposes that normalized spelling
while retaining the raw name too. This keeps container syntax out of the
Objective-C ABI contract.

### Artifact names

Both the directory and filename repeat every build axis:

```text
corpus/objc-eh/apple/arm64-apple-darwin/o2/stripped/
  objc_eh_probe-apple-arm64-apple-darwin-o2-stripped

corpus/objc-eh/apple/x86_64-apple-darwin/o2/symtab/
  objc_eh_probe_mrr-apple-x86_64-apple-darwin-o2-symtab
```

The executables have no extension, so `.gitattributes` marks only the generated
artifact depth as binary and leaves `corpus/objc-eh/README.md` diffable.

## Ada and D exception corpus

Ada and D reuse the Itanium call-site/action/type-table container, but their
type-table slots are not C++ `std::type_info`. GNAT stores `Exception_Id`
descriptors; DMD, GDC, and LDC store `ClassInfo` descriptors. The producer
therefore records three independent claims and refuses to treat personality
recognition as complete support:

| Claim | What it means |
|---|---|
| parseable LSDA | `.eh_frame` plus `.gcc_except_table` decode into a call-site graph |
| native reconstruction | the language personality is preserved and type-table slots stay address-valued opaque descriptors |
| corpus-proven | a real GNAT, GDC, DMD, or LDC artifact exists for that claim |

The matrix is six (toolchain, target) cells, each at `-O0` and `-O2`, for a
canonical total of 12 ELF executables:

| Toolchain | Target | Personality | Descriptor ABI | Runner | Executables run? |
|---|---|---|---|---|---|
| gnat-13 | `x86_64-linux-gnu` | `__gnat_personality_v0` | `gnat-exception-id` | `ubuntu-24.04` | yes |
| gnat-13 | `aarch64-linux-gnu` | `__gnat_personality_v0` | `gnat-exception-id` | `ubuntu-24.04` | cross-built |
| gdc-13 | `x86_64-linux-gnu` | `__gdc_personality_v0` | `d-classinfo` | `ubuntu-24.04` | yes |
| gdc-13 | `aarch64-linux-gnu` | `__gdc_personality_v0` | `d-classinfo` | `ubuntu-24.04` | cross-built |
| dmd-2.112.1 | `x86_64-linux-gnu` | `__dmd_personality_v0` | `d-classinfo` | `ubuntu-24.04` | yes |
| ldc-1.42.0 | `x86_64-linux-gnu` | `_d_eh_personality` | `d-classinfo` | `ubuntu-24.04` | yes |

GNAT and GDC install from versioned apt packages. DMD and LDC install from a
pinned `dlang-community/setup-dlang` revision. GCC-family cells pass
`-ffile-prefix-map` and `-g0`; DMD and LDC compile a relative source path
without debug info. The verifier fails if the checkout path is still findable
in a published binary.

### Test inputs

Two sources under `sources/ada-d-eh/`:

- `ada_eh_probe.adb` raises `Constraint_Error` plus two user exceptions, catches
  each by name, and has an `others` handler.
- `d_eh_probe.d` throws three `Exception` subclasses, catches each by class,
  has a `Throwable` fallback, and uses `scope (exit)` so the D cells must
  produce a cleanup pad.

Both print `ada-d-eh probe passed` on the default success path. Native cells
must print that marker before their fragment can be uploaded.

### Artifact names

Both the directory and the filename repeat every build axis:

```text
corpus/ada-d-eh/ada/gnat/x86_64-linux-gnu/o2/
  ada_eh_probe-gnat-x86_64-linux-gnu-o2

corpus/ada-d-eh/d/ldc/x86_64-linux-gnu/o0/
  d_eh_probe-ldc-x86_64-linux-gnu-o0
```

## Repository layout

```text
.github/workflows/        Build, assemble, and publish workflows
corpus/windows-eh/        Committed generated PE files
corpus/rust-eh/           Committed generated ELF, PE, and Mach-O files
corpus/cxx-itanium-eh/    Committed generated ELF, Mach-O, and PE files
corpus/objc-eh/            Committed generated Mach-O files
corpus/ada-d-eh/           Committed generated Ada and D ELF files
manifests/                Canonical machine-readable contracts
schema/                   Manifest schemas
scripts/                  Matrices, builders, mergers, verifiers, and tests
sources/msvc-exceptions/  Focused ABI probes
sources/rust-eh/          Rust panic and unwinding probes
sources/cxx-itanium-eh/   C++ and C Itanium exception probes
sources/objc-eh/           Objective-C runtime and exception probe
sources/ada-d-eh/          Ada and D Itanium exception probes
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
  scripts/build_rust_corpus.py \
  scripts/cxx_itanium_matrix.py \
  scripts/verify_cxx_itanium_corpus.py \
  scripts/merge_cxx_itanium_corpus.py \
  scripts/build_cxx_itanium_corpus.py \
  scripts/objc_matrix.py \
  scripts/verify_objc_corpus.py \
  scripts/merge_objc_corpus.py \
  scripts/build_objc_corpus.py \
  scripts/ada_d_eh_matrix.py \
  scripts/verify_ada_d_eh_corpus.py \
  scripts/merge_ada_d_eh_corpus.py \
  scripts/build_language_eh_corpus.py
python3 -m json.tool schema/windows-eh-manifest.schema.json >/dev/null
python3 -m json.tool schema/rust-eh-manifest.schema.json >/dev/null
python3 -m json.tool schema/cxx-itanium-eh-manifest.schema.json >/dev/null
python3 -m json.tool schema/objc-eh-manifest.schema.json >/dev/null
python3 -m json.tool schema/ada-d-eh-manifest.schema.json >/dev/null
python3 scripts/windows_matrix.py --json
python3 scripts/rust_matrix.py --json
python3 scripts/cxx_itanium_matrix.py --json
python3 scripts/objc_matrix.py --json
python3 scripts/ada_d_eh_matrix.py --json
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

One C++ Itanium cell can be built anywhere the cell's drivers are on `PATH` and
report the pinned release series:

```bash
python3 scripts/build_cxx_itanium_corpus.py \
  --toolchain clang \
  --target arm64-apple-darwin \
  --output-root ./staging
```

`--describe-only` resolves the same cell without building anything, which is how
the producer tests check all nine cells on a machine with no cross toolchain
installed. `scripts/cxx_itanium_matrix.py --plan` prints the whole 72-artifact
inventory with the contract each entry carries, and `--paths` prints just the
canonical paths.

```bash
python3 scripts/verify_cxx_itanium_corpus.py \
  manifests/cxx-itanium-eh.json \
  --root . \
  --require-complete-matrix
```

One Objective-C cell can be built on macOS after selecting the pinned Xcode:

```bash
sudo xcode-select --switch /Applications/Xcode_16.4.app/Contents/Developer
python3 scripts/build_objc_corpus.py \
  --runtime apple \
  --target arm64-apple-darwin \
  --output-root ./staging
```

`--describe-only` resolves either target without invoking clang.
`scripts/objc_matrix.py --plan` prints all 12 contracts, and `--paths` prints
the canonical inventory.

```bash
python3 scripts/verify_objc_corpus.py \
  manifests/objc-eh.json \
  --root . \
  --require-complete-matrix
```

One Ada or D cell can be built anywhere the cell's compiler is on `PATH` and
reports the pinned release:

```bash
python3 scripts/build_language_eh_corpus.py \
  --toolchain gnat \
  --target x86_64-linux-gnu \
  --output-root ./staging
```

`--describe-only` resolves the same cell without a compiler.
`scripts/ada_d_eh_matrix.py --plan` prints all 12 contracts.

```bash
python3 scripts/verify_ada_d_eh_corpus.py \
  manifests/ada-d-eh.json \
  --root . \
  --require-complete-matrix
```

## CI publication

**Build and publish Windows EH corpus**, **Build and publish Rust EH corpus**,
**Build and publish C++ Itanium EH corpus**, **Build and publish Objective-C
EH corpus**, and **Build and publish Ada/D EH corpus** each run their complete
matrix when their producer source, schema, scripts, or workflow changes. They
are independent, and each publishes only its own tree.

- Pull requests build and validate with read-only repository permissions.
- A successful producer change on `main` assembles and re-verifies the complete
  corpus, then a dedicated job receives `contents: write`.
- Each publish job synchronizes only its own generated files: `corpus/windows-eh`
  and `manifests/windows-eh.json`, `corpus/rust-eh` and `manifests/rust-eh.json`,
  `corpus/cxx-itanium-eh` and `manifests/cxx-itanium-eh.json`,
  `corpus/objc-eh` and `manifests/objc-eh.json`, or `corpus/ada-d-eh` and
  `manifests/ada-d-eh.json`. Each creates a bot commit only when its own files
  changed, and pushes it to `main`.
- Generated-only paths do not trigger any producer workflow, and each workflow's
  path filters name its own files rather than `scripts/**`, so one line's change
  does not rebuild another's matrix. Concurrency and trigger-revision checks
  prevent an older run from publishing over newer producer source.

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
cmake --build build-corpus \
  --target check-neverd-cxx-itanium-eh-corpus \
  --parallel 4
```

Configuration fails immediately if the pinned submodule revision does not
contain the manifest a target consumes. NeverD verifies hashes and parses every
image as data through its public loader; it never executes corpus binaries.
