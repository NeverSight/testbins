# testbins

`testbins` is the versioned binary corpus consumed by NeverD integration tests.
It owns the source snapshots, purpose-built probes, compilers, validation,
manifests, and generated PE files. NeverD treats the repository as read-only
test data and does not rebuild these binaries.

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
axes and the focused probes provide personality and security-cookie evidence.

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
sections, imports, hashes, and manifest consistency. `llvm-readobj --unwind`
provides an additional independent producer check for ARM artifacts.

## Repository layout

```text
.github/workflows/        Build, assemble, and publish workflow
corpus/windows-eh/        Committed generated PE files
manifests/                Canonical machine-readable contract
schema/                   Manifest schema
scripts/                  Matrix, builder, merger, verifier, and tests
sources/msvc-exceptions/  Focused ABI probes
sources/windows-seh-tests Pinned official source snapshot
LICENSES/                 Third-party license notices
```

## Producer checks

Cross-platform checks:

```bash
python3 -m unittest discover -s scripts/tests -v
python3 -m py_compile \
  scripts/windows_matrix.py \
  scripts/verify_windows_corpus.py \
  scripts/Merge-WindowsCorpus.py
python3 -m json.tool schema/windows-eh-manifest.schema.json >/dev/null
python3 scripts/windows_matrix.py --json
```

On Windows with the required Visual Studio target tools and LLVM components,
one cell can be built with PowerShell 7:

```powershell
./scripts/Build-WindowsCorpus.ps1 `
  -Toolchain msvc `
  -Architecture x86_64 `
  -Optimization o0 `
  -SecurityCookie off `
  -CxxFormat fh3 `
  -OutputRoot ./staging
```

Validate the assembled corpus with:

```bash
python3 scripts/verify_windows_corpus.py \
  manifests/windows-eh.json \
  --root . \
  --require-complete-matrix
```

## CI publication

The **Build and publish Windows EH corpus** workflow runs the complete matrix
when producer source, schema, scripts, or the workflow changes.

- Pull requests build and validate with read-only repository permissions.
- A successful producer change on `main` assembles and re-verifies the complete
  corpus, then a dedicated job receives `contents: write`.
- The publish job synchronizes only `corpus/windows-eh` and
  `manifests/windows-eh.json`, creates a bot commit only when those files
  changed, and pushes it to `main`.
- Generated-only paths do not trigger the producer workflow. Concurrency and
  trigger-revision checks prevent an older run from publishing over newer
  producer source.

Repository settings must allow GitHub Actions to write contents and must permit
this generated-file bot commit on `main`.

### Empty-repository bootstrap

An empty remote cannot run a workflow it does not contain. The first publication
therefore has this order:

1. Review the source snapshot, probes, scripts, schema, workflow, and docs.
2. The repository owner makes the first source/workflow commit and pushes it to
   `main`.
3. The workflow builds and pushes the first generated corpus commit.
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
```

Configuration fails immediately if the pinned submodule revision does not
contain `manifests/windows-eh.json`. NeverD verifies hashes and parses every PE
as data through its public loader; it never executes corpus binaries.
