# Manifests

A manifest is the stable interface NeverD consumes. Do not edit one by hand;
change producer inputs and let the publication workflow regenerate it.

## `windows-eh.json`

Generated only after all 32 MSVC/clang-cl Windows exception cells have built and
passed validation. It inventories 168 committed PE artifacts and conforms to
`../schema/windows-eh-manifest.schema.json`. For focused `/GS` probes, its
structural evidence requires a nonzero security cookie referenced by the PE Load
Config directory.

## `rust-eh.json`

Generated only after all 20 Rust cells have built and passed validation across
three runner operating systems. It inventories 40 committed ELF, PE, and Mach-O
artifacts and conforms to `../schema/rust-eh-manifest.schema.json`.

Its `producer` block holds only what every cell shares: the pinned toolchain
channel, the `rustc` release, commit, and LLVM version, and the producer
revision. Anything that legitimately differs between a Linux, Windows, and macOS
runner -- the compiler's host triple, the runner image, its operating system and
architecture -- is recorded on each artifact instead, which is what lets
fragments from three platforms merge into one envelope.

Each artifact carries the exact `rustc` flag vector it was built with, the
structural evidence the verifier re-derives from the file, and a `neverd` block
stating the weakest result the decompiler must produce. Artifacts built with
`-C panic=abort` set every minimum to zero and assert
`expect_no_landing_pads`, scoped to the probe symbols the producer compiled.

## `cxx-itanium-eh.json`

Generated only after all nine (toolchain, target) cells have built and passed
validation across two runner operating systems. It inventories 72 committed ELF,
Mach-O, and PE artifacts and conforms to
`../schema/cxx-itanium-eh-manifest.schema.json`.

Its `producer` block holds the repository revision plus one record per cell,
because nine cells install five different compilers and no single version can
stand for all of them. Each record names the drivers the matrix defines, the
release series the cell is pinned to, and the release the runner actually
reported; the verifier recomputes the first two and rejects a version outside
the third. That per-cell shape is what lets fragments from nine jobs merge into
one envelope.

The pin is a prefix of what the driver says about itself rather than a release
number, because not every driver numbers itself the same way. Debian's mingw
GCC reports `13-posix` and has no minor version to report, the thread model
being part of which compiler it is; pinning the whole string there pins the
model with it, which matters because posix and win32 reach the unwinder
through different `libstdc++` builds.

Each artifact carries the exact driver, flag vector, and pinned environment it
was built with, the corpus paths its link consumed, the structural evidence the
verifier re-derives from the file, and a `neverd` block stating the weakest
result the decompiler must produce.

The evidence makes absence claims as well as presence claims, and both are
scoped to what a flag actually decides. A stripped artifact claims no symbol
names at all and is identified instead by the mangled name of the type it
throws, which is data and survives stripping. The `-fno-exceptions` control
claims no except table and no `__cxa_throw` where the C++ runtime is dynamic,
and claims neither on mingw, where it is linked in statically. ARM artifacts
claim an `.ARM.exidx` index with a minimum entry count and claim nothing about
DWARF, because ARM EHABI has no DWARF frame chain to claim anything about.

## `objc-eh.json`

Generated only after both Apple-runtime target cells have built and passed
validation. It inventories 12 committed Mach-O executables and conforms to
`../schema/objc-eh-manifest.schema.json`.

The `producer` block holds the repository revision plus one Apple clang record
per target cell. Each artifact records the Objective-C runtime, target, ARC and
exception settings, exact compiler flags, runner identity, and the exact
three-part compiler release reported by the selected Xcode.

Its evidence is re-derived from Mach-O headers and bytes: architecture,
sections, normalized symbols and imports, class-name strings, compact unwind,
the architecture-specific DWARF frame expectation, hashes, sizes, and build
path absence. The `neverd` block is then compared exactly with
`objc_matrix.neverd_contract`; an exception-free control can claim only
`cfi-only`, while exception-enabled artifacts require an Apple Objective-C
exception graph and its class-clause categories.
