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
