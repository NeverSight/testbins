# Generated Ada/D exception corpus

This tree is synchronized by the `Build and publish Ada/D EH corpus` workflow
after every successful producer change on `main`. Nothing here is built on a
developer's machine, and nothing here is committed by hand.

Do not add, rename, or replace a binary without the matching generated entry in
`manifests/ada-d-eh.json`. Every artifact name repeats its language, toolchain,
target, and optimization level, and the directory it sits in repeats them
again, so an artifact that has been moved cannot be mistaken for one that
belongs where it now is.

The ELF executables have no file extension, which is what Linux actually
produces. `.gitattributes` therefore marks the generated artifact directories
as binary by path rather than by suffix.

Artifacts arrive through the workflow's upload and download steps, which do not
preserve the executable bit. That is harmless: NeverD parses these images as
data through its public loader and never runs them. The producer runs every
native executable on the runner that built it, before it is uploaded.
