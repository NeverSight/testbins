# Generated Rust exception corpus

This tree is synchronized by the `Build and publish Rust EH corpus` workflow
after every successful producer change on `main`. Nothing here is built on a
developer's machine, and nothing here is committed by hand.

Do not add, rename, or replace a binary without the matching generated entry in
`manifests/rust-eh.json`. Every artifact name repeats its target triple, panic
strategy, and optimization level, and the directory it sits in repeats them
again, so an artifact that has been moved cannot be mistaken for one that
belongs where it now is.

Linux and macOS executables have no file extension, which is what those
platforms actually produce. `.gitattributes` therefore marks this whole tree as
binary by path rather than by extension.

Artifacts arrive through the workflow's upload and download steps, which do not
preserve the executable bit. That is harmless: NeverD parses these images as
data through its public loader and never runs them. The producer runs the
executable probe on the runner that built it, before it is uploaded.
