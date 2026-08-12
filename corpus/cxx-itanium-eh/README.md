# Generated C++ Itanium exception corpus

This tree is synchronized by the `Build and publish C++ Itanium EH corpus`
workflow after every successful producer change on `main`. Nothing here is
built on a developer's machine, and nothing here is committed by hand.

Do not add, rename, or replace a binary without the matching generated entry in
`manifests/cxx-itanium-eh.json`. Every artifact name repeats its toolchain,
target, optimization level, and symbol state, and the directory it sits in
repeats them again, so an artifact that has been moved cannot be mistaken for
one that belongs where it now is.

The Linux and macOS executables have no file extension, which is what those
platforms actually produce. `.gitattributes` therefore marks the generated
artifact directories as binary by path rather than by suffix.

A `c_eh_probe` executable loads the `libcxx_eh_shared` object beside it, through
a runtime search path relative to the executable itself
(`$ORIGIN/../shared` on ELF, `@loader_path/../shared` on Mach-O). Moving one of
the two without the other breaks that link, which is another reason the layout
is generated rather than arranged by hand.

Artifacts arrive through the workflow's upload and download steps, which do not
preserve the executable bit. That is harmless: NeverD parses these images as
data through its public loader and never runs them. The producer runs every
executable it can on the runner that built it, before it is uploaded.
