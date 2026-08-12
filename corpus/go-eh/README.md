# Generated Go runtime-metadata corpus

This tree is synchronized by the `Build and publish Go EH corpus` workflow
after every successful producer change on `main`.

Do not add, rename, or replace Go images without the matching generated entry
in `manifests/go-eh.json`. Every artifact name must identify its toolchain
release, GOOS/GOARCH, buildmode, cgo setting, link mode, and optimization mode.

Most of these files carry no extension, because that is what a Go executable
for `linux` and `darwin` is called. They are binaries regardless of their name;
see `docs/go-eh-integration-notes.md` for the `.gitattributes` rule that keeps
Git from treating them as text.
