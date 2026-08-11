# Generated Windows exception corpus

This tree is synchronized by the `Build and publish Windows EH corpus`
workflow after every successful producer change on `main`.

Do not add, rename, or replace PE files without the matching generated entry in
`manifests/windows-eh.json`. Every artifact name must identify its toolchain,
architecture, C++ EH format, security-cookie mode, and optimization mode.
