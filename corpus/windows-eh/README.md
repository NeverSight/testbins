# Generated Windows exception corpus

This tree is synchronized by the `Build and publish Windows EH corpus`
workflow after every successful producer change on `main`.

Do not add, rename, or replace PE files without the matching generated entry in
`manifests/windows-eh.json`. Every artifact name must identify its toolchain,
architecture, C++ EH format, security-cookie mode, and optimization mode.

MSVC cells are built for every Visual Studio year the GitHub-hosted runner can
install (VS 2022 on `windows-2022`, VS 2026 on `windows-2025`). VS 2010–2019
and a non-existent VS 2025 product are explicit producer skips, not silent
cells. VS 2022 keeps the historical path; later years use
`corpus/windows-eh/msvc/vs<year>/...`.
