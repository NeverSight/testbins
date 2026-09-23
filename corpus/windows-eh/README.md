# Generated Windows exception corpus

This tree is synchronized by the `Build and publish Windows EH corpus`
workflow after every successful producer change on `main`.

Do not add, rename, or replace PE files without the matching generated entry in
`manifests/windows-eh.json`. Every artifact name must identify its toolchain,
architecture, C++ EH format, security-cookie mode, and optimization mode.

MSVC cells use the VS 2019 v142 toolset hosted by VS 2022 on
`windows-2022`, VS 2022 on `windows-2022`, and VS 2026 on
`windows-2025`. VS 2010, 2012, 2013, 2015, and 2017 are explicit
producer skips; VS 2025 has no product. VS 2022 keeps the historical
path; VS 2019 and VS 2026 use
`corpus/windows-eh/msvc/vs<year>/...`.
