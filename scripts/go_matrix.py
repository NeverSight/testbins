#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Define the supported Go runtime-metadata corpus build matrix.

A Go image carries none of the platform exception tables for its own code.
Everything an unwinder needs is in the `pclntab`, so the axes that matter here
are the ones that change that table's shape or hide it: the toolchain release
that wrote the header, the container the linker folded it into, whether the
symbol table that names it survived, and whether the compiler was allowed to
open-code defers.

One matrix cell is one pinned Go toolchain, because installing a toolchain is
by far the most expensive thing a build job does and every artifact a release
can produce is cross-compiled from the same ubuntu host.  Each cell expands to
a fixed list of variants, and each variant is exactly one committed artifact.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

ARTIFACT_NAME = "eh_probe"
CORPUS_ROOT = "corpus/go-eh"
MODULE_PACKAGE = "./cmd/eh_probe"


@dataclass(frozen=True)
class GoRelease:
    """A pinned toolchain and the `pcHeader` it writes."""

    version: str
    pclntab_version: str
    pclntab_magic: int
    #: Lowest funcdata index that holds `FUNCDATA_OpenCodedDeferInfo`.  Go 1.16
    #: dropped `FUNCDATA_RegPointerMaps` and shifted the array down by one.
    open_coded_defer_funcdata_index: int
    #: Go 1.16 introduced `PCDATA_UnsafePoint`; index 0 was `PCDATA_RegMapIndex`
    #: before that, so an older image has no async-preemption table at all.
    has_unsafe_point_table: bool
    #: `go:func.*` gained its colon in Go 1.20 (#37762).
    gofunc_symbol: str
    #: How `FUNCDATA_OpenCodedDeferInfo` spells the frame's closure slots.
    #: Open-coded defers arrived in Go 1.14 and the record has been rewritten
    #: twice since.  CL 326061 made deferred functions argumentless for Go
    #: 1.18, dropping the leading maximum argument frame and each defer's own
    #: argument size and argument list; CL 516199 then sorted the slots into
    #: one ascending run for Go 1.22, after which the record names only where
    #: the run begins.  The pclntab magic says nothing about either change --
    #: it last moved in Go 1.20, so one magic spans the 1.22 rewrite and the
    #: 1.18 one happened inside the span of another -- so a reader has to
    #: decide this from the bytes, and the releases either side of each change
    #: are here to prove it does.
    open_coded_defer_layout: str
    #: True while a position-independent ELF still carried the table in the
    #: relro segment, which named it `.data.rel.ro.gopclntab`.  CL 718065 moved
    #: it to plain read-only data for Go 1.26 on the grounds that it holds no
    #: relocations, so from that release a PIE names it like every other link.
    relro_pclntab: bool
    #: darwin/arm64 only exists from Go 1.16.
    supports_darwin_arm64: bool

    @property
    def label(self) -> str:
        return f"go{self.version}"


_RELEASES: tuple[GoRelease, ...] = (
    GoRelease(
        version="1.15.15",
        pclntab_version="go1.2",
        pclntab_magic=0xFFFFFFFB,
        open_coded_defer_funcdata_index=5,
        has_unsafe_point_table=False,
        gofunc_symbol="go.func.*",
        open_coded_defer_layout="legacy-enumerated",
        relro_pclntab=True,
        supports_darwin_arm64=False,
    ),
    GoRelease(
        version="1.16.15",
        pclntab_version="go1.16",
        pclntab_magic=0xFFFFFFFA,
        open_coded_defer_funcdata_index=4,
        has_unsafe_point_table=True,
        gofunc_symbol="go.func.*",
        open_coded_defer_layout="legacy-enumerated",
        relro_pclntab=True,
        supports_darwin_arm64=True,
    ),
    GoRelease(
        version="1.18.10",
        pclntab_version="go1.18",
        pclntab_magic=0xFFFFFFF0,
        open_coded_defer_funcdata_index=4,
        has_unsafe_point_table=True,
        gofunc_symbol="go.func.*",
        open_coded_defer_layout="enumerated",
        relro_pclntab=True,
        supports_darwin_arm64=True,
    ),
    GoRelease(
        version="1.20.14",
        pclntab_version="go1.20",
        pclntab_magic=0xFFFFFFF1,
        open_coded_defer_funcdata_index=4,
        has_unsafe_point_table=True,
        gofunc_symbol="go:func.*",
        open_coded_defer_layout="enumerated",
        relro_pclntab=True,
        supports_darwin_arm64=True,
    ),
    # The last release before CL 516199 and the first one after it.  1.16 and
    # 1.18 already straddle the other open-coded defer rewrite and are told
    # apart by their magic; this pair is not, sharing one with each other and
    # with 1.20 and 1.26, so it is the pair that proves the record layout is
    # read from the bytes and not guessed from the header.
    GoRelease(
        version="1.21.13",
        pclntab_version="go1.20",
        pclntab_magic=0xFFFFFFF1,
        open_coded_defer_funcdata_index=4,
        has_unsafe_point_table=True,
        gofunc_symbol="go:func.*",
        open_coded_defer_layout="enumerated",
        relro_pclntab=True,
        supports_darwin_arm64=True,
    ),
    GoRelease(
        version="1.22.12",
        pclntab_version="go1.20",
        pclntab_magic=0xFFFFFFF1,
        open_coded_defer_funcdata_index=4,
        has_unsafe_point_table=True,
        gofunc_symbol="go:func.*",
        open_coded_defer_layout="contiguous",
        relro_pclntab=True,
        supports_darwin_arm64=True,
    ),
    GoRelease(
        version="1.26.5",
        pclntab_version="go1.20",
        pclntab_magic=0xFFFFFFF1,
        open_coded_defer_funcdata_index=4,
        has_unsafe_point_table=True,
        gofunc_symbol="go:func.*",
        open_coded_defer_layout="contiguous",
        relro_pclntab=False,
        supports_darwin_arm64=True,
    ),
)

_RELEASES_BY_VERSION = {release.version: release for release in _RELEASES}


@dataclass(frozen=True)
class Target:
    """One GOOS/GOARCH pair and the container facts that follow from it."""

    goos: str
    goarch: str
    object_format: str
    #: `sys.PCQuantum`, the unit every pc delta in the table is divided by.
    min_lc: int
    pointer_size: int
    #: True when an ubuntu x64 runner can execute the artifact it produces.
    native: bool
    extension: str
    shared_extension: str

    @property
    def label(self) -> str:
        return f"{self.goos}-{self.goarch}"


_TARGETS: tuple[Target, ...] = (
    Target("linux", "amd64", "elf", 1, 8, True, "", ".so"),
    Target("linux", "arm64", "elf", 4, 8, False, "", ".so"),
    Target("windows", "amd64", "pe", 1, 8, False, ".exe", ".dll"),
    Target("darwin", "amd64", "macho", 1, 8, False, "", ".dylib"),
    Target("darwin", "arm64", "macho", 4, 8, False, "", ".dylib"),
)

_TARGETS_BY_LABEL = {target.label: target for target in _TARGETS}

_BUILDMODES = ("exe", "pie", "c-shared")
_OPTIMIZATIONS = ("default", "none")

#: Container discovery sweep.  Every release covers at least ELF/amd64; the
#: releases whose magic nothing else produces cover more containers, and the
#: current release covers all five targets.  Stripped, because a stripped image
#: is both the smaller artifact and the harder one to decode.
_BASE_TARGETS: dict[str, tuple[str, ...]] = {
    "1.15.15": ("linux-amd64", "linux-arm64", "windows-amd64", "darwin-amd64"),
    "1.16.15": ("linux-amd64", "darwin-arm64"),
    "1.18.10": ("linux-amd64", "windows-amd64"),
    "1.20.14": ("linux-amd64",),
    "1.21.13": ("linux-amd64",),
    "1.22.12": ("linux-amd64",),
    "1.26.5": (
        "linux-amd64",
        "linux-arm64",
        "windows-amd64",
        "darwin-amd64",
        "darwin-arm64",
    ),
}

#: Variants that exist to pin one specific decoder path rather than a
#: container.  Each entry is (go_version, target, buildmode, cgo, stripped,
#: optimization, purpose).
_FOCUS_VARIANTS: tuple[tuple[str, str, str, bool, bool, str, str], ...] = (
    (
        "1.15.15",
        "linux-amd64",
        "exe",
        False,
        False,
        "default",
        "go1.2 pcHeader with a symbol table, funcdata addressed by relocated "
        "pointer, and no PCDATA_UnsafePoint table to find",
    ),
    (
        "1.26.5",
        "linux-amd64",
        "exe",
        False,
        False,
        "default",
        "unstripped ELF, so moduledata can name the funcdata base through the "
        "go:func.* symbol instead of through the textsectmap search",
    ),
    (
        "1.26.5",
        "windows-amd64",
        "exe",
        False,
        False,
        "default",
        "PE with a COFF symbol table: the pclntab still has no section of its "
        "own and must be found by scanning .rdata",
    ),
    (
        "1.26.5",
        "darwin-arm64",
        "exe",
        False,
        False,
        "default",
        "unstripped Mach-O, where the pclntab lives in __DATA_CONST and the "
        "pc deltas are in four-byte units",
    ),
    (
        "1.26.5",
        "linux-amd64",
        "exe",
        False,
        True,
        "none",
        "-gcflags=all=-N -l, which clears ssagen.hasOpenDefers for every "
        "function so all defers lower to deferproc/deferprocStack",
    ),
    (
        "1.26.5",
        "linux-amd64",
        "pie",
        False,
        True,
        "default",
        "position-independent ELF, which from Go 1.26 names the table "
        ".gopclntab like an ordinary executable rather than moving it into "
        "the relro segment",
    ),
    (
        "1.26.5",
        "linux-arm64",
        "pie",
        False,
        True,
        "default",
        "position-independent ELF with a four-byte pc quantum",
    ),
    (
        "1.26.5",
        "linux-amd64",
        "exe",
        True,
        False,
        "default",
        "cgo executable: an externally linked image that carries real DWARF "
        ".eh_frame beside Go's own tables",
    ),
    (
        "1.26.5",
        "linux-amd64",
        "c-shared",
        True,
        True,
        "default",
        "shared object with no exe entry point, which moves moduledata and "
        "forces external linking",
    ),
)


class MatrixError(ValueError):
    """Raised when a cell or variant is outside the supported matrix."""


@dataclass(frozen=True, order=True)
class Variant:
    """One committed artifact, named by every axis that produced it."""

    go_version: str
    goos: str
    goarch: str
    buildmode: str
    cgo_enabled: bool
    stripped: bool
    optimization: str

    @property
    def release(self) -> GoRelease:
        return _RELEASES_BY_VERSION[self.go_version]

    @property
    def target(self) -> Target:
        return _TARGETS_BY_LABEL[f"{self.goos}-{self.goarch}"]

    @property
    def cgo_label(self) -> str:
        return "cgo1" if self.cgo_enabled else "cgo0"

    @property
    def link_label(self) -> str:
        return "stripped" if self.stripped else "symtab"

    @property
    def optimization_label(self) -> str:
        return "opt" if self.optimization == "default" else "noopt"

    @property
    def key(self) -> str:
        return "-".join(
            (
                self.release.label,
                self.target.label,
                self.buildmode,
                self.cgo_label,
                self.link_label,
                self.optimization_label,
            )
        )

    @property
    def extension(self) -> str:
        if self.buildmode == "c-shared":
            return self.target.shared_extension
        return self.target.extension

    @property
    def filename(self) -> str:
        return f"{ARTIFACT_NAME}-{self.key}{self.extension}"

    @property
    def directory(self) -> str:
        return "/".join(
            (
                CORPUS_ROOT,
                self.release.label,
                self.target.label,
                self.buildmode,
                self.cgo_label,
                self.link_label,
                self.optimization_label,
            )
        )

    @property
    def path(self) -> str:
        return f"{self.directory}/{self.filename}"

    @property
    def elf_pclntab_section(self) -> str:
        """The ELF section this cell's linker puts the function table in.

        Only ELF has a name to give: the Mach-O link uses `__gopclntab` and the
        PE link folds the table into `.rdata` with no section of its own, so
        both are decided by the container rather than by the release.
        """

        if self.buildmode == "exe" or not self.release.relro_pclntab:
            return ".gopclntab"
        return ".data.rel.ro.gopclntab"

    @property
    def executable_here(self) -> bool:
        """True when the ubuntu x64 build host can run the artifact."""

        return self.target.native and self.buildmode in ("exe", "pie")

    @property
    def execution(self) -> str:
        if self.executable_here:
            return "passed"
        if self.buildmode == "c-shared":
            return "not-run-shared-object"
        return "not-run-cross-target"

    def build_env(self) -> dict[str, str]:
        """The complete environment the `go build` runs under.

        Everything the toolchain might otherwise pick up from the runner is
        pinned so a rebuild on a different image produces the same bytes.
        `GOTOOLCHAIN` and `GOWORK` predate none of the toolchains here but are
        simply ignored by the ones that do not know them.
        """

        return {
            "CGO_ENABLED": "1" if self.cgo_enabled else "0",
            "GO111MODULE": "on",
            "GOARCH": self.goarch,
            "GOFLAGS": "",
            "GOOS": self.goos,
            "GOPROXY": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        }

    def build_flags(self) -> list[str]:
        """`go build` arguments, excluding `-o` and the package pattern.

        `-trimpath` is unconditional: without it the CI checkout directory
        appears in the file table the corpus publishes.
        """

        flags = ["-trimpath", f"-buildmode={self.buildmode}"]
        if self.optimization == "none":
            flags.append("-gcflags=all=-N -l")
        if self.stripped:
            flags.append("-ldflags=-s -w")
        return flags

    def to_json(self) -> dict[str, object]:
        release = self.release
        target = self.target
        return {
            "buildmode": self.buildmode,
            "cgo_enabled": self.cgo_enabled,
            "expected_pclntab_magic": release.pclntab_magic,
            "expected_pclntab_version": release.pclntab_version,
            "go_version": self.go_version,
            "goarch": self.goarch,
            "goos": self.goos,
            "key": self.key,
            "min_lc": target.min_lc,
            "object_format": target.object_format,
            "optimization": self.optimization,
            "path": self.path,
            "pointer_size": target.pointer_size,
            "stripped": self.stripped,
        }


@dataclass(frozen=True, order=True)
class MatrixCell:
    """One pinned toolchain, which is one build job."""

    go_version: str

    @property
    def release(self) -> GoRelease:
        return _RELEASES_BY_VERSION[self.go_version]

    @property
    def key(self) -> str:
        return self.release.label

    @property
    def variants(self) -> tuple[Variant, ...]:
        return variants_for_version(self.go_version)

    def to_actions_entry(self) -> dict[str, object]:
        release = self.release
        return {
            "artifact_count": len(self.variants),
            "cell_name": self.key,
            "go_version": release.version,
            "pclntab_magic": f"0x{release.pclntab_magic:08x}",
            "pclntab_version": release.pclntab_version,
        }


def release_for(version: str) -> GoRelease:
    """Return the pinned release record for \\p version."""

    normalized = version.strip().lower().removeprefix("go")
    release = _RELEASES_BY_VERSION.get(normalized)
    if release is None:
        raise MatrixError(f"unsupported Go toolchain version: {version}")
    return release


def target_for(goos: str, goarch: str) -> Target:
    """Return the target record for a GOOS/GOARCH pair."""

    label = f"{goos.strip().lower()}-{goarch.strip().lower()}"
    target = _TARGETS_BY_LABEL.get(label)
    if target is None:
        raise MatrixError(f"unsupported Go target: {goos}/{goarch}")
    return target


def pinned_go_versions() -> tuple[str, ...]:
    return tuple(release.version for release in _RELEASES)


def validate_variant(
    go_version: str,
    goos: str,
    goarch: str,
    buildmode: str,
    cgo_enabled: bool,
    stripped: bool,
    optimization: str,
) -> Variant:
    """Validate and canonicalize one artifact description.

    The rules here are capabilities, not preferences: `c-shared` genuinely
    cannot be linked without cgo, cgo cannot cross-compile without a C
    toolchain the runner does not carry, and darwin/arm64 did not exist before
    Go 1.16.
    """

    release = release_for(go_version)
    target = target_for(goos, goarch)
    normalized_buildmode = buildmode.strip().lower()
    if normalized_buildmode not in _BUILDMODES:
        raise MatrixError(f"unsupported Go buildmode: {buildmode}")
    normalized_optimization = optimization.strip().lower()
    if normalized_optimization not in _OPTIMIZATIONS:
        raise MatrixError(f"unsupported optimization mode: {optimization}")
    if not isinstance(cgo_enabled, bool) or not isinstance(stripped, bool):
        raise MatrixError("cgo_enabled and stripped must be boolean")

    if target.label == "darwin-arm64" and not release.supports_darwin_arm64:
        raise MatrixError(
            f"Go {release.version} has no darwin/arm64 port, so it cannot "
            "produce that artifact"
        )
    if normalized_buildmode == "c-shared" and not cgo_enabled:
        raise MatrixError(
            "-buildmode=c-shared requires external linking, which requires "
            "CGO_ENABLED=1"
        )
    if cgo_enabled and not target.native:
        raise MatrixError(
            f"cgo builds for {target.label} would need a cross C toolchain "
            "the build host does not provide"
        )
    if normalized_buildmode == "pie" and target.goos != "linux":
        raise MatrixError(
            f"the corpus does not carry a {target.label} PIE cell: darwin is "
            "already position independent by default and the Windows PIE "
            "image reaches its pclntab exactly as the exe image does"
        )
    return Variant(
        release.version,
        target.goos,
        target.goarch,
        normalized_buildmode,
        cgo_enabled,
        stripped,
        normalized_optimization,
    )


def expected_variants() -> tuple[Variant, ...]:
    """Return the complete, deterministic artifact plan."""

    variants: list[Variant] = []
    seen: set[str] = set()

    def add(variant: Variant) -> None:
        if variant.key in seen:
            raise MatrixError(f"duplicate matrix variant: {variant.key}")
        seen.add(variant.key)
        variants.append(variant)

    for release in _RELEASES:
        for target_label in _BASE_TARGETS[release.version]:
            target = _TARGETS_BY_LABEL[target_label]
            add(
                validate_variant(
                    release.version,
                    target.goos,
                    target.goarch,
                    "exe",
                    False,
                    True,
                    "default",
                )
            )
    for (
        version,
        target_label,
        buildmode,
        cgo_enabled,
        stripped,
        optimization,
        _purpose,
    ) in _FOCUS_VARIANTS:
        target = _TARGETS_BY_LABEL[target_label]
        add(
            validate_variant(
                version,
                target.goos,
                target.goarch,
                buildmode,
                cgo_enabled,
                stripped,
                optimization,
            )
        )
    return tuple(sorted(variants, key=lambda variant: variant.path))


def variants_for_version(version: str) -> tuple[Variant, ...]:
    """Return the artifacts one build job is responsible for."""

    release = release_for(version)
    return tuple(
        variant
        for variant in expected_variants()
        if variant.go_version == release.version
    )


def variant_purposes() -> dict[str, str]:
    """Map each focus variant's key to why the corpus carries it."""

    purposes: dict[str, str] = {}
    for (
        version,
        target_label,
        buildmode,
        cgo_enabled,
        stripped,
        optimization,
        purpose,
    ) in _FOCUS_VARIANTS:
        target = _TARGETS_BY_LABEL[target_label]
        variant = validate_variant(
            version,
            target.goos,
            target.goarch,
            buildmode,
            cgo_enabled,
            stripped,
            optimization,
        )
        purposes[variant.key] = purpose
    return purposes


def expected_cells() -> tuple[MatrixCell, ...]:
    return tuple(MatrixCell(release.version) for release in _RELEASES)


def variant_for_path(path: str) -> Variant:
    """Recover the variant a manifest path claims to be.

    Used by the verifier so that a path and the axes recorded beside it cannot
    disagree without one of them being wrong.
    """

    for variant in expected_variants():
        if variant.path == path:
            return variant
    raise MatrixError(f"path is not part of the Go corpus matrix: {path}")


def actions_matrix() -> dict[str, list[dict[str, object]]]:
    return {"include": [cell.to_actions_entry() for cell in expected_cells()]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--github-output",
        type=Path,
        help="append matrix=<compact JSON> to a GitHub Actions output file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the compact Actions matrix to stdout",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print the full artifact plan as indented JSON",
    )
    args = parser.parse_args()
    if not args.github_output and not args.json and not args.plan:
        parser.error("one of --github-output, --json, or --plan is required")

    payload = json.dumps(actions_matrix(), separators=(",", ":"), sort_keys=True)
    if args.github_output:
        args.github_output.parent.mkdir(parents=True, exist_ok=True)
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"matrix={payload}\n")
    if args.json:
        print(payload)
    if args.plan:
        purposes = variant_purposes()
        plan = []
        for variant in expected_variants():
            entry = variant.to_json()
            entry["execution"] = variant.execution
            entry["build_flags"] = variant.build_flags()
            if variant.key in purposes:
                entry["purpose"] = purposes[variant.key]
            plan.append(entry)
        print(
            json.dumps(
                {
                    "cells": [cell.key for cell in expected_cells()],
                    "artifact_count": len(plan),
                    "artifacts": plan,
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
