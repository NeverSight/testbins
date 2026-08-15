#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Define the real Ada/D Itanium-EH corpus build matrix.

The matrix separates three claims that must not be conflated:

* the binary has a parseable Itanium LSDA graph;
* its native reconstruction preserves the language personality and uses
  address-valued clauses for non-C++ type descriptors;
* an artifact from the actual language toolchain proves those claims.

GNAT type entries point at ``Exception_Id`` descriptors.  D entries point at
``ClassInfo`` descriptors.  Neither is a C++ ``std::type_info`` object, even
though all cells use the Itanium call-site/action/type-table container.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


CORPUS_NAME = "ada-d-eh"
CORPUS_ROOT = f"corpus/{CORPUS_NAME}"
SOURCE_ROOT = f"sources/{CORPUS_NAME}"
PROBE_PASS_MARKER = "ada-d-eh probe passed"
BUILD_ENVIRONMENT = {
    "LC_ALL": "C",
    "SOURCE_DATE_EPOCH": "1704067200",
    "TZ": "UTC",
}


class MatrixError(ValueError):
    """Raised when a cell or variant is outside the supported matrix."""


@dataclass(frozen=True)
class Variant:
    optimization: str

    @property
    def key(self) -> str:
        return self.optimization


VARIANTS = (Variant("o0"), Variant("o2"))


@dataclass(frozen=True)
class MatrixCell:
    toolchain: str
    target: str
    language: str
    architecture: str
    compiler: str
    version_prefix: str
    apt_packages: tuple[str, ...]
    dlang_compiler: str
    source: str
    personality: str
    descriptor_abi: str
    min_cleanup_pads: int
    native: bool

    @property
    def key(self) -> str:
        return f"{self.toolchain}-{self.target}"

    @property
    def runner_os(self) -> str:
        return "linux"

    @property
    def runner_arch(self) -> str:
        return "x64"

    @property
    def runs_on(self) -> str:
        return "ubuntu-24.04"

    @property
    def object_format(self) -> str:
        return "elf"

    @property
    def variants(self) -> tuple[Variant, ...]:
        return VARIANTS

    @property
    def source_path(self) -> str:
        return f"{SOURCE_ROOT}/{self.source}"

    def artifact_filename(self, variant: Variant) -> str:
        return (
            f"{self.language}_eh_probe-{self.toolchain}-{self.target}-"
            f"{variant.optimization}"
        )

    def artifact_path(self, variant: Variant) -> str:
        return (
            f"{CORPUS_ROOT}/{self.language}/{self.toolchain}/{self.target}/"
            f"{variant.optimization}/{self.artifact_filename(variant)}"
        )

    def execution(self) -> str:
        return "passed" if self.native else "not-run-cross-target"

    def to_actions_entry(self) -> dict[str, str]:
        return {
            "cell_name": self.key,
            "toolchain": self.toolchain,
            "target": self.target,
            "runs_on": self.runs_on,
            "apt_packages": " ".join(self.apt_packages),
            "dlang_compiler": self.dlang_compiler,
        }


_AARCH64_GNAT = (
    "gnat-13-aarch64-linux-gnu",
    "libc6-dev-arm64-cross",
    "libgnat-13-arm64-cross",
)
_AARCH64_GDC = (
    "gdc-13-aarch64-linux-gnu",
    "libc6-dev-arm64-cross",
    "libgphobos-13-dev-arm64-cross",
)

_CELLS: tuple[MatrixCell, ...] = (
    MatrixCell(
        toolchain="gnat",
        target="x86_64-linux-gnu",
        language="ada",
        architecture="x86_64",
        compiler="gnatmake-13",
        version_prefix="13.",
        apt_packages=("gnat-13",),
        dlang_compiler="",
        source="ada_eh_probe.adb",
        personality="__gnat_personality_v0",
        descriptor_abi="gnat-exception-id",
        min_cleanup_pads=0,
        native=True,
    ),
    MatrixCell(
        toolchain="gnat",
        target="aarch64-linux-gnu",
        language="ada",
        architecture="aarch64",
        compiler="aarch64-linux-gnu-gnatmake-13",
        version_prefix="13.",
        apt_packages=_AARCH64_GNAT,
        dlang_compiler="",
        source="ada_eh_probe.adb",
        personality="__gnat_personality_v0",
        descriptor_abi="gnat-exception-id",
        min_cleanup_pads=0,
        native=False,
    ),
    MatrixCell(
        toolchain="gdc",
        target="x86_64-linux-gnu",
        language="d",
        architecture="x86_64",
        compiler="gdc-13",
        version_prefix="13.",
        apt_packages=("gdc-13",),
        dlang_compiler="",
        source="d_eh_probe.d",
        personality="__gdc_personality_v0",
        descriptor_abi="d-classinfo",
        min_cleanup_pads=1,
        native=True,
    ),
    MatrixCell(
        toolchain="gdc",
        target="aarch64-linux-gnu",
        language="d",
        architecture="aarch64",
        compiler="aarch64-linux-gnu-gdc-13",
        version_prefix="13.",
        apt_packages=_AARCH64_GDC,
        dlang_compiler="",
        source="d_eh_probe.d",
        personality="__gdc_personality_v0",
        descriptor_abi="d-classinfo",
        min_cleanup_pads=1,
        native=False,
    ),
    MatrixCell(
        toolchain="dmd",
        target="x86_64-linux-gnu",
        language="d",
        architecture="x86_64",
        compiler="dmd",
        version_prefix="2.112.1",
        apt_packages=(),
        dlang_compiler="dmd-2.112.1",
        source="d_eh_probe.d",
        personality="__dmd_personality_v0",
        descriptor_abi="d-classinfo",
        min_cleanup_pads=1,
        native=True,
    ),
    MatrixCell(
        toolchain="ldc",
        target="x86_64-linux-gnu",
        language="d",
        architecture="x86_64",
        compiler="ldc2",
        version_prefix="1.42.0",
        apt_packages=(),
        dlang_compiler="ldc-1.42.0",
        source="d_eh_probe.d",
        personality="_d_eh_personality",
        descriptor_abi="d-classinfo",
        min_cleanup_pads=1,
        native=True,
    ),
)


def expected_cells() -> tuple[MatrixCell, ...]:
    return tuple(sorted(_CELLS, key=lambda cell: cell.key))


def validate_cell(toolchain: str, target: str) -> MatrixCell:
    for cell in _CELLS:
        if cell.toolchain == toolchain and cell.target == target:
            return cell
    raise MatrixError(f"unsupported Ada/D EH cell: {toolchain}/{target}")


def validate_variant(optimization: str) -> Variant:
    for variant in VARIANTS:
        if variant.optimization == optimization:
            return variant
    raise MatrixError(f"unsupported Ada/D EH optimization: {optimization}")


def compiler_flags(
    cell: MatrixCell, variant: Variant, checkout_prefix: str
) -> tuple[str, ...]:
    mapped = f"-ffile-prefix-map={checkout_prefix}=/testbins"
    if cell.toolchain == "gnat":
        # -cargs is a one-way door: gnatmake hands every later argv token to
        # gcc, including the source file and -o if they follow it.
        return (
            "-q",
            "-gnat2022",
            f"-O{variant.optimization[-1]}",
            "-cargs",
            "-fexceptions",
            "-g0",
            mapped,
        )
    if cell.toolchain == "gdc":
        return (
            "-fexceptions",
            "-g0",
            mapped,
            f"-O{variant.optimization[-1]}",
        )
    if cell.toolchain == "dmd":
        common = ("-m64", "-fPIE")
        if variant.optimization == "o0":
            return common
        return (*common, "-O", "-release", "-inline")
    if cell.toolchain == "ldc":
        return ("-m64", f"-O{variant.optimization[-1]}", "-relocation-model=pic")
    raise MatrixError(f"unsupported compiler family: {cell.toolchain}")


def build_contract(
    cell: MatrixCell, variant: Variant, checkout_prefix: str
) -> dict[str, object]:
    return {
        "compiler": cell.compiler,
        "compiler_flags": list(compiler_flags(cell, variant, checkout_prefix)),
        "source": cell.source_path,
        "working_directory": "/testbins",
        "checkout_prefix": checkout_prefix,
        "environment": dict(BUILD_ENVIRONMENT),
        "path_strategy": (
            "compiler-prefix-map"
            if cell.toolchain in {"gnat", "gdc"}
            else "relative-source-no-debug"
        ),
    }


def toolchain_contract(cell: MatrixCell) -> dict[str, object]:
    return {
        "cell": cell.key,
        "toolchain": cell.toolchain,
        "target": cell.target,
        "compiler": cell.compiler,
        "version_prefix": cell.version_prefix,
        "apt_packages": list(cell.apt_packages),
        "dlang_compiler": cell.dlang_compiler,
    }


def evidence_contract(cell: MatrixCell) -> dict[str, object]:
    return {
        "required_sections": [".eh_frame", ".gcc_except_table"],
        "required_symbols": [cell.personality],
        "required_strings": [
            "ada-d-eh probe passed",
            "constraint",
            "decode",
            "secondary",
        ],
        "require_unwind_tables": True,
        "eh_frame_present": True,
        "checkout_path_absent": True,
    }


def neverd_contract(cell: MatrixCell) -> dict[str, object]:
    return {
        "validation_level": "lsda-graph",
        "personalities_any": [cell.personality],
        "type_table_interpretation": "opaque-descriptor",
        "descriptor_abi": cell.descriptor_abi,
        "native_reconstruction": "address-clauses",
        "corpus_proven": True,
        "min_call_sites": 1,
        "min_landing_pads": 1,
        "min_catch_clauses": 3,
        "min_cleanup_pads": cell.min_cleanup_pads,
        "min_type_table_entries": 3,
    }


def expected_artifact_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            cell.artifact_path(variant)
            for cell in expected_cells()
            for variant in cell.variants
        )
    )


def actions_matrix() -> dict[str, list[dict[str, str]]]:
    return {"include": [cell.to_actions_entry() for cell in expected_cells()]}


def artifact_plan() -> dict[str, object]:
    artifacts = []
    for cell in expected_cells():
        for variant in cell.variants:
            artifacts.append(
                {
                    "cell": cell.key,
                    "path": cell.artifact_path(variant),
                    "language": cell.language,
                    "architecture": cell.architecture,
                    "optimization": variant.optimization,
                    "compiler": cell.compiler,
                    "compiler_flags": list(compiler_flags(cell, variant, "/checkout")),
                    "evidence": evidence_contract(cell),
                    "neverd": neverd_contract(cell),
                }
            )
    artifacts.sort(key=lambda entry: str(entry["path"]))
    return {
        "cells": [cell.key for cell in expected_cells()],
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--paths", action="store_true")
    args = parser.parse_args()
    if not (args.github_output or args.json or args.plan or args.paths):
        parser.error("one output mode is required")

    payload = json.dumps(actions_matrix(), separators=(",", ":"), sort_keys=True)
    if args.github_output:
        args.github_output.parent.mkdir(parents=True, exist_ok=True)
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"matrix={payload}\n")
    if args.json:
        print(payload)
    if args.plan:
        print(json.dumps(artifact_plan(), indent=2, sort_keys=True))
    if args.paths:
        print("\n".join(expected_artifact_paths()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
