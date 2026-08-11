#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Define the supported Windows exception-corpus build matrix."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


_ARCHITECTURES = {
    "x86": {
        "target_triple": "i686-pc-windows-msvc",
        "vs_arch": "x86",
        "linker_machine": "X86",
        "execute": True,
    },
    "x86_64": {
        "target_triple": "x86_64-pc-windows-msvc",
        "vs_arch": "x64",
        "linker_machine": "X64",
        "execute": True,
    },
    "arm": {
        "target_triple": "thumbv7-pc-windows-msvc",
        "vs_arch": "arm",
        "linker_machine": "ARM",
        "execute": False,
    },
    "aarch64": {
        "target_triple": "aarch64-pc-windows-msvc",
        "vs_arch": "arm64",
        "linker_machine": "ARM64",
        "execute": False,
    },
}

_ARCHITECTURE_ALIASES = {
    "i386": "x86",
    "win32": "x86",
    "x64": "x86_64",
    "arm32": "arm",
    "arm64": "aarch64",
}

_TOOLCHAINS = ("msvc", "clang-cl")
_OPTIMIZATIONS = ("o0", "o2")
_SECURITY_COOKIE_MODES = ("off", "on")
_FULL_ARTIFACT_INVENTORY = (
    "xcpt4",
    "nested_collided",
    "xframe_eh_dll",
    "xframe_eh_exe",
    "seh_probe",
    "cxx_eh_probe",
)


def normalize_architecture(value: str) -> str:
    """Return the canonical manifest architecture for a user-facing alias."""

    normalized = value.strip().lower()
    normalized = _ARCHITECTURE_ALIASES.get(normalized, normalized)
    if normalized not in _ARCHITECTURES:
        raise ValueError(f"unsupported Windows target architecture: {value}")
    return normalized


def _supported_formats(toolchain: str, architecture: str) -> tuple[str, ...]:
    if architecture != "x86_64":
        return ("native",)
    if toolchain == "msvc":
        return ("fh3", "fh4")
    return ("fh3",)


@dataclass(frozen=True, order=True)
class MatrixCell:
    toolchain: str
    architecture: str
    cxx_format: str
    security_cookie: str
    optimization: str

    @property
    def target_triple(self) -> str:
        return str(_ARCHITECTURES[self.architecture]["target_triple"])

    @property
    def vs_arch(self) -> str:
        return str(_ARCHITECTURES[self.architecture]["vs_arch"])

    @property
    def linker_machine(self) -> str:
        return str(_ARCHITECTURES[self.architecture]["linker_machine"])

    @property
    def execute(self) -> bool:
        return bool(_ARCHITECTURES[self.architecture]["execute"])

    @property
    def cookie_label(self) -> str:
        return "gs" if self.security_cookie == "on" else "no-gs"

    @property
    def artifact_names(self) -> tuple[str, ...]:
        """Return artifacts the selected compiler can produce for this target."""

        if self.toolchain == "clang-cl" and self.architecture == "arm":
            return ("cxx_eh_probe",)
        return _FULL_ARTIFACT_INVENTORY

    @property
    def key(self) -> str:
        return "-".join(
            (
                self.toolchain,
                self.architecture,
                self.cxx_format,
                self.cookie_label,
                self.optimization,
            )
        )

    def to_actions_entry(self) -> dict[str, str | bool]:
        return {
            "toolchain": self.toolchain,
            "architecture": self.architecture,
            "cxx_format": self.cxx_format,
            "security_cookie": self.security_cookie,
            "optimization": self.optimization,
            "target_triple": self.target_triple,
            "vs_arch": self.vs_arch,
            "linker_machine": self.linker_machine,
            "execute": self.execute,
            "cell_name": self.key,
        }


def validate_cell(
    toolchain: str,
    architecture: str,
    cxx_format: str,
    optimization: str,
    security_cookie: str,
) -> MatrixCell:
    """Validate and canonicalize one producer cell."""

    normalized_toolchain = toolchain.strip().lower()
    if normalized_toolchain not in _TOOLCHAINS:
        raise ValueError(f"unsupported Windows toolchain: {toolchain}")
    normalized_architecture = normalize_architecture(architecture)
    normalized_format = cxx_format.strip().lower()
    supported_formats = _supported_formats(
        normalized_toolchain, normalized_architecture
    )
    if normalized_format not in supported_formats:
        raise ValueError(
            f"unsupported C++ EH format {cxx_format!r} for "
            f"{normalized_toolchain}/{normalized_architecture}"
        )
    normalized_optimization = optimization.strip().lower()
    if normalized_optimization not in _OPTIMIZATIONS:
        raise ValueError(f"unsupported optimization mode: {optimization}")
    normalized_cookie = security_cookie.strip().lower()
    if normalized_cookie not in _SECURITY_COOKIE_MODES:
        raise ValueError(f"unsupported security-cookie mode: {security_cookie}")
    return MatrixCell(
        normalized_toolchain,
        normalized_architecture,
        normalized_format,
        normalized_cookie,
        normalized_optimization,
    )


def expected_cells() -> tuple[MatrixCell, ...]:
    """Return the complete, deterministic producer capability matrix."""

    cells: list[MatrixCell] = []
    for toolchain in _TOOLCHAINS:
        for architecture in _ARCHITECTURES:
            for cxx_format in _supported_formats(toolchain, architecture):
                for security_cookie in _SECURITY_COOKIE_MODES:
                    for optimization in _OPTIMIZATIONS:
                        cells.append(
                            validate_cell(
                                toolchain,
                                architecture,
                                cxx_format,
                                optimization,
                                security_cookie,
                            )
                        )
    return tuple(cells)


def artifact_cell_key(build: dict[str, object], architecture: str) -> str:
    """Derive the canonical matrix key from one manifest artifact."""

    security_cookie = build.get("security_cookie")
    if not isinstance(security_cookie, bool):
        raise ValueError("security_cookie must be boolean")
    cell = validate_cell(
        str(build.get("toolchain", "")),
        architecture,
        str(build.get("cxx_format", "")),
        str(build.get("optimization", "")),
        "on" if security_cookie else "off",
    )
    return cell.key


def actions_matrix() -> dict[str, list[dict[str, str | bool]]]:
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
    args = parser.parse_args()
    if not args.github_output and not args.json:
        parser.error("one of --github-output or --json is required")

    payload = json.dumps(actions_matrix(), separators=(",", ":"), sort_keys=True)
    if args.github_output:
        args.github_output.parent.mkdir(parents=True, exist_ok=True)
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"matrix={payload}\n")
    if args.json:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
