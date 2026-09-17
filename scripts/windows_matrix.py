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
# Hosted-image MSVC product years the producer can actually drive.  VS 2022
# keeps the historical cell key/path so existing artifacts stay valid.
_MSVC_VS_YEARS = (2022, 2026)
_MSVC_VS_YEAR_RUNNERS = {
    2022: {
        "runner": "windows-2022",
        "vswhere_version": "[17.0,18.0)",
    },
    2026: {
        "runner": "windows-2025",
        "vswhere_version": "[18.0,19.0)",
    },
}
# Requested 2010–2026 coverage.  Years the hosted runner cannot install are
# explicit skips, not silent cells.
_MSVC_VS_YEAR_SKIPS = {
    2010: "VS 2010 Build Tools cannot be installed on current GitHub-hosted Windows images",
    2012: "VS 2012 Build Tools cannot be installed on current GitHub-hosted Windows images",
    2013: "VS 2013 Build Tools cannot be installed on current GitHub-hosted Windows images",
    2015: "VS 2015 Build Tools cannot be installed on current GitHub-hosted Windows images",
    2017: "VS 2017 Build Tools cannot be installed on current GitHub-hosted Windows images",
    2019: "VS 2019 Build Tools are not preinstalled on windows-2022/windows-2025 and are not part of the hosted-image contract",
    2025: "There is no Visual Studio 2025 product; MSVC 14.4x ships as Visual Studio 2022",
}
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
    if toolchain == "clang-cl" and architecture == "arm":
        return ()
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
    vs_year: int = 2022

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

        if self.toolchain == "clang-cl" and self.architecture in ("x86", "x86_64"):
            return tuple(
                name
                for name in _FULL_ARTIFACT_INVENTORY
                if name not in {"xcpt4", "xframe_eh_dll", "xframe_eh_exe"}
            )
        return _FULL_ARTIFACT_INVENTORY

    @property
    def key(self) -> str:
        toolchain = self.toolchain
        if self.toolchain == "msvc" and self.vs_year != 2022:
            toolchain = f"msvc-vs{self.vs_year}"
        return "-".join(
            (
                toolchain,
                self.architecture,
                self.cxx_format,
                self.cookie_label,
                self.optimization,
            )
        )

    @property
    def runner(self) -> str:
        if self.toolchain != "msvc":
            return "windows-2022"
        return str(_MSVC_VS_YEAR_RUNNERS[self.vs_year]["runner"])

    @property
    def vswhere_version(self) -> str:
        if self.toolchain != "msvc":
            return ""
        return str(_MSVC_VS_YEAR_RUNNERS[self.vs_year]["vswhere_version"])

    def to_actions_entry(self) -> dict[str, str | bool | int]:
        entry: dict[str, str | bool | int] = {
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
            "runner": self.runner,
            "vs_year": self.vs_year,
        }
        if self.vswhere_version:
            entry["vswhere_version"] = self.vswhere_version
        return entry


def skipped_vs_years() -> dict[int, str]:
    """Return Visual Studio years that are requested but not installable."""

    return dict(_MSVC_VS_YEAR_SKIPS)


def validate_cell(
    toolchain: str,
    architecture: str,
    cxx_format: str,
    optimization: str,
    security_cookie: str,
    vs_year: int = 2022,
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
    if not isinstance(vs_year, int):
        raise ValueError(f"unsupported Visual Studio year: {vs_year}")
    if normalized_toolchain == "msvc":
        if vs_year in _MSVC_VS_YEAR_SKIPS:
            raise ValueError(
                f"Visual Studio {vs_year} is an explicit skip: "
                f"{_MSVC_VS_YEAR_SKIPS[vs_year]}"
            )
        if vs_year not in _MSVC_VS_YEARS:
            raise ValueError(f"unsupported Visual Studio year: {vs_year}")
    elif vs_year != 2022:
        raise ValueError(
            f"Visual Studio year {vs_year} is only valid for the msvc toolchain"
        )
    return MatrixCell(
        normalized_toolchain,
        normalized_architecture,
        normalized_format,
        normalized_cookie,
        normalized_optimization,
        vs_year,
    )


def expected_cells() -> tuple[MatrixCell, ...]:
    """Return the complete, deterministic producer capability matrix."""

    cells: list[MatrixCell] = []
    for toolchain in _TOOLCHAINS:
        vs_years = _MSVC_VS_YEARS if toolchain == "msvc" else (2022,)
        for vs_year in vs_years:
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
                                    vs_year,
                                )
                            )
    return tuple(cells)


def artifact_cell_key(build: dict[str, object], architecture: str) -> str:
    """Derive the canonical matrix key from one manifest artifact."""

    security_cookie = build.get("security_cookie")
    if not isinstance(security_cookie, bool):
        raise ValueError("security_cookie must be boolean")
    vs_year = 2022
    raw_year = build.get("visual_studio_year")
    if raw_year is not None:
        if not isinstance(raw_year, int):
            raise ValueError("visual_studio_year must be an integer")
        vs_year = raw_year
    cell = validate_cell(
        str(build.get("toolchain", "")),
        architecture,
        str(build.get("cxx_format", "")),
        str(build.get("optimization", "")),
        "on" if security_cookie else "off",
        vs_year,
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
