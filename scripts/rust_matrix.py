#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Define the supported Rust exception-corpus build matrix.

Rust has no unwind table format of its own, so the axis that matters most is
the target: the same source compiles to an Itanium LSDA on Linux, to a Mach-O
`__unwind_info` plus `__eh_frame` on Darwin, and to MSVC C++ EH tables keyed on
the unmangled `rust_panic` type descriptor on Windows. The panic strategy is
the second axis, and `-C panic=abort` is a negative control rather than a
variation: the crate's own frames must carry no landing pad at all.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


_TARGETS: dict[str, dict[str, object]] = {
    "x86_64-unknown-linux-gnu": {
        "architecture": "x86_64",
        "object_format": "elf",
        "runner_os": "linux",
        "runs_on": "ubuntu-24.04",
        # Hosted Linux runners are x64, so this is the one ELF cell whose
        # executable can be run before publication.
        "native": True,
        "linker": "rustc-default",
        "apt_packages": (),
    },
    "aarch64-unknown-linux-gnu": {
        "architecture": "aarch64",
        "object_format": "elf",
        "runner_os": "linux",
        "runs_on": "ubuntu-24.04",
        "native": False,
        "linker": "aarch64-linux-gnu-gcc",
        # `libc6-dev-arm64-cross` carries `Scrt1.o` and `crti.o`, which the
        # link needs and which the compiler package only *recommends*.  The
        # installer runs with `--no-install-recommends` for reproducibility, so
        # naming it here is what keeps the cross link from failing on a missing
        # C runtime.
        "apt_packages": ("gcc-aarch64-linux-gnu", "libc6-dev-arm64-cross"),
    },
    "x86_64-pc-windows-msvc": {
        "architecture": "x86_64",
        "object_format": "pe",
        "runner_os": "windows",
        "runs_on": "windows-2022",
        "native": True,
        "linker": "rustc-default",
        "apt_packages": (),
    },
    "x86_64-apple-darwin": {
        "architecture": "x86_64",
        "object_format": "macho",
        "runner_os": "macos",
        # The hosted macOS image is Apple silicon and has no Rosetta, so the
        # Intel slice is cross-built and never executed.
        "runs_on": "macos-15",
        "native": False,
        "linker": "rustc-default",
        "apt_packages": (),
    },
    "aarch64-apple-darwin": {
        "architecture": "aarch64",
        "object_format": "macho",
        "runner_os": "macos",
        "runs_on": "macos-15",
        "native": True,
        "linker": "rustc-default",
        "apt_packages": (),
    },
}

_PANIC_STRATEGIES = ("unwind", "abort")
_OPTIMIZATIONS = ("o0", "o2")

# What each hosted runner image actually is, so a manifest cannot claim it was
# built somewhere the matrix does not run.
_RUNNERS: dict[str, dict[str, str]] = {
    "linux": {"arch": "x64", "host": "x86_64-unknown-linux-gnu"},
    "windows": {"arch": "x64", "host": "x86_64-pc-windows-msvc"},
    "macos": {"arch": "arm64", "host": "aarch64-apple-darwin"},
}

_CRATES: dict[str, dict[str, str]] = {
    "rust_eh_probe": {
        "crate_type": "bin",
        "source": "sources/rust-eh/rust_eh_probe.rs",
    },
    "rust_eh_cdylib": {
        "crate_type": "cdylib",
        "source": "sources/rust-eh/rust_eh_cdylib.rs",
    },
}

_ARTIFACT_EXTENSIONS: dict[tuple[str, str], str] = {
    ("bin", "elf"): "",
    ("bin", "macho"): "",
    ("bin", "pe"): ".exe",
    ("cdylib", "elf"): ".so",
    ("cdylib", "macho"): ".dylib",
    ("cdylib", "pe"): ".dll",
}

_EDITION = "2024"

# Symbols each crate exports for the manifest's evidence assertions. The
# producer tests compare these against the sources, so a probe cannot be added
# or renamed without the contract following it.
_PROBE_SYMBOLS: dict[str, tuple[str, ...]] = {
    "rust_eh_probe": (
        "rust_eh_c_abort_boundary",
        "rust_eh_c_leaf_nounwind",
        "rust_eh_c_unwind_boundary",
        "rust_eh_catch_unwind_boundary",
        "rust_eh_drop_across_panic",
        "rust_eh_explicit_panic",
        "rust_eh_index_panic",
        "rust_eh_nested_drop_order",
        "rust_eh_overflow_panic",
        "rust_eh_slice_range_panic",
        "rust_eh_unwrap_none_panic",
    ),
    "rust_eh_cdylib": (
        "rust_eh_dylib_c_abort_boundary",
        "rust_eh_dylib_c_leaf_nounwind",
        "rust_eh_dylib_c_unwind_boundary",
        "rust_eh_dylib_catch_unwind_boundary",
        "rust_eh_dylib_drop_log",
        "rust_eh_dylib_index_panic",
        "rust_eh_dylib_nested_drop_order",
    ),
}

# Sections the corpus asserts by object format. `.gcc_except_table` and
# `__gcc_except_tab` are bound to the unwinding builds only: an aborting build
# still links standard-library objects that were compiled to unwind, so their
# presence there is an accident of the prebuilt `std` rather than a property
# this producer controls.
_UNWIND_SECTIONS: dict[str, tuple[str, ...]] = {
    "elf": (".text", ".eh_frame", ".gcc_except_table"),
    "macho": ("__text", "__eh_frame", "__gcc_except_tab", "__unwind_info"),
    "pe": (".text", ".pdata", ".rdata"),
}

_ABORT_SECTIONS: dict[str, tuple[str, ...]] = {
    "elf": (".text", ".eh_frame"),
    "macho": ("__text", "__eh_frame", "__unwind_info"),
    "pe": (".text", ".pdata", ".rdata"),
}

# On every Itanium target the personality is `rust_eh_personality`; on MSVC the
# personality is `__CxxFrameHandler3` and Rust is told apart from C++ only by
# the unmangled `rust_panic` type descriptor a catch names.
_PERSONALITIES: dict[str, tuple[str, ...]] = {
    "elf": ("rust_eh_personality",),
    "macho": ("rust_eh_personality",),
    "pe": ("__CxxFrameHandler3",),
}


def target_names() -> tuple[str, ...]:
    """Return every supported target triple, in declaration order."""

    return tuple(_TARGETS)


def target_property(target: str, key: str) -> object:
    """Return one declared property of \\p target."""

    try:
        return _TARGETS[target][key]
    except KeyError as error:
        raise ValueError(f"unsupported rust-eh target or property: {error}") from error


def crate_names() -> tuple[str, ...]:
    """Return every crate the producer builds, in manifest order."""

    return tuple(_CRATES)


def crate_type(crate_name: str) -> str:
    try:
        return _CRATES[crate_name]["crate_type"]
    except KeyError as error:
        raise ValueError(f"unsupported rust-eh crate: {crate_name}") from error


def crate_source(crate_name: str) -> str:
    try:
        return _CRATES[crate_name]["source"]
    except KeyError as error:
        raise ValueError(f"unsupported rust-eh crate: {crate_name}") from error


def probe_symbols(crate_name: str) -> tuple[str, ...]:
    try:
        return _PROBE_SYMBOLS[crate_name]
    except KeyError as error:
        raise ValueError(f"unsupported rust-eh crate: {crate_name}") from error


def artifact_extension(crate_name: str, object_format: str) -> str:
    key = (crate_type(crate_name), object_format)
    if key not in _ARTIFACT_EXTENSIONS:
        raise ValueError(f"unsupported crate type and object format: {key}")
    return _ARTIFACT_EXTENSIONS[key]


def required_sections(object_format: str, panic_strategy: str) -> tuple[str, ...]:
    table = _UNWIND_SECTIONS if panic_strategy == "unwind" else _ABORT_SECTIONS
    if object_format not in table:
        raise ValueError(f"unsupported object format: {object_format}")
    return table[object_format]


def personalities(object_format: str) -> tuple[str, ...]:
    if object_format not in _PERSONALITIES:
        raise ValueError(f"unsupported object format: {object_format}")
    return _PERSONALITIES[object_format]


def edition() -> str:
    return _EDITION


@dataclass(frozen=True, order=True)
class MatrixCell:
    target: str
    panic_strategy: str
    optimization: str

    @property
    def architecture(self) -> str:
        return str(_TARGETS[self.target]["architecture"])

    @property
    def object_format(self) -> str:
        return str(_TARGETS[self.target]["object_format"])

    @property
    def runner_os(self) -> str:
        return str(_TARGETS[self.target]["runner_os"])

    @property
    def runs_on(self) -> str:
        return str(_TARGETS[self.target]["runs_on"])

    @property
    def native(self) -> bool:
        return bool(_TARGETS[self.target]["native"])

    @property
    def linker(self) -> str:
        return str(_TARGETS[self.target]["linker"])

    @property
    def apt_packages(self) -> tuple[str, ...]:
        return tuple(_TARGETS[self.target]["apt_packages"])  # type: ignore[arg-type]

    @property
    def runner_arch(self) -> str:
        return _RUNNERS[self.runner_os]["arch"]

    @property
    def rustc_host(self) -> str:
        return _RUNNERS[self.runner_os]["host"]

    @property
    def artifact_names(self) -> tuple[str, ...]:
        """Every crate is buildable for every target, so this never narrows."""

        return crate_names()

    @property
    def key(self) -> str:
        return "-".join((self.target, self.panic_strategy, self.optimization))

    def execution(self, crate_name: str) -> str:
        """Return the honest execution status for one artifact of this cell."""

        if crate_type(crate_name) != "bin":
            return "not-run-library"
        return "passed" if self.native else "not-run-cross-target"

    def relative_directory(self, crate_name: str) -> str:
        return "/".join(
            (
                "corpus",
                "rust-eh",
                self.target,
                self.panic_strategy,
                self.optimization,
                crate_type(crate_name),
            )
        )

    def artifact_filename(self, crate_name: str) -> str:
        stem = "-".join(
            (crate_name, self.target, self.panic_strategy, self.optimization)
        )
        return stem + artifact_extension(crate_name, self.object_format)

    def artifact_path(self, crate_name: str) -> str:
        return "/".join(
            (self.relative_directory(crate_name), self.artifact_filename(crate_name))
        )

    def to_actions_entry(self) -> dict[str, str | bool]:
        return {
            "target": self.target,
            "panic_strategy": self.panic_strategy,
            "optimization": self.optimization,
            "architecture": self.architecture,
            "object_format": self.object_format,
            "runner_os": self.runner_os,
            "runner_arch": self.runner_arch,
            "runs_on": self.runs_on,
            "native": self.native,
            "linker": self.linker,
            "apt_packages": " ".join(self.apt_packages),
            "cell_name": self.key,
        }


def validate_cell(target: str, panic_strategy: str, optimization: str) -> MatrixCell:
    """Validate and canonicalize one producer cell."""

    normalized_target = target.strip()
    if normalized_target not in _TARGETS:
        raise ValueError(f"unsupported rust-eh target: {target}")
    normalized_panic = panic_strategy.strip().lower()
    if normalized_panic not in _PANIC_STRATEGIES:
        raise ValueError(f"unsupported panic strategy: {panic_strategy}")
    normalized_optimization = optimization.strip().lower()
    if normalized_optimization not in _OPTIMIZATIONS:
        raise ValueError(f"unsupported optimization mode: {optimization}")
    return MatrixCell(normalized_target, normalized_panic, normalized_optimization)


def expected_cells() -> tuple[MatrixCell, ...]:
    """Return the complete, deterministic producer matrix."""

    return tuple(
        validate_cell(target, panic_strategy, optimization)
        for target in _TARGETS
        for panic_strategy in _PANIC_STRATEGIES
        for optimization in _OPTIMIZATIONS
    )


def artifact_cell_key(artifact: dict[str, object]) -> str:
    """Derive the canonical matrix key from one manifest artifact."""

    cell = validate_cell(
        str(artifact.get("target_triple", "")),
        str(artifact.get("panic_strategy", "")),
        str(artifact.get("optimization", "")),
    )
    return cell.key


def rustc_flags(cell: MatrixCell, crate_name: str, remapped_prefix: str) -> list[str]:
    """Return the exact rustc command-line flags for one artifact.

    The builder and the verifier both call this, so a flag can never be passed
    without the manifest recording it or recorded without being passed.
    """

    opt_level = "0" if cell.optimization == "o0" else "2"
    flags = [
        "--edition",
        _EDITION,
        "--crate-name",
        crate_name,
        "--crate-type",
        crate_type(crate_name),
        "--target",
        cell.target,
        "-C",
        f"opt-level={opt_level}",
        "-C",
        f"panic={cell.panic_strategy}",
        # Without this the arithmetic panic only exists at `-C opt-level=0`,
        # because rustc ties overflow checks to debug assertions and those
        # default off once optimizing.
        "-C",
        "overflow-checks=on",
        # Keeps the images small and keeps the checkout path out of the debug
        # line tables; `--remap-path-prefix` covers what is left.
        "-C",
        "debuginfo=0",
        # The manifest asserts symbol evidence, so the symbol table has to
        # survive whatever the host toolchain would have stripped by default.
        "-C",
        "strip=none",
        "--remap-path-prefix",
        f"{remapped_prefix}=/testbins",
    ]
    if cell.linker != "rustc-default":
        flags += ["-C", f"linker={cell.linker}"]
    return flags


#
# The contract one artifact carries. The builder writes exactly what these
# return and the verifier recomputes them and compares, so the manifest cannot
# drift from the matrix; the object readers then prove the same claims against
# the file itself.
#


def symbol_names_expected(object_format: str, crate_name: str) -> bool:
    """True when the verifier can recover names from the artifact.

    A linked PE keeps its names only in a PDB the corpus does not ship, so an
    executable offers nothing to check. A `cdylib` is different: its export
    table names every `#[unsafe(no_mangle)] pub extern` function.
    """

    if object_format != "pe":
        return True
    return crate_type(crate_name) == "cdylib"


def required_symbols(cell: MatrixCell, crate_name: str) -> tuple[str, ...]:
    if not symbol_names_expected(cell.object_format, crate_name):
        return ()
    names = set(probe_symbols(crate_name))
    if cell.object_format == "pe":
        # Only the exports are visible, and only the C-ABI probes are exported.
        return tuple(sorted(names))
    names.add("rust_eh_personality")
    if cell.panic_strategy == "unwind":
        names.add("_Unwind_RaiseException")
    return tuple(sorted(names))


def forbidden_symbols(cell: MatrixCell, crate_name: str) -> tuple[str, ...]:
    """Absence claims, restricted to what a build actually decides.

    An aborting image still links a standard library that was compiled to
    unwind, so it keeps `_Unwind_Resume`, `rust_eh_personality`, and an except
    table. What disappears is the ability to start a panic:
    `_Unwind_RaiseException` is referenced only by the `panic_unwind` runtime,
    which an aborting build does not link. Export tables list only what a
    library chose to export, so absence there proves nothing and PE claims
    nothing.
    """

    if cell.object_format == "pe" or cell.panic_strategy != "abort":
        return ()
    return ("_Unwind_RaiseException",)


def required_strings(cell: MatrixCell, crate_name: str) -> tuple[str, ...]:
    if cell.object_format == "pe" and cell.panic_strategy == "unwind":
        return ("rust_panic",)
    return ()


def landing_pad_free_symbols(cell: MatrixCell, crate_name: str) -> tuple[str, ...]:
    """Frames that must carry no landing pad.

    Under `-C panic=abort` that is every frame this producer compiled. Under
    `-C panic=unwind` it is the one `extern "C"` probe whose body provably
    cannot panic, which is what makes the guard on its neighbours meaningful.
    """

    if cell.panic_strategy == "abort":
        return probe_symbols(crate_name)
    leaf = "rust_eh_dylib_c_leaf_nounwind"
    if crate_type(crate_name) == "bin":
        leaf = "rust_eh_c_leaf_nounwind"
    return (leaf,)


def evidence_contract(cell: MatrixCell, crate_name: str) -> dict[str, object]:
    return {
        "required_sections": list(
            required_sections(cell.object_format, cell.panic_strategy)
        ),
        "required_symbols": list(required_symbols(cell, crate_name)),
        "forbidden_symbols": list(forbidden_symbols(cell, crate_name)),
        "required_strings": list(required_strings(cell, crate_name)),
        "require_unwind_tables": True,
        "symbol_names_expected": symbol_names_expected(cell.object_format, crate_name),
    }


def neverd_contract(cell: MatrixCell, crate_name: str) -> dict[str, object]:
    """The weakest result NeverD must produce for one artifact.

    The MSVC numbers are lower on purpose rather than by omission. On an
    Itanium target every Rust frame with an LSDA is recognizable from its
    `rust_eh_personality`. On `*-pc-windows-msvc` a Rust frame is spelled with
    the same `__CxxFrameHandler3` tables as C++, and the only thing that tells
    the two apart is a catch naming the unmangled `rust_panic` descriptor -- so
    a frame that merely runs `Drop` glue is indistinguishable from a C++ frame
    and is not claimed here.
    """

    if cell.panic_strategy == "abort":
        return {
            "validation_level": "unwind-only",
            "allowed_parse_status": ["complete", "partial"],
            "personalities_any": list(personalities(cell.object_format)),
            "expect_no_landing_pads": True,
            "landing_pad_free_symbols": list(
                landing_pad_free_symbols(cell, crate_name)
            ),
            "min_landing_pads": 0,
            "min_drop_glue_pads": 0,
            "min_catch_unwind_pads": 0,
            "min_nounwind_guard_pads": 0,
            "min_panic_sites": 0,
        }

    is_bin = crate_type(crate_name) == "bin"
    if cell.object_format == "pe":
        minimums = {
            "min_landing_pads": 1,
            "min_drop_glue_pads": 0,
            "min_catch_unwind_pads": 1,
            "min_nounwind_guard_pads": 0,
            "min_panic_sites": 0,
        }
    else:
        minimums = {
            "min_landing_pads": 4 if is_bin else 3,
            "min_drop_glue_pads": 2,
            "min_catch_unwind_pads": 1,
            "min_nounwind_guard_pads": 1,
            "min_panic_sites": 3 if is_bin else 2,
        }
    contract: dict[str, object] = {
        "validation_level": "panic-graph",
        "allowed_parse_status": ["complete"],
        "personalities_any": list(personalities(cell.object_format)),
        "expect_no_landing_pads": False,
        "landing_pad_free_symbols": list(landing_pad_free_symbols(cell, crate_name)),
    }
    contract.update(minimums)
    return contract


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
