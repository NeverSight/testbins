#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Define the supported C++ Itanium exception-corpus build matrix.

The Itanium C++ ABI is one exception model with three containers and two
producers, and the corpus exists because those combinations do not agree with
each other:

* on x86-64 and AArch64 ELF the tables are `.eh_frame` plus `.gcc_except_table`,
  and the personality is `__gxx_personality_v0`;
* on 32-bit ARM the same source produces ARM EHABI instead -- an `.ARM.exidx`
  index and an `.ARM.extab` entry that carries the language specific data area
  inline, with no `.gcc_except_table` section anywhere;
* on Mach-O the tables are `__unwind_info` compact records plus
  `__gcc_except_tab`, and `__eh_frame` appears only for the frames the compact
  encoding cannot describe;
* on mingw-w64 the language semantics are still Itanium but the unwinder is
  Windows SEH, so `.pdata`/`.xdata` carry the frames and the personality is
  spelled `__gxx_personality_seh0`.

One matrix cell is one (toolchain, target) pair, because installing a cross
toolchain is by far the most expensive thing a build job does and every variant
of a given target shares it.  Each cell expands to a fixed list of eight
variants, and each variant is exactly one committed artifact.

The corpus deliberately carries no `-fsjlj-exceptions` axis.  The setjmp/longjmp
model is a configure-time property of the toolchain rather than a flag a
distribution compiler reliably honours, so a cell for it would be red more often
than it was informative.  It is the obvious next axis if a producer that
guarantees it is ever pinned here.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

CORPUS_NAME = "cxx-itanium-eh"
CORPUS_ROOT = f"corpus/{CORPUS_NAME}"
SOURCE_ROOT = f"sources/{CORPUS_NAME}"

#: What the executables print when their own runtime checks pass.
PROBE_PASS_MARKER = "cxx-itanium-eh probe passed"

#: The Xcode the macOS cells select before building.  Apple's clang has its own
#: version line, so this and `_TOOLSETS[...].version_prefix` are the pin: change
#: one without the other and the verifier rejects the manifest.
MACOS_XCODE_PATH = "/Applications/Xcode_16.4.app"


class MatrixError(ValueError):
    """Raised when a cell or variant is outside the supported matrix."""


# ===----------------------------------------------------------------------===#
# Targets
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True)
class Target:
    """One target and the container facts that follow from it."""

    architecture: str
    object_format: str
    #: The triple the drivers spell, which is not always the corpus's name for
    #: the target: Debian calls the hard-float ARM port `arm-linux-gnueabihf`
    #: while the corpus records the ISA it is actually built for.
    gnu_triple: str
    runner_os: str
    runs_on: str
    #: True when the runner that builds this target can also execute it.
    native: bool
    exe_extension: str
    shared_extension: str


_TARGETS: dict[str, Target] = {
    "x86_64-linux-gnu": Target(
        architecture="x86_64",
        object_format="elf",
        gnu_triple="x86_64-linux-gnu",
        runner_os="linux",
        runs_on="ubuntu-24.04",
        native=True,
        exe_extension="",
        shared_extension=".so",
    ),
    "aarch64-linux-gnu": Target(
        architecture="aarch64",
        object_format="elf",
        gnu_triple="aarch64-linux-gnu",
        runner_os="linux",
        runs_on="ubuntu-24.04",
        native=False,
        exe_extension="",
        shared_extension=".so",
    ),
    # The one target whose unwind metadata is not DWARF.  It is the reason this
    # product line exists in the shape it does.
    "armv7-linux-gnueabihf": Target(
        architecture="arm",
        object_format="elf",
        gnu_triple="arm-linux-gnueabihf",
        runner_os="linux",
        runs_on="ubuntu-24.04",
        native=False,
        exe_extension="",
        shared_extension=".so",
    ),
    "x86_64-w64-mingw32": Target(
        architecture="x86_64",
        object_format="pe",
        gnu_triple="x86_64-w64-mingw32",
        runner_os="linux",
        runs_on="ubuntu-24.04",
        native=False,
        exe_extension=".exe",
        shared_extension=".dll",
    ),
    "x86_64-apple-darwin": Target(
        architecture="x86_64",
        object_format="macho",
        gnu_triple="x86_64-apple-darwin",
        runner_os="macos",
        # The hosted macOS image is Apple silicon and has no Rosetta, so the
        # Intel slice is cross-built and never executed.
        runs_on="macos-15",
        native=False,
        exe_extension="",
        shared_extension=".dylib",
    ),
    "arm64-apple-darwin": Target(
        architecture="aarch64",
        object_format="macho",
        gnu_triple="arm64-apple-darwin",
        runner_os="macos",
        runs_on="macos-15",
        native=True,
        exe_extension="",
        shared_extension=".dylib",
    ),
}

# What each hosted runner image actually is, so a manifest cannot claim it was
# built somewhere the matrix does not run.
_RUNNER_ARCHITECTURES = {"linux": "x64", "macos": "arm64"}


# ===----------------------------------------------------------------------===#
# Toolsets
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True)
class Toolset:
    """The exact programs one cell invokes, and the version it must report."""

    cxx_driver: str
    c_driver: str
    #: Symbols are removed after the link rather than by a linker flag, because
    #: `ld64` has no equivalent of GNU `ld -s` and the corpus wants one story.
    strip_tool: str
    #: The version the cell is pinned to.  Ubuntu's versioned packages make this
    #: a real pin on Linux; on macOS it is `MACOS_XCODE_PATH` that pins it.
    version_prefix: str
    apt_packages: tuple[str, ...]
    #: Flags that select the target.  Everything else is a property of the
    #: variant rather than the cell.
    target_flags: tuple[str, ...]


# The cross libc and the cross libstdc++ are named even where a compiler package
# would pull them in, because the installer runs with `--no-install-recommends`
# and a link that cannot find `Scrt1.o` fails long after the install looked fine.
_AARCH64_CROSS = (
    "g++-aarch64-linux-gnu",
    "libc6-dev-arm64-cross",
    "libstdc++-13-dev-arm64-cross",
)
_ARMHF_CROSS = (
    "g++-arm-linux-gnueabihf",
    "libc6-dev-armhf-cross",
    "libstdc++-13-dev-armhf-cross",
)
# Clang has no runtime of its own here: it compiles against the cross GCC's
# sysroot, links with the cross binutils, and uses the cross libstdc++.
_CLANG_PACKAGE = ("clang-18",)

# 32-bit ARM has no single default ISA, and the two producers do not pick the
# same one.  Naming it makes both cells build the same instruction set.
_ARMV7_ISA = ("-march=armv7-a", "-mfpu=vfpv3-d16", "-mfloat-abi=hard")

_TOOLSETS: dict[tuple[str, str], Toolset] = {
    ("gcc", "x86_64-linux-gnu"): Toolset(
        cxx_driver="g++",
        c_driver="gcc",
        strip_tool="strip",
        version_prefix="13.",
        apt_packages=(),
        target_flags=(),
    ),
    ("gcc", "aarch64-linux-gnu"): Toolset(
        cxx_driver="aarch64-linux-gnu-g++",
        c_driver="aarch64-linux-gnu-gcc",
        strip_tool="aarch64-linux-gnu-strip",
        version_prefix="13.",
        apt_packages=_AARCH64_CROSS,
        target_flags=(),
    ),
    ("gcc", "armv7-linux-gnueabihf"): Toolset(
        cxx_driver="arm-linux-gnueabihf-g++",
        c_driver="arm-linux-gnueabihf-gcc",
        strip_tool="arm-linux-gnueabihf-strip",
        version_prefix="13.",
        apt_packages=_ARMHF_CROSS,
        target_flags=_ARMV7_ISA,
    ),
    # `x86_64-w64-mingw32-g++` itself is an update-alternatives link that the
    # posix and win32 packages fight over, so the cell names the concrete
    # posix-threads driver and never depends on which one won.
    #
    # That driver is a whole second GCC rather than a mode of the first, and
    # Debian spells the distinction in the version itself: it reports
    # `13-posix`, with no minor or patch to report.  Pinning the string it
    # actually says pins the thread model too, which for an exception corpus is
    # the more important half -- posix and win32 reach the unwinder through
    # different libstdc++ builds.
    ("gcc", "x86_64-w64-mingw32"): Toolset(
        cxx_driver="x86_64-w64-mingw32-g++-posix",
        c_driver="x86_64-w64-mingw32-gcc-posix",
        strip_tool="x86_64-w64-mingw32-strip",
        version_prefix="13-posix",
        apt_packages=("g++-mingw-w64-x86-64",),
        target_flags=(),
    ),
    ("clang", "x86_64-linux-gnu"): Toolset(
        cxx_driver="clang++-18",
        c_driver="clang-18",
        strip_tool="strip",
        version_prefix="18.",
        apt_packages=_CLANG_PACKAGE,
        target_flags=("--target=x86_64-linux-gnu",),
    ),
    ("clang", "aarch64-linux-gnu"): Toolset(
        cxx_driver="clang++-18",
        c_driver="clang-18",
        strip_tool="aarch64-linux-gnu-strip",
        version_prefix="18.",
        apt_packages=_CLANG_PACKAGE + _AARCH64_CROSS,
        target_flags=("--target=aarch64-linux-gnu",),
    ),
    ("clang", "armv7-linux-gnueabihf"): Toolset(
        cxx_driver="clang++-18",
        c_driver="clang-18",
        strip_tool="arm-linux-gnueabihf-strip",
        version_prefix="18.",
        apt_packages=_CLANG_PACKAGE + _ARMHF_CROSS,
        # Debian's cross GCC is installed under `arm-linux-gnueabihf`, and that
        # is the directory clang has to find, so the driver triple is spelled
        # the way the sysroot is even though the corpus records the ISA.
        target_flags=("--target=arm-linux-gnueabihf",) + _ARMV7_ISA,
    ),
    ("clang", "x86_64-apple-darwin"): Toolset(
        cxx_driver="clang++",
        c_driver="clang",
        strip_tool="strip",
        version_prefix="17.",
        apt_packages=(),
        target_flags=("-arch", "x86_64"),
    ),
    ("clang", "arm64-apple-darwin"): Toolset(
        cxx_driver="clang++",
        c_driver="clang",
        strip_tool="strip",
        version_prefix="17.",
        apt_packages=(),
        target_flags=("-arch", "arm64"),
    ),
}

#: Declaration order is the matrix order, so an Actions matrix is stable.
_CELL_ORDER: tuple[tuple[str, str], ...] = tuple(_TOOLSETS)

_TOOLCHAINS = ("gcc", "clang")
_OPTIMIZATIONS = ("o0", "o2")


# ===----------------------------------------------------------------------===#
# Programs and variants
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True)
class Program:
    artifact_kind: str
    source_language: str
    exceptions: str
    source: str


_PROGRAMS: dict[str, Program] = {
    "cxx_eh_probe": Program(
        artifact_kind="exe",
        source_language="cxx",
        exceptions="on",
        source=f"{SOURCE_ROOT}/cxx_eh_probe.cpp",
    ),
    # The negative control is the same source compiled without exceptions, so
    # the two differ in the flag and in nothing else.
    "cxx_eh_probe_noexc": Program(
        artifact_kind="exe",
        source_language="cxx",
        exceptions="off",
        source=f"{SOURCE_ROOT}/cxx_eh_probe.cpp",
    ),
    "libcxx_eh_shared": Program(
        artifact_kind="shared",
        source_language="cxx",
        exceptions="on",
        source=f"{SOURCE_ROOT}/cxx_eh_shared.cpp",
    ),
    "c_eh_probe": Program(
        artifact_kind="exe",
        source_language="c",
        exceptions="on",
        source=f"{SOURCE_ROOT}/c_eh_probe.c",
    ),
}

#: The optimization level whose shared library the C probe links against.  The
#: C probe is an `-O2` artifact, so it takes the `-O2` library.
_C_PROBE_DEPENDENCY_OPTIMIZATION = "o2"

#: Where a `c_eh_probe` executable looks for the library beside it, expressed
#: relative to the executable so that no build path reaches the image.
_RUNTIME_SEARCH_PATHS = {
    "elf": "$ORIGIN/../shared",
    "macho": "@loader_path/../shared",
}

# Probes the source defines whatever the exception setting is.  An exception
# free build has these and nothing else, which is what makes it a control
# rather than a different program.
_QUIET_PROBES: tuple[str, ...] = (
    "cxx_eh_probe_array_scope",
    "cxx_eh_probe_cleanup_scope",
    "cxx_eh_probe_loop_scope",
    "cxx_eh_probe_quiet_sum",
)

# Probes that only exist behind `CXX_EH_PROBE_EXCEPTIONS`.
_THROWING_PROBES: tuple[str, ...] = (
    "cxx_eh_probe_array_cleanup",
    "cxx_eh_probe_bare_rethrow",
    "cxx_eh_probe_catch_base_of_derived",
    "cxx_eh_probe_catch_by_pointer",
    "cxx_eh_probe_catch_by_reference",
    "cxx_eh_probe_catch_by_value",
    "cxx_eh_probe_catch_ellipsis",
    "cxx_eh_probe_catch_ladder",
    "cxx_eh_probe_catch_virtual_base",
    "cxx_eh_probe_cleanup_across_throw",
    "cxx_eh_probe_deep_propagation",
    "cxx_eh_probe_function_object_throw",
    "cxx_eh_probe_lambda_throw",
    "cxx_eh_probe_loop_try",
    "cxx_eh_probe_nested_try",
    "cxx_eh_probe_noexcept_terminate",
    "cxx_eh_probe_return_from_try",
    "cxx_eh_probe_static_local_guard",
    "cxx_eh_probe_throw_builtin",
    "cxx_eh_probe_throw_custom",
    "cxx_eh_probe_throw_runtime_error",
)

_SHARED_PROBES: tuple[str, ...] = (
    "cxx_eh_shared_call_and_catch",
    "cxx_eh_shared_catch",
    "cxx_eh_shared_cleanup",
    "cxx_eh_shared_log",
    "cxx_eh_shared_raise",
    "cxx_eh_shared_rethrow",
)

_C_PROBES: tuple[str, ...] = (
    "c_eh_probe_cleanup_only",
    "c_eh_probe_cross_frame",
    "c_eh_probe_nested_cleanup",
    "c_eh_probe_raise_bridge",
)

# The mangled type names the sources throw.  RTTI is data, so these survive a
# strip that removes every function name, and they are the only C++ identity a
# stripped artifact still carries.
TYPE_INFO_STRINGS: dict[str, str] = {
    "cxx_eh_probe": "15CxxEhProbeError",
    "libcxx_eh_shared": "16CxxEhSharedError",
}

# The weakest graph NeverD must recover, per program.  These are deliberately
# far below what any of the nine cells actually emits: the point is a floor that
# no optimization level, ABI, or libstdc++ version can drop through, not a
# measurement of one build.
_GRAPH_MINIMUMS: dict[str, dict[str, int]] = {
    "cxx_eh_probe": {
        "min_call_sites": 10,
        "min_landing_pads": 6,
        "min_catch_clauses": 4,
        "min_cleanup_pads": 3,
        "min_type_table_entries": 2,
    },
    "libcxx_eh_shared": {
        "min_call_sites": 3,
        "min_landing_pads": 2,
        "min_catch_clauses": 1,
        "min_cleanup_pads": 1,
        "min_type_table_entries": 1,
    },
    # A C frame has cleanup actions and no type table at all, which is the
    # whole reason the corpus carries one.
    "c_eh_probe": {
        "min_call_sites": 1,
        "min_landing_pads": 1,
        "min_catch_clauses": 0,
        "min_cleanup_pads": 1,
        "min_type_table_entries": 0,
    },
    "cxx_eh_probe_noexc": {
        "min_call_sites": 0,
        "min_landing_pads": 0,
        "min_catch_clauses": 0,
        "min_cleanup_pads": 0,
        "min_type_table_entries": 0,
    },
}

#: A linked ARM executable's index covers the C runtime as well as the probe,
#: so this floor is far under what any of them emits.
_MIN_ARM_EXIDX_ENTRIES = 8


@dataclass(frozen=True, order=True)
class Variant:
    """One committed artifact within a cell."""

    program: str
    optimization: str
    stripped: bool

    @property
    def _program(self) -> Program:
        try:
            return _PROGRAMS[self.program]
        except KeyError as error:
            raise MatrixError(f"unsupported program: {self.program}") from error

    @property
    def artifact_kind(self) -> str:
        return self._program.artifact_kind

    @property
    def source_language(self) -> str:
        return self._program.source_language

    @property
    def exceptions(self) -> str:
        return self._program.exceptions

    @property
    def source(self) -> str:
        return self._program.source

    @property
    def symbols_label(self) -> str:
        return "stripped" if self.stripped else "symtab"

    @property
    def key(self) -> str:
        return "-".join((self.program, self.optimization, self.symbols_label))


#: The eight artifacts every cell produces.  Two optimization levels crossed
#: with two symbol states cover the main probe; the remaining four are the
#: shapes that only exist once -- the exception-free control, the shared object
#: at both levels, and the C frame.
_VARIANTS: tuple[Variant, ...] = (
    Variant("cxx_eh_probe", "o0", False),
    Variant("cxx_eh_probe", "o0", True),
    Variant("cxx_eh_probe", "o2", False),
    Variant("cxx_eh_probe", "o2", True),
    Variant("cxx_eh_probe_noexc", "o2", False),
    Variant("libcxx_eh_shared", "o0", False),
    Variant("libcxx_eh_shared", "o2", False),
    Variant("c_eh_probe", "o2", False),
)


# ===----------------------------------------------------------------------===#
# Cells
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True, order=True)
class MatrixCell:
    """One (toolchain, target) pair, which is one build job."""

    toolchain: str
    target: str

    @property
    def _target(self) -> Target:
        return _TARGETS[self.target]

    @property
    def _toolset(self) -> Toolset:
        return _TOOLSETS[(self.toolchain, self.target)]

    @property
    def architecture(self) -> str:
        return self._target.architecture

    @property
    def object_format(self) -> str:
        return self._target.object_format

    @property
    def gnu_triple(self) -> str:
        return self._target.gnu_triple

    @property
    def runner_os(self) -> str:
        return self._target.runner_os

    @property
    def runs_on(self) -> str:
        return self._target.runs_on

    @property
    def runner_arch(self) -> str:
        return _RUNNER_ARCHITECTURES[self.runner_os]

    @property
    def native(self) -> bool:
        return self._target.native

    @property
    def cxx_driver(self) -> str:
        return self._toolset.cxx_driver

    @property
    def c_driver(self) -> str:
        return self._toolset.c_driver

    @property
    def strip_tool(self) -> str:
        return self._toolset.strip_tool

    @property
    def version_prefix(self) -> str:
        return self._toolset.version_prefix

    @property
    def apt_packages(self) -> tuple[str, ...]:
        return self._toolset.apt_packages

    @property
    def target_flags(self) -> tuple[str, ...]:
        return self._toolset.target_flags

    @property
    def xcode_path(self) -> str:
        return MACOS_XCODE_PATH if self.runner_os == "macos" else ""

    @property
    def variants(self) -> tuple[Variant, ...]:
        """Every cell builds every variant; nothing narrows per target."""

        return _VARIANTS

    @property
    def key(self) -> str:
        return f"{self.toolchain}-{self.target}"

    def driver(self, variant: Variant) -> str:
        return self.c_driver if variant.source_language == "c" else self.cxx_driver

    def execution(self, variant: Variant) -> str:
        """Return the honest execution status for one artifact of this cell."""

        if variant.artifact_kind == "shared":
            return "not-run-library"
        return "passed" if self.native else "not-run-cross-target"

    def artifact_extension(self, variant: Variant) -> str:
        if variant.artifact_kind == "shared":
            return self._target.shared_extension
        return self._target.exe_extension

    def relative_directory(self, variant: Variant) -> str:
        return "/".join(
            (
                CORPUS_ROOT,
                self.toolchain,
                self.target,
                variant.optimization,
                variant.symbols_label,
                variant.artifact_kind,
            )
        )

    def artifact_filename(self, variant: Variant) -> str:
        stem = "-".join(
            (
                variant.program,
                self.toolchain,
                self.target,
                variant.optimization,
                variant.symbols_label,
            )
        )
        return stem + self.artifact_extension(variant)

    def artifact_path(self, variant: Variant) -> str:
        return "/".join(
            (self.relative_directory(variant), self.artifact_filename(variant))
        )

    def to_actions_entry(self) -> dict[str, str | bool | int]:
        return {
            "cell_name": self.key,
            "toolchain": self.toolchain,
            "target": self.target,
            "architecture": self.architecture,
            "object_format": self.object_format,
            "runner_os": self.runner_os,
            "runner_arch": self.runner_arch,
            "runs_on": self.runs_on,
            "native": self.native,
            "apt_packages": " ".join(self.apt_packages),
            "xcode_path": self.xcode_path,
            "artifact_count": len(self.variants),
        }


def target_names() -> tuple[str, ...]:
    return tuple(_TARGETS)


def program_names() -> tuple[str, ...]:
    return tuple(_PROGRAMS)


def program_source(program: str) -> str:
    try:
        return _PROGRAMS[program].source
    except KeyError as error:
        raise MatrixError(f"unsupported program: {program}") from error


def probe_symbols(program: str) -> tuple[str, ...]:
    """Return the entry points \\p program defines, in manifest order."""

    if program == "cxx_eh_probe":
        return tuple(sorted(_QUIET_PROBES + _THROWING_PROBES))
    if program == "cxx_eh_probe_noexc":
        return tuple(sorted(_QUIET_PROBES))
    if program == "libcxx_eh_shared":
        return tuple(sorted(_SHARED_PROBES))
    if program == "c_eh_probe":
        return tuple(sorted(_C_PROBES))
    raise MatrixError(f"unsupported program: {program}")


def quiet_probe_symbols() -> tuple[str, ...]:
    return tuple(sorted(_QUIET_PROBES))


def throwing_probe_symbols() -> tuple[str, ...]:
    return tuple(sorted(_THROWING_PROBES))


def validate_cell(toolchain: str, target: str) -> MatrixCell:
    """Validate and canonicalize one producer cell."""

    normalized_toolchain = toolchain.strip().lower()
    normalized_target = target.strip()
    if normalized_toolchain not in _TOOLCHAINS:
        raise MatrixError(f"unsupported cxx-itanium-eh toolchain: {toolchain}")
    if normalized_target not in _TARGETS:
        raise MatrixError(f"unsupported cxx-itanium-eh target: {target}")
    key = (normalized_toolchain, normalized_target)
    if key not in _TOOLSETS:
        raise MatrixError(
            f"{normalized_toolchain} does not build {normalized_target} in this corpus"
        )
    return MatrixCell(normalized_toolchain, normalized_target)


def validate_variant(program: str, optimization: str, stripped: bool) -> Variant:
    normalized_program = program.strip()
    if normalized_program not in _PROGRAMS:
        raise MatrixError(f"unsupported program: {program}")
    normalized_optimization = optimization.strip().lower()
    if normalized_optimization not in _OPTIMIZATIONS:
        raise MatrixError(f"unsupported optimization mode: {optimization}")
    if not isinstance(stripped, bool):
        raise MatrixError("stripped must be boolean")
    variant = Variant(normalized_program, normalized_optimization, stripped)
    if variant not in _VARIANTS:
        raise MatrixError(f"variant is not part of the matrix: {variant.key}")
    return variant


def expected_cells() -> tuple[MatrixCell, ...]:
    """Return the complete, deterministic producer matrix."""

    return tuple(MatrixCell(toolchain, target) for toolchain, target in _CELL_ORDER)


def expected_artifact_paths() -> tuple[str, ...]:
    """Return every canonical artifact path, sorted the way a manifest is."""

    return tuple(
        sorted(
            cell.artifact_path(variant)
            for cell in expected_cells()
            for variant in cell.variants
        )
    )


# ===----------------------------------------------------------------------===#
# Build description
# ===----------------------------------------------------------------------===#


def build_environment() -> dict[str, str]:
    """The environment every compilation runs under.

    Anything the toolchain might otherwise take from the runner is pinned, so a
    rebuild on a refreshed image produces the same bytes.  `SOURCE_DATE_EPOCH`
    also fixes the PE header timestamp, which is otherwise the only field in a
    mingw artifact that changes on every run.
    """

    return {"LC_ALL": "C", "SOURCE_DATE_EPOCH": "1735689600", "TZ": "UTC"}


def toolchain_contract(cell: MatrixCell) -> dict[str, str]:
    """The part of a `producer.toolchains` record the matrix decides.

    A fragment adds the version its runner actually reported; everything here
    is recomputed by the verifier, so a cell cannot claim to have used a
    compiler the matrix does not name.
    """

    return {
        "cell": cell.key,
        "toolchain": cell.toolchain,
        "target": cell.target,
        "cxx_driver": cell.cxx_driver,
        "c_driver": cell.c_driver,
        "strip_tool": cell.strip_tool,
        "version_prefix": cell.version_prefix,
    }


def compiler_flags(
    cell: MatrixCell, variant: Variant, remapped_prefix: str
) -> list[str]:
    """Return the exact driver flags for one artifact.

    The builder and the verifier both call this, so a flag can never be passed
    without the manifest recording it or recorded without being passed.  The
    output path, the source path, and any library the link consumes are inputs
    rather than flags and are recorded separately.
    """

    flags = list(cell.target_flags)
    if variant.source_language == "cxx":
        flags.append("-std=c++17")
    else:
        flags.append("-std=c11")
    flags.append("-O0" if variant.optimization == "o0" else "-O2")
    # Without debug information there is nothing left to leak but the file
    # names, and `-ffile-prefix-map` covers those.
    flags.append("-g0")
    if variant.exceptions == "on":
        # Explicit on both languages: it is the default for C++ and off by
        # default for C, and the manifest should not have to know which.
        flags.append("-fexceptions")
    else:
        flags.append("-fno-exceptions")
    # Keeps the negative control worth having.  Without it an exception-free
    # build can end up with no unwind metadata at all, and `cfi-only` would be
    # a claim about an empty image.
    flags.append("-fasynchronous-unwind-tables")

    if variant.artifact_kind == "shared":
        if cell.object_format != "pe":
            # A Windows image is position independent whether or not anyone
            # asks, and mingw's driver says so once per compilation.
            flags.append("-fPIC")
        # The library is loaded by its own corpus filename.  Without an
        # install name the dependent executable would record the absolute path
        # the link happened to use, which is the build path the corpus spends
        # `-ffile-prefix-map` keeping out of the image.
        soname = cell.artifact_filename(variant)
        if cell.object_format == "macho":
            flags += ["-dynamiclib", "-install_name", f"@rpath/{soname}"]
        else:
            flags.append("-shared")
            if cell.object_format == "elf":
                flags.append(f"-Wl,-soname,{soname}")

    if linked_artifacts(cell, variant):
        search_path = _RUNTIME_SEARCH_PATHS.get(cell.object_format)
        if search_path:
            flags.append(f"-Wl,-rpath,{search_path}")

    if cell.object_format == "pe":
        # A mingw image that resolves the unwinder through `libstdc++-6.dll`
        # names it in an import table the corpus's readers do not decode, so
        # the runtime is linked in and the evidence stays checkable.
        flags.append("-static-libgcc")
        if variant.source_language == "cxx":
            flags.append("-static-libstdc++")

    flags.append(f"-ffile-prefix-map={remapped_prefix}=/testbins")
    return flags


def linked_artifacts(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Corpus artifacts this artifact's link consumes.

    Only the C probe has one: its cleanup tables exist because the shared
    library on the other side of the call can throw.
    """

    if variant.program != "c_eh_probe":
        return ()
    dependency = Variant("libcxx_eh_shared", _C_PROBE_DEPENDENCY_OPTIMIZATION, False)
    return (cell.artifact_path(dependency),)


def build_contract(
    cell: MatrixCell, variant: Variant, remapped_prefix: str
) -> dict[str, object]:
    """The part of the build the matrix decides, without the runner's facts."""

    return {
        "compiler": cell.driver(variant),
        "compiler_flags": compiler_flags(cell, variant, remapped_prefix),
        "linked_artifacts": list(linked_artifacts(cell, variant)),
        "strip_tool": cell.strip_tool if variant.stripped else "",
        "environment": build_environment(),
    }


# ===----------------------------------------------------------------------===#
# Evidence: what the verifier re-derives from the bytes
# ===----------------------------------------------------------------------===#


def personality(object_format: str, source_language: str) -> str:
    """Return the personality routine one artifact's frames name.

    mingw-w64 keeps Itanium language semantics but reaches them through a
    Windows SEH dispatcher, so both personalities are spelled `seh0` there.
    """

    if source_language == "c":
        return (
            "__gcc_personality_seh0"
            if object_format == "pe"
            else "__gcc_personality_v0"
        )
    return "__gxx_personality_seh0" if object_format == "pe" else "__gxx_personality_v0"


def required_sections(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Sections the artifact must carry, named the way its format names them."""

    if cell.object_format == "elf":
        if cell.architecture == "arm":
            # ARM EHABI replaces the DWARF chain outright: there is no
            # `.eh_frame` and no `.gcc_except_table`, and the language specific
            # data area is emitted inline in `.ARM.extab`.
            names = [".text", ".ARM.exidx"]
            if variant.exceptions == "on":
                names.append(".ARM.extab")
            return tuple(names)
        names = [".text", ".eh_frame", ".eh_frame_hdr"]
        if variant.exceptions == "on":
            names.append(".gcc_except_table")
        return tuple(names)
    if cell.object_format == "macho":
        names = ["__TEXT,__text", "__TEXT,__unwind_info"]
        if variant.exceptions == "on":
            names.append("__TEXT,__gcc_except_tab")
        return tuple(names)
    # A PE section name is eight bytes, so `.gcc_except_table` cannot survive
    # the link under its own name; what proves the LSDA is there is the SEH
    # personality, which is asserted as a symbol instead.
    return (".text", ".pdata", ".xdata")


def forbidden_sections(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Sections whose absence is a property of the build.

    Only the exception-free control claims one, and only where the C++ runtime
    is linked dynamically.  A mingw image carries a static `libstdc++`, so an
    except table there could belong to the runtime rather than to the producer
    and its presence would prove nothing either way.
    """

    if variant.exceptions == "on":
        return ()
    if cell.object_format == "elf" and cell.architecture != "arm":
        return (".gcc_except_table",)
    if cell.object_format == "macho":
        return ("__TEXT,__gcc_except_tab",)
    return ()


def _runtime_symbols(cell: MatrixCell, variant: Variant) -> set[str]:
    if variant.exceptions == "off":
        return set()
    names = {personality(cell.object_format, variant.source_language)}
    if variant.source_language == "cxx":
        names |= {
            "__cxa_allocate_exception",
            "__cxa_begin_catch",
            "__cxa_end_catch",
            "__cxa_rethrow",
            "__cxa_throw",
        }
        if variant.program == "cxx_eh_probe":
            # Only the executable has a function-scope static whose initializer
            # can throw.
            names |= {"__cxa_guard_acquire", "__cxa_guard_release"}
    if cell.architecture != "arm":
        # ARM EHABI resumes through `__cxa_end_cleanup` rather than calling
        # `_Unwind_Resume` directly, so the name a frame references there is a
        # libstdc++ detail the corpus does not pin.
        names.add("_Unwind_Resume")
    return names


def required_symbols(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    if variant.stripped:
        return ()
    return tuple(
        sorted(set(probe_symbols(variant.program)) | _runtime_symbols(cell, variant))
    )


def forbidden_symbols(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """The one absence an exception-free build actually decides.

    `__cxa_throw` is referenced only by a `throw` expression, so a build that
    has none cannot reference it.  The rest of the C++ runtime is still on the
    other side of a `DT_NEEDED`, and claiming its absence would be claiming
    something the flag does not control.
    """

    if variant.exceptions == "on" or variant.stripped:
        return ()
    if cell.object_format == "pe":
        return ()
    return ("__cxa_throw",)


def required_strings(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Byte sequences that must appear in the image.

    A stripped artifact has no function names left, but RTTI is data: the
    mangled name of the type a probe throws is still in the image, and it is
    the only thing that identifies it as this corpus's C++ rather than some
    other program's.
    """

    if variant.exceptions == "off":
        return ()
    text = TYPE_INFO_STRINGS.get(variant.program)
    return (text,) if text else ()


def eh_frame_present(cell: MatrixCell, variant: Variant) -> bool:
    """True when the artifact must carry a well-formed DWARF frame chain.

    False is "not asserted" rather than "absent".  Mach-O keeps `__eh_frame`
    only for the frames compact unwind cannot describe, a mingw x86-64 image
    describes its frames in `.xdata`, and ARM EHABI has no DWARF chain at all;
    none of the three is a claim the producer can make from the flags alone.
    """

    return cell.object_format == "elf" and cell.architecture != "arm"


def arm_exidx_present(cell: MatrixCell, variant: Variant) -> bool:
    return cell.architecture == "arm"


def min_arm_exidx_entries(cell: MatrixCell, variant: Variant) -> int:
    return _MIN_ARM_EXIDX_ENTRIES if cell.architecture == "arm" else 0


def require_unwind_tables(cell: MatrixCell, variant: Variant) -> bool:
    """Whether the format's own unwind table check applies.

    ARM EHABI has neither a DWARF frame chain nor a compact unwind table, so
    the index section is what gets counted there instead.
    """

    return cell.architecture != "arm"


def evidence_contract(cell: MatrixCell, variant: Variant) -> dict[str, object]:
    return {
        "required_sections": list(required_sections(cell, variant)),
        "forbidden_sections": list(forbidden_sections(cell, variant)),
        "required_symbols": list(required_symbols(cell, variant)),
        "forbidden_symbols": list(forbidden_symbols(cell, variant)),
        "required_strings": list(required_strings(cell, variant)),
        "symbol_names_expected": not variant.stripped,
        "require_unwind_tables": require_unwind_tables(cell, variant),
        "eh_frame_present": eh_frame_present(cell, variant),
        "arm_exidx_present": arm_exidx_present(cell, variant),
        "min_arm_exidx_entries": min_arm_exidx_entries(cell, variant),
    }


# ===----------------------------------------------------------------------===#
# The consumer contract
# ===----------------------------------------------------------------------===#


def validation_level(cell: MatrixCell, variant: Variant) -> str:
    if variant.exceptions == "off":
        return "cfi-only"
    if cell.architecture == "arm":
        return "ehabi"
    return "lsda-graph"


def personalities_any(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    if variant.exceptions == "off":
        return ()
    names = [personality(cell.object_format, variant.source_language)]
    if cell.architecture == "arm":
        # EHABI lets a frame with no table use the compact model, whose
        # personality is one of the `__aeabi_unwind_cpp_pr*` routines rather
        # than the language's own.
        names += ["__aeabi_unwind_cpp_pr0", "__aeabi_unwind_cpp_pr1"]
    return tuple(names)


def neverd_contract(cell: MatrixCell, variant: Variant) -> dict[str, object]:
    """The weakest result NeverD must produce for one artifact."""

    contract: dict[str, object] = {
        "validation_level": validation_level(cell, variant),
        "personalities_any": list(personalities_any(cell, variant)),
        "expect_no_lsda": variant.exceptions == "off",
        "expect_arm_ehabi": cell.architecture == "arm",
    }
    contract.update(_GRAPH_MINIMUMS[variant.program])
    return contract


# ===----------------------------------------------------------------------===#
# Command line
# ===----------------------------------------------------------------------===#


def actions_matrix() -> dict[str, list[dict[str, str | bool | int]]]:
    return {"include": [cell.to_actions_entry() for cell in expected_cells()]}


def artifact_plan() -> dict[str, object]:
    artifacts = []
    for cell in expected_cells():
        for variant in cell.variants:
            artifacts.append(
                {
                    "cell": cell.key,
                    "path": cell.artifact_path(variant),
                    "program": variant.program,
                    "artifact_kind": variant.artifact_kind,
                    "source_language": variant.source_language,
                    "exceptions": variant.exceptions,
                    "optimization": variant.optimization,
                    "stripped": variant.stripped,
                    "object_format": cell.object_format,
                    "architecture": cell.architecture,
                    "execution": cell.execution(variant),
                    "compiler": cell.driver(variant),
                    "compiler_flags": compiler_flags(cell, variant, "/checkout"),
                    "linked_artifacts": list(linked_artifacts(cell, variant)),
                    "evidence": evidence_contract(cell, variant),
                    "neverd": neverd_contract(cell, variant),
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
    parser.add_argument(
        "--paths",
        action="store_true",
        help="print every canonical artifact path, one per line",
    )
    args = parser.parse_args()
    if not (args.github_output or args.json or args.plan or args.paths):
        parser.error("one of --github-output, --json, --plan, or --paths is required")

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
        for path in expected_artifact_paths():
            print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
