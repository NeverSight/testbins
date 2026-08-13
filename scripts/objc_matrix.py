#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Define the supported Objective-C exception-corpus build matrix.

Objective-C has no table format of its own.  Every runtime emits an Itanium
language specific data area -- the same structure C++ uses -- so this corpus
does not exist to pin a format.  It exists to pin the one thing the runtimes
disagree about, which is what a type-table slot holds:

* Apple's non-fragile runtime reaches `__objc_personality_v0`, and a slot
  addresses an `objc_typeinfo` whose first two fields are laid out as
  `std::type_info`'s are -- deliberately, so that one table can name both an
  Objective-C class and a C++ type -- with the class itself in a third field
  that only Objective-C has;
* the GNU runtimes reach `__gnu_objc_personality_v0`, and a slot is not a
  pointer at all: it holds the class name string;
* GNUstep's Objective-C++ routine reaches `__gnustep_objcxx_personality_v0`,
  and a slot addresses a real `std::type_info` subclass.

A reader that applies one runtime's convention to another's table does not
fail.  It reports a class name read out of the middle of something else, and
only a binary each runtime actually produced can catch that.

The cell axis is therefore the *runtime* rather than the compiler.  Every cell
here is clang, because clang is the only compiler that targets all three; what
distinguishes one cell from the next is which runtime it was asked for, and on
Apple's targets that choice is also a choice of object format and host.

Two axes deliberately cross the runtime axis:

* ARC.  A landing pad in ARC code is mostly compiler-inserted releases, and
  telling that apart from cleanup the program wrote is a reading a consumer
  has to get right.  The corpus carries the same source both ways so the
  difference is the flag and nothing else.
* Exceptions.  The control is the same source with `-fno-objc-exceptions`,
  which is a program with the same entry points and no landing pad anywhere.

The fragile runtime is not here yet.  Its `@try` is a setjmp buffer rather
than a table, so it is a different model rather than another slot convention,
and Apple dropped the only target that shipped it.  It is the obvious next
axis if a producer that still builds it is ever pinned.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

CORPUS_NAME = "objc-eh"
CORPUS_ROOT = f"corpus/{CORPUS_NAME}"
SOURCE_ROOT = f"sources/{CORPUS_NAME}"

#: What the executables print when their own runtime checks pass.
PROBE_PASS_MARKER = "objc-eh probe passed"

#: The Xcode the macOS cells select before building.  Apple's clang has its own
#: version line, so this and `_TOOLSETS[...].version_prefix` are the pin: change
#: one without the other and the verifier rejects the manifest.  It matches the
#: C++ Itanium line's pin, because one runner image should not be two compilers.
MACOS_XCODE_PATH = "/Applications/Xcode_16.4.app"


class MatrixError(ValueError):
    """Raised when a cell or variant is outside the supported matrix."""


# ===----------------------------------------------------------------------===#
# Runtimes
# ===----------------------------------------------------------------------===#

#: Which personality a runtime's frames install, which is the whole of how its
#: type table is read.  A cell claims one of these and the verifier requires the
#: symbol to be in the image, so a cell that silently built against a different
#: runtime fails rather than being recorded as the one it was asked for.
#:
#: Spelled the way the source does. `object_readers.MachOImage` exposes both
#: the raw nlist spelling and this source spelling, so every manifest contract
#: uses the source spelling and never bakes Mach-O's extra underscore into an
#: Objective-C runtime name.
_RUNTIME_PERSONALITIES = {
    "apple": "__objc_personality_v0",
}

#: The `-fobjc-runtime=` value each runtime is selected with.  Apple's targets
#: default to it, but naming it means the manifest records the choice rather
#: than inheriting it from whichever SDK the runner happened to carry.
_RUNTIME_FLAGS = {
    "apple": "macosx",
}

_RUNTIMES = tuple(_RUNTIME_PERSONALITIES)


# ===----------------------------------------------------------------------===#
# Targets
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True)
class Target:
    """One target and the container facts that follow from it."""

    architecture: str
    object_format: str
    runner_os: str
    runs_on: str
    #: True when the runner that builds this target can also execute it.
    native: bool
    exe_extension: str


_TARGETS: dict[str, Target] = {
    "arm64-apple-darwin": Target(
        architecture="aarch64",
        object_format="macho",
        runner_os="macos",
        runs_on="macos-15",
        native=True,
        exe_extension="",
    ),
    "x86_64-apple-darwin": Target(
        architecture="x86_64",
        object_format="macho",
        runner_os="macos",
        # The hosted macOS image is Apple silicon and has no Rosetta, so the
        # Intel slice is cross-built and never executed.
        runs_on="macos-15",
        native=False,
        exe_extension="",
    ),
}

# What each hosted runner image actually is, so a manifest cannot claim it was
# built somewhere the matrix does not run.
_RUNNER_ARCHITECTURES = {"macos": "arm64"}


# ===----------------------------------------------------------------------===#
# Toolsets
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True)
class Toolset:
    """The exact programs one cell invokes, and the version it must report."""

    driver: str
    #: Symbols are removed after the link rather than by a linker flag, because
    #: `ld64` has no equivalent of GNU `ld -s` and the corpus wants one story.
    strip_tool: str
    #: The version the cell is pinned to.  On macOS it is `MACOS_XCODE_PATH`
    #: that makes this pin true.
    version_prefix: str
    apt_packages: tuple[str, ...]
    #: Flags that select the target.  Everything else is a property of the
    #: variant rather than the cell.
    target_flags: tuple[str, ...]
    #: Frameworks or libraries every link in the cell consumes.  Apple's
    #: `NSException` is the framework class the corpus catches, so Foundation is
    #: not an extra here -- it is where half the type table comes from.
    link_flags: tuple[str, ...]


_TOOLSETS: dict[tuple[str, str], Toolset] = {
    ("apple", "arm64-apple-darwin"): Toolset(
        driver="clang",
        strip_tool="strip",
        version_prefix="17.",
        apt_packages=(),
        target_flags=("-arch", "arm64"),
        link_flags=("-framework", "Foundation"),
    ),
    ("apple", "x86_64-apple-darwin"): Toolset(
        driver="clang",
        strip_tool="strip",
        version_prefix="17.",
        apt_packages=(),
        target_flags=("-arch", "x86_64"),
        link_flags=("-framework", "Foundation"),
    ),
}

#: Declaration order is the matrix order, so an Actions matrix is stable.
_CELL_ORDER: tuple[tuple[str, str], ...] = tuple(_TOOLSETS)

_OPTIMIZATIONS = ("o0", "o2")


# ===----------------------------------------------------------------------===#
# Programs and variants
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True)
class Program:
    #: `on` or `off`: whether the translation unit is compiled with
    #: `-fobjc-exceptions`.
    exceptions: str
    #: `on` or `off`: whether it is compiled with `-fobjc-arc`.
    arc: str
    source: str


#: All three are the same source.  They differ in two flags, which is what
#: makes each one a control for the others rather than a different program.
_PROGRAMS: dict[str, Program] = {
    "objc_eh_probe": Program(
        exceptions="on",
        arc="on",
        source=f"{SOURCE_ROOT}/objc_eh_probe.m",
    ),
    # Manual retain/release.  Its landing pads are the program's own cleanup
    # rather than the compiler's, and no ARC entry point is referenced at all.
    "objc_eh_probe_mrr": Program(
        exceptions="on",
        arc="off",
        source=f"{SOURCE_ROOT}/objc_eh_probe.m",
    ),
    # The negative control: same source, no exceptions.
    "objc_eh_probe_noexc": Program(
        exceptions="off",
        arc="on",
        source=f"{SOURCE_ROOT}/objc_eh_probe.m",
    ),
}

# Probes the source defines whatever the exception setting is.  An exception
# free build has these and nothing else, which is what makes it a control
# rather than a different program.
_QUIET_PROBES: tuple[str, ...] = (
    "objc_eh_probe_quiet_message",
    "objc_eh_probe_quiet_pool",
    "objc_eh_probe_quiet_sum",
)

# Probes that only exist behind `OBJC_EH_PROBE_EXCEPTIONS`.
_THROWING_PROBES: tuple[str, ...] = (
    "objc_eh_probe_autoreleasepool",
    "objc_eh_probe_catch_class",
    "objc_eh_probe_catch_ellipsis",
    "objc_eh_probe_catch_framework_class",
    "objc_eh_probe_catch_id",
    "objc_eh_probe_catch_ladder",
    "objc_eh_probe_cleanup_only",
    "objc_eh_probe_finally",
    "objc_eh_probe_held_local",
    "objc_eh_probe_nested_try",
    "objc_eh_probe_raise",
    "objc_eh_probe_rethrow",
    "objc_eh_probe_synchronized",
    "objc_eh_probe_synchronized_throwing",
)

#: The class this source defines.  Its name reaches `__objc_classname` as data,
#: so it survives a strip that removes every function name and is the only
#: thing identifying a stripped artifact as this program rather than another.
PROBE_CLASS_NAME = "ObjCEhProbeError"

#: Runtime entry points an exception-carrying artifact must reference. These
#: are source spellings, not Mach-O nlist spellings: the object reader removes
#: the container's one leading underscore. They survive a strip because the
#: dynamic linker still has to bind them.
_EXCEPTION_IMPORTS: tuple[str, ...] = (
    "OBJC_EHTYPE_$_NSException",
    "OBJC_EHTYPE_id",
    "objc_begin_catch",
    "objc_end_catch",
    "objc_exception_rethrow",
    "objc_exception_throw",
    "objc_sync_enter",
    "objc_sync_exit",
)

#: The ARC entry point an optimized Apple build actually reaches.  It is the
#: caller half of the return-value handshake, and no hand-written code contains
#: it -- which is the whole reason it can stand for "this image is ARC".
_ARC_IMPORT = "objc_retainAutoreleasedReturnValue"


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
    def exceptions(self) -> str:
        return self._program.exceptions

    @property
    def arc(self) -> str:
        return self._program.arc

    @property
    def source(self) -> str:
        return self._program.source

    @property
    def symbols_label(self) -> str:
        return "stripped" if self.stripped else "symtab"

    @property
    def key(self) -> str:
        return "-".join((self.program, self.optimization, self.symbols_label))


#: The six artifacts every cell produces.  Two optimization levels crossed with
#: two symbol states cover the main probe; the remaining two are the axes that
#: only need to exist once -- the manual-retain build and the exception-free
#: control -- and both are taken at `-O2`, where a shape that survives is a
#: shape the optimizer could not remove.
_VARIANTS: tuple[Variant, ...] = (
    Variant("objc_eh_probe", "o0", False),
    Variant("objc_eh_probe", "o0", True),
    Variant("objc_eh_probe", "o2", False),
    Variant("objc_eh_probe", "o2", True),
    Variant("objc_eh_probe_mrr", "o2", False),
    Variant("objc_eh_probe_noexc", "o2", False),
)


# ===----------------------------------------------------------------------===#
# Cells
# ===----------------------------------------------------------------------===#


@dataclass(frozen=True, order=True)
class MatrixCell:
    """One (runtime, target) pair, which is one build job."""

    runtime: str
    target: str

    @property
    def _target(self) -> Target:
        return _TARGETS[self.target]

    @property
    def _toolset(self) -> Toolset:
        return _TOOLSETS[(self.runtime, self.target)]

    @property
    def architecture(self) -> str:
        return self._target.architecture

    @property
    def object_format(self) -> str:
        return self._target.object_format

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
    def driver(self) -> str:
        return self._toolset.driver

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
    def link_flags(self) -> tuple[str, ...]:
        return self._toolset.link_flags

    @property
    def personality(self) -> str:
        """The routine's name as the source spells it."""

        return _RUNTIME_PERSONALITIES[self.runtime]

    @property
    def personality_symbol(self) -> str:
        """The normalized name exposed by the repository's object reader."""

        return self.personality

    @property
    def xcode_path(self) -> str:
        return MACOS_XCODE_PATH if self.runner_os == "macos" else ""

    @property
    def variants(self) -> tuple[Variant, ...]:
        """Every cell builds every variant; nothing narrows per target."""

        return _VARIANTS

    @property
    def key(self) -> str:
        return f"{self.runtime}-{self.target}"

    def execution(self, variant: Variant) -> str:
        """Return the honest execution status for one artifact of this cell."""

        return "passed" if self.native else "not-run-cross-target"

    def relative_directory(self, variant: Variant) -> str:
        return "/".join(
            (
                CORPUS_ROOT,
                self.runtime,
                self.target,
                variant.optimization,
                variant.symbols_label,
            )
        )

    def artifact_filename(self, variant: Variant) -> str:
        stem = "-".join(
            (
                variant.program,
                self.runtime,
                self.target,
                variant.optimization,
                variant.symbols_label,
            )
        )
        return stem + self._target.exe_extension

    def artifact_path(self, variant: Variant) -> str:
        return "/".join(
            (self.relative_directory(variant), self.artifact_filename(variant))
        )

    def to_actions_entry(self) -> dict[str, str | bool | int]:
        return {
            "cell_name": self.key,
            "runtime": self.runtime,
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


def runtime_names() -> tuple[str, ...]:
    return _RUNTIMES


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

    try:
        exceptions = _PROGRAMS[program].exceptions
    except KeyError as error:
        raise MatrixError(f"unsupported program: {program}") from error
    names = _QUIET_PROBES + (_THROWING_PROBES if exceptions == "on" else ())
    return tuple(sorted(names))


def quiet_probe_symbols() -> tuple[str, ...]:
    return tuple(sorted(_QUIET_PROBES))


def throwing_probe_symbols() -> tuple[str, ...]:
    return tuple(sorted(_THROWING_PROBES))


def validate_cell(runtime: str, target: str) -> MatrixCell:
    """Validate and canonicalize one producer cell."""

    normalized_runtime = runtime.strip().lower()
    normalized_target = target.strip()
    if normalized_runtime not in _RUNTIMES:
        raise MatrixError(f"unsupported objc-eh runtime: {runtime}")
    if normalized_target not in _TARGETS:
        raise MatrixError(f"unsupported objc-eh target: {target}")
    key = (normalized_runtime, normalized_target)
    if key not in _TOOLSETS:
        raise MatrixError(
            f"the {normalized_runtime} runtime does not build "
            f"{normalized_target} in this corpus"
        )
    return MatrixCell(normalized_runtime, normalized_target)


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

    return tuple(MatrixCell(runtime, target) for runtime, target in _CELL_ORDER)


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
    rebuild on a refreshed image produces the same bytes.
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
        "runtime": cell.runtime,
        "target": cell.target,
        "driver": cell.driver,
        "strip_tool": cell.strip_tool,
        "version_prefix": cell.version_prefix,
    }


def compiler_flags(
    cell: MatrixCell, variant: Variant, remapped_prefix: str
) -> list[str]:
    """Return the exact driver flags for one artifact.

    The builder and the verifier both call this, so a flag can never be passed
    without the manifest recording it or recorded without being passed.  The
    output path and the source path are inputs rather than flags and are
    recorded separately.
    """

    flags = list(cell.target_flags)
    flags.append("-std=c11")
    flags.append("-O0" if variant.optimization == "o0" else "-O2")
    # Without debug information there is nothing left to leak but the file
    # names, and `-ffile-prefix-map` covers those.
    flags.append("-g0")
    # Named on both sides rather than left to the target's default, so the
    # manifest records the choice instead of inheriting whatever SDK the runner
    # carried.
    flags.append(f"-fobjc-runtime={_RUNTIME_FLAGS[cell.runtime]}")
    flags.append("-fobjc-arc" if variant.arc == "on" else "-fno-objc-arc")
    flags.append(
        "-fobjc-exceptions" if variant.exceptions == "on" else "-fno-objc-exceptions"
    )
    # Keeps the negative control worth having.  Without it an exception-free
    # build can end up with no unwind metadata at all, and the compact-unwind
    # assertion would be a claim about an empty image.
    flags.append("-fasynchronous-unwind-tables")
    flags.append(f"-ffile-prefix-map={remapped_prefix}=/testbins")
    flags.extend(cell.link_flags)
    return flags


def linked_artifacts(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Corpus artifacts this artifact's link consumes.

    None do.  Every variant is a self-contained executable, and the only
    library any of them needs is the one the platform already ships.
    """

    return ()


def build_contract(
    cell: MatrixCell, variant: Variant, remapped_prefix: str
) -> dict[str, object]:
    """The part of the build the matrix decides, without the runner's facts."""

    return {
        "compiler": cell.driver,
        "compiler_flags": compiler_flags(cell, variant, remapped_prefix),
        "linked_artifacts": list(linked_artifacts(cell, variant)),
        "strip_tool": cell.strip_tool if variant.stripped else "",
        "environment": build_environment(),
    }


# ===----------------------------------------------------------------------===#
# Evidence: what the verifier re-derives from the bytes
# ===----------------------------------------------------------------------===#


def required_sections(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Sections the artifact must carry, named the way its format names them.

    `__objc_classlist` is named without a segment because which segment holds
    it is a linker's decision that has already changed once -- it moved from
    `__DATA` to `__DATA_CONST` -- and pinning the segment would be pinning that
    decision rather than a fact about Objective-C.  It appears only in the
    exception-carrying builds, because the one class this source defines is the
    exception class and it lives behind the guard.
    """

    names = ["__TEXT,__text", "__TEXT,__unwind_info"]
    if eh_frame_present(cell, variant):
        names.append("__TEXT,__eh_frame")
    if variant.exceptions == "on":
        names += ["__TEXT,__gcc_except_tab", "__objc_classlist"]
    return tuple(names)


def forbidden_sections(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Sections whose absence is a property of the build.

    Only the exception-free control claims one.  Apple links the Objective-C
    runtime dynamically, so an except table in this image could only have come
    from this translation unit.
    """

    if variant.exceptions == "on":
        return ()
    return ("__TEXT,__gcc_except_tab",)


def required_symbols(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Names the image must carry.

    A stripped artifact keeps more here than the C++ line's does.  `strip`
    removes what the dynamic linker does not need, and an Objective-C frame
    needs its personality and its catch-type descriptors bound at load time --
    so the personality, `OBJC_EHTYPE_id`, and `OBJC_EHTYPE_$_NSException`
    survive a strip that took every function name with it.
    """

    names = set()
    if variant.exceptions == "on":
        names.add(cell.personality_symbol)
        names.update(_EXCEPTION_IMPORTS)
    if variant.arc == "on":
        names.add(_ARC_IMPORT)
    if not variant.stripped:
        names.update(probe_symbols(variant.program))
    return tuple(sorted(names))


def forbidden_symbols(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """The absences each flag actually decides.

    An exception-free build cannot reference the personality or the throw, and
    a manual-retain build cannot reference the ARC return-value handshake.
    Both are references the compiler emits or does not, so their absence is
    controlled by the flag rather than by what got linked in beside them.
    """

    names = []
    if variant.exceptions == "off":
        names += [cell.personality_symbol, "objc_exception_throw"]
    if variant.arc == "off":
        names.append(_ARC_IMPORT)
    return tuple(sorted(names))


def required_strings(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    """Byte sequences that must appear in the image.

    A stripped artifact has no function names left, but a class name is data:
    it reaches `__objc_classname` and stays there, which is the only thing
    identifying a stripped artifact as this program rather than another.
    """

    if variant.exceptions == "off":
        return ()
    return (PROBE_CLASS_NAME,)


def eh_frame_present(cell: MatrixCell, variant: Variant) -> bool:
    """True when the artifact must carry a well-formed DWARF frame chain.

    This is architecture-specific under the pinned Apple toolchain. arm64
    Objective-C executables keep a DWARF chain beside compact unwind (including
    the exception-free control), while the x86_64 slices encode every frame in
    `__unwind_info` and carry no `__eh_frame`.
    """

    return cell.architecture == "aarch64"


def require_unwind_tables(cell: MatrixCell, variant: Variant) -> bool:
    """Whether the format's own unwind table check applies.

    It always does here: every artifact has `__unwind_info`, and arm64 may
    additionally carry `__eh_frame`. The control is built with
    `-fasynchronous-unwind-tables` precisely so that it has metadata too.
    """

    return True


def evidence_contract(cell: MatrixCell, variant: Variant) -> dict[str, object]:
    return {
        "required_sections": list(required_sections(cell, variant)),
        "forbidden_sections": list(forbidden_sections(cell, variant)),
        "required_symbols": list(required_symbols(cell, variant)),
        "forbidden_symbols": list(forbidden_symbols(cell, variant)),
        "required_strings": list(required_strings(cell, variant)),
        # An Apple artifact keeps its imports through a strip, and this corpus
        # asserts them, so the flag stays true for every variant.  What it means
        # is "this contract names symbols the image must carry", not "no symbol
        # was removed".
        "symbol_names_expected": True,
        "require_unwind_tables": require_unwind_tables(cell, variant),
        "eh_frame_present": eh_frame_present(cell, variant),
    }


# ===----------------------------------------------------------------------===#
# The consumer contract
# ===----------------------------------------------------------------------===#

# The weakest graph NeverD must recover, per program.  These sit far below what
# any cell actually emits -- an `-O2` Apple build reaches thirteen frames with a
# landing pad and thirteen catch clauses -- because the point is a floor no
# optimization level or SDK version can drop through, not a measurement of one
# build.
#
# `min_cleanup_frames` is the one floor that has to be read carefully: an `-O0`
# build has thirteen and an `-O2` build has two, because the optimizer folds
# most cleanup into the catch path.  Two is what survives both.
_GRAPH_MINIMUMS: dict[str, dict[str, int]] = {
    "objc_eh_probe": {
        "min_exception_functions": 10,
        "min_landing_pads": 10,
        "min_catch_frames": 10,
        "min_catch_clauses": 12,
        "min_class_clauses": 2,
        "min_any_object_clauses": 1,
        "min_catch_all_clauses": 1,
        "min_cleanup_frames": 2,
        "min_synchronized_frames": 2,
        "min_throw_sites": 1,
    },
    "objc_eh_probe_mrr": {
        "min_exception_functions": 10,
        "min_landing_pads": 10,
        "min_catch_frames": 10,
        "min_catch_clauses": 12,
        "min_class_clauses": 2,
        "min_any_object_clauses": 1,
        "min_catch_all_clauses": 1,
        "min_cleanup_frames": 2,
        "min_synchronized_frames": 2,
        "min_throw_sites": 1,
    },
    "objc_eh_probe_noexc": {
        "min_exception_functions": 0,
        "min_landing_pads": 0,
        "min_catch_frames": 0,
        "min_catch_clauses": 0,
        "min_class_clauses": 0,
        "min_any_object_clauses": 0,
        "min_catch_all_clauses": 0,
        "min_cleanup_frames": 0,
        "min_synchronized_frames": 0,
        "min_throw_sites": 0,
    },
}

#: Class names NeverD must recover from the type table.  Both survive a strip:
#: the first because its descriptor is in the image, the second because the
#: binding that reaches Foundation's names it.
_REQUIRED_CLASS_NAMES: tuple[str, ...] = (PROBE_CLASS_NAME, "NSException")


def validation_level(cell: MatrixCell, variant: Variant) -> str:
    if variant.exceptions == "off":
        return "cfi-only"
    return "objc-graph"


def personalities_any(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    if variant.exceptions == "off":
        return ()
    # Named the way the source does.  A consumer strips the container's
    # underscore before it classifies a personality, so that is the spelling
    # the contract should be written against.
    return (cell.personality,)


def required_class_names(cell: MatrixCell, variant: Variant) -> tuple[str, ...]:
    if variant.exceptions == "off":
        return ()
    return _REQUIRED_CLASS_NAMES


def neverd_contract(cell: MatrixCell, variant: Variant) -> dict[str, object]:
    """The weakest result NeverD must produce for one artifact."""

    contract: dict[str, object] = {
        "validation_level": validation_level(cell, variant),
        "objc_runtime": cell.runtime,
        "personalities_any": list(personalities_any(cell, variant)),
        "required_class_names": list(required_class_names(cell, variant)),
        "expect_no_lsda": variant.exceptions == "off",
        "expect_arc": variant.arc == "on",
        "expect_runtime_proven_by_personality": variant.exceptions == "on",
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
                    "runtime": cell.runtime,
                    "exceptions": variant.exceptions,
                    "arc": variant.arc,
                    "optimization": variant.optimization,
                    "stripped": variant.stripped,
                    "object_format": cell.object_format,
                    "architecture": cell.architecture,
                    "execution": cell.execution(variant),
                    "compiler": cell.driver,
                    "compiler_flags": compiler_flags(cell, variant, "/checkout"),
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
