# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import re
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import objc_matrix as matrix  # noqa: E402

REPOSITORY_ROOT = SCRIPTS_ROOT.parent
SOURCE_ROOT = REPOSITORY_ROOT / matrix.SOURCE_ROOT
SOURCE_PATH = SOURCE_ROOT / "objc_eh_probe.m"
_EXCEPTION_GUARD = "OBJC_EH_PROBE_EXCEPTIONS"
_PROBE_RE = re.compile(
    r"^\s*PROBE\s+(?:void|long)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def _read() -> str:
    return SOURCE_PATH.read_text(encoding="utf-8")


def _entry_points(text: str) -> dict[str, bool]:
    """Map every PROBE definition to whether it is exception-guarded."""

    definitions: dict[str, bool] = {}
    conditionals: list[bool] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#if"):
            conditionals.append(_EXCEPTION_GUARD in stripped)
            continue
        if stripped.startswith("#endif"):
            if conditionals:
                conditionals.pop()
            continue
        match = _PROBE_RE.match(line)
        if match:
            definitions[match.group(1)] = any(conditionals)
    return definitions


class SourceInventoryTests(unittest.TestCase):
    def test_every_program_source_exists_where_the_matrix_says(self) -> None:
        for program in matrix.program_names():
            with self.subTest(program=program):
                self.assertTrue((REPOSITORY_ROOT / matrix.program_source(program)).is_file())

    def test_product_line_is_one_source_and_no_build_system(self) -> None:
        sources = sorted(path.name for path in SOURCE_ROOT.iterdir())

        self.assertEqual(sources, ["objc_eh_probe.m"])
        self.assertEqual(list(SOURCE_ROOT.rglob("CMakeLists.txt")), [])
        self.assertEqual(list(SOURCE_ROOT.rglob("Makefile")), [])

    def test_declared_probe_symbols_match_the_source(self) -> None:
        definitions = _entry_points(_read())

        self.assertEqual(
            sorted(definitions), sorted(matrix.probe_symbols("objc_eh_probe"))
        )

    def test_exception_guard_splits_full_and_control_inventories(self) -> None:
        definitions = _entry_points(_read())
        quiet = sorted(name for name, guarded in definitions.items() if not guarded)
        throwing = sorted(name for name, guarded in definitions.items() if guarded)

        self.assertEqual(quiet, list(matrix.quiet_probe_symbols()))
        self.assertEqual(throwing, list(matrix.throwing_probe_symbols()))
        self.assertEqual(quiet, list(matrix.probe_symbols("objc_eh_probe_noexc")))

    def test_every_probe_is_noinline_and_externally_visible(self) -> None:
        text = _read()

        self.assertIn('__attribute__((visibility("default")))', text)
        self.assertIn("__attribute__((noinline))", text)
        self.assertTrue(_entry_points(text))

    def test_source_uses_only_platform_or_c_library_headers(self) -> None:
        includes = re.findall(
            r"^#(?:include|import)\s+([<\"].+[>\"])", _read(), re.MULTILINE
        )

        self.assertEqual(includes, ["<Foundation/Foundation.h>", "<stdio.h>"])


class ProbeCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _read()

    def test_exception_feature_guard_tracks_the_compiler_flag(self) -> None:
        self.assertIn("#if defined(__EXCEPTIONS)", self.text)
        self.assertIn(f"#if {_EXCEPTION_GUARD}", self.text)

    def test_probe_covers_all_objective_c_catch_forms(self) -> None:
        for construct in (
            "@catch (ObjCEhProbeError *error)",
            "@catch (NSException *error)",
            "@catch (id error)",
            "@catch (...)",
        ):
            with self.subTest(construct=construct):
                self.assertIn(construct, self.text)

    def test_probe_covers_cleanup_and_runtime_specific_shapes(self) -> None:
        for construct in (
            "@finally",
            "@throw;",
            "@synchronized (lock)",
            "@autoreleasepool",
            "NSString *held =",
            "objc_eh_probe_nested_try",
            "objc_eh_probe_catch_ladder",
        ):
            with self.subTest(construct=construct):
                self.assertIn(construct, self.text)

    def test_probe_defines_and_catches_its_own_exception_class(self) -> None:
        self.assertIn("@interface ObjCEhProbeError : NSException", self.text)
        self.assertIn("@implementation ObjCEhProbeError", self.text)
        self.assertIn('@throw [ObjCEhProbeError exceptionWithName:', self.text)

    def test_mrr_release_paths_are_guarded_by_arc_feature(self) -> None:
        self.assertIn("#if !OBJC_EH_PROBE_ARC", self.text)
        self.assertIn("[held release];", self.text)
        self.assertIn("[lock release];", self.text)

    def test_probe_reports_its_runtime_result(self) -> None:
        self.assertIn(matrix.PROBE_PASS_MARKER, self.text)
        self.assertIn('printf("%s %ld\\n", kPassMarker, total);', self.text)


if __name__ == "__main__":
    unittest.main()
