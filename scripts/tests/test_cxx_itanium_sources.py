# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import re
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import cxx_itanium_matrix as matrix  # noqa: E402

REPOSITORY_ROOT = SCRIPTS_ROOT.parent
SOURCE_ROOT = REPOSITORY_ROOT / matrix.SOURCE_ROOT

# A corpus entry point is spelled one of two ways: with the attribute written
# out, or through the shared library's macro, which expands to the same thing
# plus the export marker.
_ENTRY_MARKERS = ("__attribute__((noinline))", "CXX_EH_SHARED_ENTRY")
_CALLABLE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_NOT_A_NAME = frozenset({"__attribute__", "noinline", "visibility", "__declspec"})
_EXCEPTION_GUARD = "CXX_EH_PROBE_EXCEPTIONS"


def _read(name: str) -> str:
    return (SOURCE_ROOT / name).read_text(encoding="utf-8")


def _entry_points(text: str) -> dict[str, bool]:
    """Map every entry point the source defines to whether it is guarded.

    "Guarded" means the definition sits inside `#if CXX_EH_PROBE_EXCEPTIONS`,
    which is the line between what an exception-free build still has and what
    only exists when the compiler was allowed to throw.
    """

    definitions: dict[str, bool] = {}
    conditionals: list[bool] = []
    in_directive = False
    for line in text.splitlines():
        stripped = line.strip()
        was_directive = in_directive
        in_directive = (
            stripped.startswith("#") or was_directive
        ) and stripped.endswith("\\")
        if stripped.startswith("#if"):
            conditionals.append(_EXCEPTION_GUARD in stripped)
            continue
        if stripped.startswith("#endif"):
            if conditionals:
                conditionals.pop()
            continue
        # The macro that spells an entry point is not itself one.
        if stripped.startswith("#") or was_directive:
            continue
        if not any(marker in line for marker in _ENTRY_MARKERS):
            continue
        names = [name for name in _CALLABLE_RE.findall(line) if name not in _NOT_A_NAME]
        if not names:
            continue
        definitions[names[-1]] = any(conditionals)
    return definitions


class SourceInventoryTests(unittest.TestCase):
    def test_every_program_source_exists_where_the_matrix_says(self) -> None:
        for program in matrix.program_names():
            with self.subTest(program=program):
                path = REPOSITORY_ROOT / matrix.program_source(program)
                self.assertTrue(path.is_file(), path)

    def test_the_corpus_is_three_sources_and_no_build_system(self) -> None:
        sources = sorted(
            path.name for path in SOURCE_ROOT.iterdir() if path.suffix != ".md"
        )

        self.assertEqual(
            sources, ["c_eh_probe.c", "cxx_eh_probe.cpp", "cxx_eh_shared.cpp"]
        )
        self.assertEqual(list(SOURCE_ROOT.rglob("CMakeLists.txt")), [])
        self.assertEqual(list(SOURCE_ROOT.rglob("Makefile")), [])

    def test_declared_probe_symbols_match_the_probe_source(self) -> None:
        defined = _entry_points(_read("cxx_eh_probe.cpp"))

        self.assertEqual(sorted(defined), sorted(matrix.probe_symbols("cxx_eh_probe")))

    def test_the_exception_guard_is_what_splits_the_two_probe_inventories(
        self,
    ) -> None:
        defined = _entry_points(_read("cxx_eh_probe.cpp"))

        unguarded = sorted(name for name, guarded in defined.items() if not guarded)
        guarded = sorted(name for name, guarded in defined.items() if guarded)
        self.assertEqual(unguarded, list(matrix.quiet_probe_symbols()))
        self.assertEqual(guarded, list(matrix.throwing_probe_symbols()))
        # The exception-free build is the same source, so the entry points it
        # keeps are exactly the ones outside the guard.
        self.assertEqual(unguarded, list(matrix.probe_symbols("cxx_eh_probe_noexc")))

    def test_declared_library_and_c_symbols_match_their_sources(self) -> None:
        for program, source in (
            ("libcxx_eh_shared", "cxx_eh_shared.cpp"),
            ("c_eh_probe", "c_eh_probe.c"),
        ):
            with self.subTest(program=program):
                self.assertEqual(
                    sorted(_entry_points(_read(source))),
                    sorted(matrix.probe_symbols(program)),
                )

    def test_every_entry_point_survives_optimization(self) -> None:
        for source in ("cxx_eh_probe.cpp", "cxx_eh_shared.cpp", "c_eh_probe.c"):
            text = _read(source)
            with self.subTest(source=source):
                # Nothing declares itself an entry point without also declaring
                # that the optimizer may not fold it into a neighbour.
                self.assertIn("__attribute__((noinline))", text)
                self.assertTrue(_entry_points(text))

    def test_the_sources_have_no_third_party_includes(self) -> None:
        for path in sorted(SOURCE_ROOT.iterdir()):
            if path.suffix not in (".c", ".cpp"):
                continue
            with self.subTest(source=path.name):
                for include in re.findall(
                    r'^#include\s+([<"].+[>"])',
                    path.read_text(encoding="utf-8"),
                    re.MULTILINE,
                ):
                    self.assertTrue(
                        include.startswith("<"),
                        f"{path.name} includes {include}, which is not a system header",
                    )


class ProbeCoverageTests(unittest.TestCase):
    """The probe has to keep producing every shape the manifest claims."""

    def setUp(self) -> None:
        self.text = _read("cxx_eh_probe.cpp")

    def test_the_probe_covers_every_catch_form(self) -> None:
        for construct in (
            "catch (int caught)",
            "catch (const CxxEhProbeError &caught)",
            "catch (CxxEhProbeError *caught)",
            "catch (...)",
            "catch (const std::exception &)",
        ):
            with self.subTest(construct=construct):
                self.assertIn(construct, self.text)

    def test_the_probe_covers_every_throw_form(self) -> None:
        for construct in (
            "throw CxxEhProbeError(",
            "throw static_cast<int>(",
            "throw std::runtime_error(",
            "throw CxxEhProbeDerivedError(",
            "throw CxxEhProbeVirtualDiamond(",
            "throw &g_pointer_exception",
            # A bare rethrow is `__cxa_rethrow`, not a second `__cxa_throw`.
            "      throw;",
        ):
            with self.subTest(construct=construct):
                self.assertIn(construct, self.text)

    def test_the_probe_covers_the_shapes_that_are_not_catches(self) -> None:
        for construct in (
            # A terminate landing pad rather than a catch.
            "noexcept {",
            # A guard variable whose initializer can throw.
            "static GuardedInitializer once(",
            # Virtual inheritance, where the runtime adjusts by a lookup.
            "virtual CxxEhProbeVirtualBase",
            # Cleanup of a whole array while unwinding.
            "CleanupCounter batch[4]",
            "std::function<long(long)>",
        ):
            with self.subTest(construct=construct):
                self.assertIn(construct, self.text)

    def test_the_probe_never_throws_when_it_cannot(self) -> None:
        self.assertIn("#if defined(__cpp_exceptions) && __cpp_exceptions", self.text)
        self.assertIn(f"#if {_EXCEPTION_GUARD}", self.text)
        # Everything that raises is behind the guard, including the exception
        # types themselves, so the control has no RTTI to give it away either.
        guarded, _ = self.text.split(f"#endif  // {_EXCEPTION_GUARD}", 1)
        _, guarded = guarded.split(f"#if {_EXCEPTION_GUARD}", 2)[-2:]
        self.assertIn("struct CxxEhProbeError", guarded)

    def test_the_probe_reports_its_own_runtime_result(self) -> None:
        self.assertIn(matrix.PROBE_PASS_MARKER, self.text)


class SharedLibraryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _read("cxx_eh_shared.cpp")

    def test_one_export_macro_covers_all_three_object_formats(self) -> None:
        self.assertIn("#define CXX_EH_SHARED_API __declspec(dllexport)", self.text)
        self.assertIn(
            '#define CXX_EH_SHARED_API __attribute__((visibility("default")))',
            self.text,
        )
        # Hiding the exception type's RTTI is what stops a catch in another
        # object from matching it, so no cell may narrow visibility.
        shared = matrix.validate_variant("libcxx_eh_shared", "o2", False)
        for cell in matrix.expected_cells():
            self.assertNotIn(
                "-fvisibility=hidden",
                matrix.compiler_flags(cell, shared, "/checkout"),
                cell.key,
            )

    def test_the_library_both_raises_out_of_itself_and_catches_inside(self) -> None:
        self.assertIn("cxx_eh_shared_raise", self.text)
        self.assertIn("cxx_eh_shared_catch", self.text)
        self.assertIn("catch (const CxxEhSharedError &caught)", self.text)
        # The call-back entry is what lets an exception cross a C frame.
        self.assertIn("cxx_eh_shared_call_and_catch", self.text)


class CProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _read("c_eh_probe.c")

    def test_the_c_frames_carry_cleanup_attributes(self) -> None:
        self.assertIn("__attribute__((cleanup(c_eh_note)))", self.text)
        self.assertGreaterEqual(self.text.count("cleanup(c_eh_note)"), 3)

    def test_the_c_probe_lets_a_cxx_exception_cross_its_frame(self) -> None:
        self.assertIn("cxx_eh_shared_call_and_catch", self.text)
        self.assertIn("cxx_eh_shared_raise", self.text)
        self.assertIn("#define CXX_EH_SHARED_IMPORT __declspec(dllimport)", self.text)

    def test_the_c_probe_reports_its_own_runtime_result(self) -> None:
        self.assertIn(matrix.PROBE_PASS_MARKER, self.text)


class ContractStringTests(unittest.TestCase):
    def test_each_mangled_type_name_matches_a_class_in_its_source(self) -> None:
        expected = {
            "cxx_eh_probe": "cxx_eh_probe.cpp",
            "libcxx_eh_shared": "cxx_eh_shared.cpp",
        }
        for program, source in expected.items():
            mangled = matrix.TYPE_INFO_STRINGS[program]
            with self.subTest(program=program):
                digits = len(mangled) - len(mangled.lstrip("0123456789"))
                class_name = mangled[digits:]
                self.assertEqual(int(mangled[:digits]), len(class_name))
                self.assertIn(f"struct {class_name} {{", _read(source))


if __name__ == "__main__":
    unittest.main()
