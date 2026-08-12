# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import cxx_itanium_matrix as matrix  # noqa: E402

SCRIPT_PATH = SCRIPTS_ROOT / "cxx_itanium_matrix.py"


class MatrixShapeTests(unittest.TestCase):
    def test_matrix_is_nine_cells_of_eight_artifacts(self) -> None:
        cells = matrix.expected_cells()

        self.assertEqual(len(cells), 9)
        self.assertEqual(len({cell.key for cell in cells}), 9)
        self.assertEqual(len(matrix.expected_artifact_paths()), 72)
        for cell in cells:
            with self.subTest(cell=cell.key):
                self.assertEqual(len(cell.variants), 8)

    def test_every_artifact_path_is_unique(self) -> None:
        paths = matrix.expected_artifact_paths()

        self.assertEqual(len(set(paths)), len(paths))
        self.assertEqual(list(paths), sorted(paths))

    def test_the_two_producers_split_the_targets_the_way_they_exist(self) -> None:
        by_toolchain: dict[str, set[str]] = {}
        for cell in matrix.expected_cells():
            by_toolchain.setdefault(cell.toolchain, set()).add(cell.target)

        # GCC is the only producer with a mingw-w64 cross, and Apple clang is
        # the only producer of Mach-O.
        self.assertEqual(
            by_toolchain["gcc"],
            {
                "x86_64-linux-gnu",
                "aarch64-linux-gnu",
                "armv7-linux-gnueabihf",
                "x86_64-w64-mingw32",
            },
        )
        self.assertEqual(
            by_toolchain["clang"],
            {
                "x86_64-linux-gnu",
                "aarch64-linux-gnu",
                "armv7-linux-gnueabihf",
                "x86_64-apple-darwin",
                "arm64-apple-darwin",
            },
        )

    def test_object_format_and_architecture_follow_the_target(self) -> None:
        expected = {
            "x86_64-linux-gnu": ("elf", "x86_64", "linux", True),
            "aarch64-linux-gnu": ("elf", "aarch64", "linux", False),
            "armv7-linux-gnueabihf": ("elf", "arm", "linux", False),
            "x86_64-w64-mingw32": ("pe", "x86_64", "linux", False),
            "x86_64-apple-darwin": ("macho", "x86_64", "macos", False),
            "arm64-apple-darwin": ("macho", "aarch64", "macos", True),
        }
        self.assertEqual(set(expected), set(matrix.target_names()))
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                object_format, architecture, runner_os, native = expected[cell.target]
                self.assertEqual(cell.object_format, object_format)
                self.assertEqual(cell.architecture, architecture)
                self.assertEqual(cell.runner_os, runner_os)
                self.assertEqual(cell.native, native)

    def test_each_cell_carries_one_of_every_variant_shape(self) -> None:
        cell = matrix.validate_cell("gcc", "x86_64-linux-gnu")

        programs = Counter(variant.program for variant in cell.variants)
        self.assertEqual(
            programs,
            Counter(
                {
                    "cxx_eh_probe": 4,
                    "cxx_eh_probe_noexc": 1,
                    "libcxx_eh_shared": 2,
                    "c_eh_probe": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(variant.optimization for variant in cell.variants),
            Counter({"o0": 3, "o2": 5}),
        )
        self.assertEqual(
            Counter(variant.stripped for variant in cell.variants),
            Counter({False: 6, True: 2}),
        )

    def test_artifact_paths_repeat_every_axis(self) -> None:
        cell = matrix.validate_cell("gcc", "armv7-linux-gnueabihf")
        probe = matrix.validate_variant("cxx_eh_probe", "o2", True)
        shared = matrix.validate_variant("libcxx_eh_shared", "o0", False)

        self.assertEqual(
            cell.artifact_path(probe),
            "corpus/cxx-itanium-eh/gcc/armv7-linux-gnueabihf/o2/stripped/exe/"
            "cxx_eh_probe-gcc-armv7-linux-gnueabihf-o2-stripped",
        )
        self.assertEqual(
            cell.artifact_path(shared),
            "corpus/cxx-itanium-eh/gcc/armv7-linux-gnueabihf/o0/symtab/shared/"
            "libcxx_eh_shared-gcc-armv7-linux-gnueabihf-o0-symtab.so",
        )

    def test_artifact_extensions_follow_the_object_format(self) -> None:
        expected = {
            ("gcc", "x86_64-linux-gnu"): ("", ".so"),
            ("clang", "arm64-apple-darwin"): ("", ".dylib"),
            ("gcc", "x86_64-w64-mingw32"): (".exe", ".dll"),
        }
        probe = matrix.validate_variant("cxx_eh_probe", "o2", False)
        shared = matrix.validate_variant("libcxx_eh_shared", "o2", False)
        for (toolchain, target), (exe, library) in expected.items():
            with self.subTest(target=target):
                cell = matrix.validate_cell(toolchain, target)
                self.assertEqual(cell.artifact_extension(probe), exe)
                self.assertEqual(cell.artifact_extension(shared), library)

    def test_execution_status_is_honest_about_what_can_run(self) -> None:
        shared = matrix.validate_variant("libcxx_eh_shared", "o2", False)
        probe = matrix.validate_variant("cxx_eh_probe", "o2", False)
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                self.assertEqual(cell.execution(shared), "not-run-library")
                expected = "passed" if cell.native else "not-run-cross-target"
                self.assertEqual(cell.execution(probe), expected)

    def test_rejects_combinations_the_corpus_does_not_build(self) -> None:
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("gcc", "arm64-apple-darwin")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("clang", "x86_64-w64-mingw32")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("msvc", "x86_64-linux-gnu")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("gcc", "riscv64-linux-gnu")

    def test_rejects_variants_outside_the_matrix(self) -> None:
        # A stripped shared object and an -O0 C probe are both spellable and
        # neither is built.
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("libcxx_eh_shared", "o2", True)
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("c_eh_probe", "o0", False)
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("cxx_eh_probe", "o3", False)
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("rust_eh_probe", "o2", False)


class ToolsetTests(unittest.TestCase):
    def test_every_cell_pins_a_release_series(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                self.assertRegex(cell.version_prefix, r"^[0-9]+\.$")

    def test_cross_cells_name_the_libraries_their_link_needs(self) -> None:
        for toolchain in ("gcc", "clang"):
            cell = matrix.validate_cell(toolchain, "aarch64-linux-gnu")
            with self.subTest(toolchain=toolchain):
                # The compiler package alone cannot complete a link: `Scrt1.o`
                # lives in the cross libc, which apt only recommends and the
                # installer does not take recommendations.
                self.assertIn("libc6-dev-arm64-cross", cell.apt_packages)
                self.assertIn("libstdc++-13-dev-arm64-cross", cell.apt_packages)

    def test_clang_cross_cells_borrow_the_gcc_sysroot(self) -> None:
        for target in ("aarch64-linux-gnu", "armv7-linux-gnueabihf"):
            cell = matrix.validate_cell("clang", target)
            with self.subTest(target=target):
                self.assertIn("clang-18", cell.apt_packages)
                self.assertTrue(
                    any(flag.startswith("--target=") for flag in cell.target_flags)
                )
                # Clang finds the cross toolchain under Debian's own triple, so
                # the driver flag has to spell that rather than the ISA.
                self.assertIn(f"--target={cell.gnu_triple}", cell.target_flags)

    def test_both_arm_producers_are_told_the_same_instruction_set(self) -> None:
        for toolchain in ("gcc", "clang"):
            cell = matrix.validate_cell(toolchain, "armv7-linux-gnueabihf")
            with self.subTest(toolchain=toolchain):
                self.assertIn("-march=armv7-a", cell.target_flags)
                self.assertIn("-mfloat-abi=hard", cell.target_flags)

    def test_only_the_macos_cells_pin_an_xcode(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                if cell.runner_os == "macos":
                    self.assertEqual(cell.xcode_path, matrix.MACOS_XCODE_PATH)
                else:
                    self.assertEqual(cell.xcode_path, "")

    def test_the_toolchain_contract_is_recomputable(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                contract = matrix.toolchain_contract(cell)
                self.assertEqual(contract["cell"], cell.key)
                self.assertEqual(contract["cxx_driver"], cell.cxx_driver)
                self.assertEqual(contract["c_driver"], cell.c_driver)
                self.assertEqual(contract["strip_tool"], cell.strip_tool)


class FlagTests(unittest.TestCase):
    def test_every_artifact_remaps_the_build_path(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                with self.subTest(cell=cell.key, variant=variant.key):
                    flags = matrix.compiler_flags(cell, variant, "/checkout")
                    self.assertIn("-ffile-prefix-map=/checkout=/testbins", flags)
                    self.assertIn("-g0", flags)

    def test_the_exception_axis_is_the_only_difference_in_the_control(self) -> None:
        cell = matrix.validate_cell("gcc", "x86_64-linux-gnu")
        probe = matrix.compiler_flags(
            cell, matrix.validate_variant("cxx_eh_probe", "o2", False), "/checkout"
        )
        control = matrix.compiler_flags(
            cell,
            matrix.validate_variant("cxx_eh_probe_noexc", "o2", False),
            "/checkout",
        )

        self.assertEqual(
            [flag for flag in probe if flag != "-fexceptions"],
            [flag for flag in control if flag != "-fno-exceptions"],
        )
        self.assertIn("-fexceptions", probe)
        self.assertIn("-fno-exceptions", control)
        # Without unwind tables the control would have no metadata at all, and
        # `cfi-only` would be a claim about an empty image.
        self.assertIn("-fasynchronous-unwind-tables", control)

    def test_the_c_probe_is_the_only_artifact_that_links_another(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                with self.subTest(cell=cell.key, variant=variant.key):
                    linked = matrix.linked_artifacts(cell, variant)
                    if variant.program == "c_eh_probe":
                        self.assertEqual(len(linked), 1)
                        self.assertIn("libcxx_eh_shared", linked[0])
                        self.assertIn("/o2/", linked[0])
                    else:
                        self.assertEqual(linked, ())

    def test_a_shared_object_is_loaded_by_its_own_corpus_filename(self) -> None:
        shared = matrix.validate_variant("libcxx_eh_shared", "o2", False)
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                flags = matrix.compiler_flags(cell, shared, "/checkout")
                filename = cell.artifact_filename(shared)
                if cell.object_format == "elf":
                    self.assertIn(f"-Wl,-soname,{filename}", flags)
                elif cell.object_format == "macho":
                    self.assertIn(f"@rpath/{filename}", flags)
                else:
                    self.assertIn("-shared", flags)

    def test_the_c_probe_finds_its_library_without_naming_a_build_path(self) -> None:
        probe = matrix.validate_variant("c_eh_probe", "o2", False)
        for cell in matrix.expected_cells():
            if cell.object_format == "pe":
                continue
            with self.subTest(cell=cell.key):
                flags = matrix.compiler_flags(cell, probe, "/checkout")
                anchor = "$ORIGIN" if cell.object_format == "elf" else "@loader_path"
                self.assertIn(f"-Wl,-rpath,{anchor}/../shared", flags)

    def test_the_mingw_cell_links_the_runtime_it_asserts(self) -> None:
        cell = matrix.validate_cell("gcc", "x86_64-w64-mingw32")
        cxx = matrix.compiler_flags(
            cell, matrix.validate_variant("cxx_eh_probe", "o2", False), "/checkout"
        )
        c = matrix.compiler_flags(
            cell, matrix.validate_variant("c_eh_probe", "o2", False), "/checkout"
        )

        self.assertIn("-static-libstdc++", cxx)
        self.assertIn("-static-libgcc", cxx)
        # `-static-libstdc++` is a C++ driver option; the C probe would only
        # get a warning out of it.
        self.assertNotIn("-static-libstdc++", c)
        self.assertIn("-static-libgcc", c)

    def test_the_build_environment_is_pinned(self) -> None:
        environment = matrix.build_environment()

        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["TZ"], "UTC")
        self.assertRegex(environment["SOURCE_DATE_EPOCH"], r"^[0-9]+$")


class EvidenceContractTests(unittest.TestCase):
    def test_arm_claims_ehabi_and_nothing_dwarf(self) -> None:
        for toolchain in ("gcc", "clang"):
            cell = matrix.validate_cell(toolchain, "armv7-linux-gnueabihf")
            for variant in cell.variants:
                with self.subTest(toolchain=toolchain, variant=variant.key):
                    evidence = matrix.evidence_contract(cell, variant)
                    self.assertIn(".ARM.exidx", evidence["required_sections"])
                    self.assertNotIn(".eh_frame", evidence["required_sections"])
                    self.assertNotIn(".gcc_except_table", evidence["required_sections"])
                    self.assertTrue(evidence["arm_exidx_present"])
                    self.assertFalse(evidence["eh_frame_present"])
                    self.assertFalse(evidence["require_unwind_tables"])
                    self.assertGreaterEqual(evidence["min_arm_exidx_entries"], 1)
                    self.assertTrue(
                        matrix.neverd_contract(cell, variant)["expect_arm_ehabi"]
                    )

    def test_arm_carries_an_extab_only_when_it_has_exceptions(self) -> None:
        cell = matrix.validate_cell("gcc", "armv7-linux-gnueabihf")
        throwing = matrix.validate_variant("cxx_eh_probe", "o2", False)
        control = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)

        self.assertIn(".ARM.extab", matrix.required_sections(cell, throwing))
        self.assertNotIn(".ARM.extab", matrix.required_sections(cell, control))

    def test_except_tables_are_only_required_of_throwing_builds(self) -> None:
        throwing = matrix.validate_variant("cxx_eh_probe", "o2", False)
        control = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
        elf = matrix.validate_cell("gcc", "x86_64-linux-gnu")
        macho = matrix.validate_cell("clang", "arm64-apple-darwin")

        self.assertIn(".gcc_except_table", matrix.required_sections(elf, throwing))
        self.assertNotIn(".gcc_except_table", matrix.required_sections(elf, control))
        self.assertIn(
            "__TEXT,__gcc_except_tab", matrix.required_sections(macho, throwing)
        )
        self.assertNotIn(
            "__TEXT,__gcc_except_tab", matrix.required_sections(macho, control)
        )

    def test_the_control_claims_absence_only_where_the_runtime_is_dynamic(self) -> None:
        control = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
        expected = {
            ("gcc", "x86_64-linux-gnu"): ((".gcc_except_table",), ("__cxa_throw",)),
            ("clang", "arm64-apple-darwin"): (
                ("__TEXT,__gcc_except_tab",),
                ("__cxa_throw",),
            ),
            # A static libstdc++ could contribute an except table the flag did
            # not decide, so mingw claims nothing.
            ("gcc", "x86_64-w64-mingw32"): ((), ()),
            # The ARM LSDA lives inside `.ARM.extab`, which the C runtime also
            # writes into, so its presence proves nothing either way.
            ("gcc", "armv7-linux-gnueabihf"): ((), ("__cxa_throw",)),
        }
        for (toolchain, target), (sections, symbols) in expected.items():
            cell = matrix.validate_cell(toolchain, target)
            with self.subTest(cell=cell.key):
                self.assertEqual(matrix.forbidden_sections(cell, control), sections)
                self.assertEqual(matrix.forbidden_symbols(cell, control), symbols)

    def test_a_throwing_build_claims_no_absences_at_all(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                if variant.exceptions == "off":
                    continue
                with self.subTest(cell=cell.key, variant=variant.key):
                    self.assertEqual(matrix.forbidden_sections(cell, variant), ())
                    self.assertEqual(matrix.forbidden_symbols(cell, variant), ())

    def test_mingw_names_the_seh_personalities(self) -> None:
        cell = matrix.validate_cell("gcc", "x86_64-w64-mingw32")
        cxx = matrix.validate_variant("cxx_eh_probe", "o2", False)
        c = matrix.validate_variant("c_eh_probe", "o2", False)

        self.assertIn("__gxx_personality_seh0", matrix.required_symbols(cell, cxx))
        self.assertIn("__gcc_personality_seh0", matrix.required_symbols(cell, c))
        self.assertEqual(
            matrix.personalities_any(cell, cxx), ("__gxx_personality_seh0",)
        )

    def test_the_c_probe_names_the_c_personality_everywhere_else(self) -> None:
        c = matrix.validate_variant("c_eh_probe", "o2", False)
        for cell in matrix.expected_cells():
            if cell.object_format == "pe":
                continue
            with self.subTest(cell=cell.key):
                symbols = matrix.required_symbols(cell, c)
                self.assertIn("__gcc_personality_v0", symbols)
                # A C frame has cleanup actions and no catch, so none of the
                # C++ runtime is referenced.
                self.assertNotIn("__cxa_throw", symbols)
                self.assertNotIn("__cxa_begin_catch", symbols)

    def test_arm_does_not_pin_the_resume_entry_point(self) -> None:
        # EHABI resumes through `__cxa_end_cleanup`, so which name a frame
        # references is a libstdc++ detail rather than a property of the ABI.
        variant = matrix.validate_variant("cxx_eh_probe", "o2", False)
        arm = matrix.validate_cell("gcc", "armv7-linux-gnueabihf")
        aarch64 = matrix.validate_cell("gcc", "aarch64-linux-gnu")

        self.assertNotIn("_Unwind_Resume", matrix.required_symbols(arm, variant))
        self.assertIn("_Unwind_Resume", matrix.required_symbols(aarch64, variant))

    def test_a_stripped_artifact_claims_no_symbols_and_keeps_its_rtti(self) -> None:
        cell = matrix.validate_cell("clang", "x86_64-linux-gnu")
        stripped = matrix.validate_variant("cxx_eh_probe", "o2", True)

        evidence = matrix.evidence_contract(cell, stripped)
        self.assertFalse(evidence["symbol_names_expected"])
        self.assertEqual(evidence["required_symbols"], [])
        self.assertEqual(evidence["required_strings"], ["15CxxEhProbeError"])

    def test_the_mangled_type_names_carry_their_own_length(self) -> None:
        for program, mangled in matrix.TYPE_INFO_STRINGS.items():
            with self.subTest(program=program):
                digits = len(mangled) - len(mangled.lstrip("0123456789"))
                self.assertEqual(int(mangled[:digits]), len(mangled) - digits)

    def test_the_probe_symbol_inventory_splits_on_the_exception_guard(self) -> None:
        full = set(matrix.probe_symbols("cxx_eh_probe"))
        control = set(matrix.probe_symbols("cxx_eh_probe_noexc"))

        self.assertEqual(control, set(matrix.quiet_probe_symbols()))
        self.assertEqual(full - control, set(matrix.throwing_probe_symbols()))
        self.assertTrue(control < full)


class ConsumerContractTests(unittest.TestCase):
    def test_the_validation_level_follows_the_container(self) -> None:
        throwing = matrix.validate_variant("cxx_eh_probe", "o2", False)
        control = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
        expected = {
            ("gcc", "x86_64-linux-gnu"): "lsda-graph",
            ("gcc", "armv7-linux-gnueabihf"): "ehabi",
            ("gcc", "x86_64-w64-mingw32"): "lsda-graph",
            ("clang", "arm64-apple-darwin"): "lsda-graph",
        }
        for (toolchain, target), level in expected.items():
            cell = matrix.validate_cell(toolchain, target)
            with self.subTest(cell=cell.key):
                self.assertEqual(matrix.validation_level(cell, throwing), level)
                self.assertEqual(matrix.validation_level(cell, control), "cfi-only")

    def test_the_control_claims_no_graph_at_all(self) -> None:
        control = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                contract = matrix.neverd_contract(cell, control)
                self.assertTrue(contract["expect_no_lsda"])
                self.assertEqual(contract["personalities_any"], [])
                for key in (
                    "min_call_sites",
                    "min_landing_pads",
                    "min_catch_clauses",
                    "min_cleanup_pads",
                    "min_type_table_entries",
                ):
                    self.assertEqual(contract[key], 0, key)

    def test_a_throwing_artifact_claims_a_floor_on_every_axis(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                if variant.exceptions == "off":
                    continue
                with self.subTest(cell=cell.key, variant=variant.key):
                    contract = matrix.neverd_contract(cell, variant)
                    self.assertFalse(contract["expect_no_lsda"])
                    self.assertGreaterEqual(contract["min_call_sites"], 1)
                    self.assertGreaterEqual(contract["min_landing_pads"], 1)
                    self.assertGreaterEqual(contract["min_cleanup_pads"], 1)

    def test_the_c_probe_claims_cleanups_but_no_type_table(self) -> None:
        cell = matrix.validate_cell("clang", "x86_64-linux-gnu")
        contract = matrix.neverd_contract(
            cell, matrix.validate_variant("c_eh_probe", "o2", False)
        )

        self.assertGreaterEqual(contract["min_cleanup_pads"], 1)
        self.assertEqual(contract["min_catch_clauses"], 0)
        self.assertEqual(contract["min_type_table_entries"], 0)

    def test_arm_admits_the_compact_model_personalities(self) -> None:
        cell = matrix.validate_cell("clang", "armv7-linux-gnueabihf")
        variant = matrix.validate_variant("cxx_eh_probe", "o2", False)

        personalities = matrix.personalities_any(cell, variant)
        self.assertIn("__gxx_personality_v0", personalities)
        self.assertIn("__aeabi_unwind_cpp_pr0", personalities)


class CommandTests(unittest.TestCase):
    def test_github_output_is_a_compact_include_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "github-output.txt"
            subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--github-output", str(output)],
                check=True,
            )
            line = output.read_text(encoding="utf-8").strip()

        name, payload = line.split("=", 1)
        self.assertEqual(name, "matrix")
        include = json.loads(payload)["include"]
        self.assertEqual(len(include), 9)
        self.assertEqual(len({entry["cell_name"] for entry in include}), 9)
        self.assertEqual(
            {entry["runs_on"] for entry in include}, {"ubuntu-24.04", "macos-15"}
        )
        self.assertEqual(sum(entry["artifact_count"] for entry in include), 72)
        self.assertEqual(
            Counter(entry["runs_on"] for entry in include),
            Counter({"ubuntu-24.04": 7, "macos-15": 2}),
        )

    def test_the_plan_lists_every_artifact_with_its_contract(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--plan"],
            check=True,
            capture_output=True,
            text=True,
        )

        plan = json.loads(completed.stdout)
        self.assertEqual(plan["artifact_count"], 72)
        self.assertEqual(len(plan["cells"]), 9)
        for entry in plan["artifacts"]:
            self.assertIn("evidence", entry)
            self.assertIn("neverd", entry)

    def test_paths_prints_the_canonical_inventory(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--paths"],
            check=True,
            capture_output=True,
            text=True,
        )

        printed = completed.stdout.split()
        self.assertEqual(printed, list(matrix.expected_artifact_paths()))

    def test_requires_an_output_mode(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)], capture_output=True, text=True
        )

        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
