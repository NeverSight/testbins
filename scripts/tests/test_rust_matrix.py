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

import rust_matrix  # noqa: E402

SCRIPT_PATH = SCRIPTS_ROOT / "rust_matrix.py"


class RustMatrixShapeTests(unittest.TestCase):
    def test_matrix_is_five_targets_by_two_strategies_by_two_levels(self) -> None:
        cells = rust_matrix.expected_cells()

        self.assertEqual(len(cells), 20)
        self.assertEqual(len({cell.key for cell in cells}), 20)
        self.assertEqual(
            Counter(cell.target for cell in cells),
            Counter({target: 4 for target in rust_matrix.target_names()}),
        )
        self.assertEqual(
            Counter(cell.panic_strategy for cell in cells),
            Counter({"unwind": 10, "abort": 10}),
        )
        self.assertEqual(
            Counter(cell.optimization for cell in cells),
            Counter({"o0": 10, "o2": 10}),
        )

    def test_every_cell_builds_both_crates(self) -> None:
        cells = rust_matrix.expected_cells()
        total = sum(len(cell.artifact_names) for cell in cells)

        self.assertEqual(total, 40)
        for cell in cells:
            with self.subTest(cell=cell.key):
                self.assertEqual(
                    cell.artifact_names, ("rust_eh_probe", "rust_eh_cdylib")
                )

    def test_object_format_and_architecture_follow_the_target(self) -> None:
        expected = {
            "x86_64-unknown-linux-gnu": ("elf", "x86_64", "linux", True),
            "aarch64-unknown-linux-gnu": ("elf", "aarch64", "linux", False),
            "x86_64-pc-windows-msvc": ("pe", "x86_64", "windows", True),
            "x86_64-apple-darwin": ("macho", "x86_64", "macos", False),
            "aarch64-apple-darwin": ("macho", "aarch64", "macos", True),
        }
        self.assertEqual(set(expected), set(rust_matrix.target_names()))
        for cell in rust_matrix.expected_cells():
            with self.subTest(cell=cell.key):
                object_format, architecture, runner_os, native = expected[cell.target]
                self.assertEqual(cell.object_format, object_format)
                self.assertEqual(cell.architecture, architecture)
                self.assertEqual(cell.runner_os, runner_os)
                self.assertEqual(cell.native, native)

    def test_only_cross_built_targets_declare_a_linker(self) -> None:
        for cell in rust_matrix.expected_cells():
            with self.subTest(cell=cell.key):
                if cell.target == "aarch64-unknown-linux-gnu":
                    self.assertEqual(cell.linker, "aarch64-linux-gnu-gcc")
                    # The compiler alone cannot complete a link: `Scrt1.o` and
                    # `crti.o` live in the cross libc, which the compiler
                    # package only recommends and the installer does not take
                    # recommendations.  Both have to be named.
                    self.assertEqual(
                        cell.apt_packages,
                        ("gcc-aarch64-linux-gnu", "libc6-dev-arm64-cross"),
                    )
                else:
                    self.assertEqual(cell.linker, "rustc-default")
                    self.assertEqual(cell.apt_packages, ())

    def test_execution_status_is_honest_about_what_can_run(self) -> None:
        for cell in rust_matrix.expected_cells():
            with self.subTest(cell=cell.key):
                self.assertEqual(cell.execution("rust_eh_cdylib"), "not-run-library")
                expected = "passed" if cell.native else "not-run-cross-target"
                self.assertEqual(cell.execution("rust_eh_probe"), expected)

    def test_artifact_paths_repeat_every_axis(self) -> None:
        cell = rust_matrix.validate_cell("x86_64-pc-windows-msvc", "abort", "o2")

        self.assertEqual(
            cell.artifact_path("rust_eh_probe"),
            "corpus/rust-eh/x86_64-pc-windows-msvc/abort/o2/bin/"
            "rust_eh_probe-x86_64-pc-windows-msvc-abort-o2.exe",
        )
        self.assertEqual(
            cell.artifact_path("rust_eh_cdylib"),
            "corpus/rust-eh/x86_64-pc-windows-msvc/abort/o2/cdylib/"
            "rust_eh_cdylib-x86_64-pc-windows-msvc-abort-o2.dll",
        )

    def test_artifact_extensions_follow_the_object_format(self) -> None:
        expected = {
            "elf": ("", ".so"),
            "macho": ("", ".dylib"),
            "pe": (".exe", ".dll"),
        }
        for object_format, (bin_extension, library_extension) in expected.items():
            with self.subTest(object_format=object_format):
                self.assertEqual(
                    rust_matrix.artifact_extension("rust_eh_probe", object_format),
                    bin_extension,
                )
                self.assertEqual(
                    rust_matrix.artifact_extension("rust_eh_cdylib", object_format),
                    library_extension,
                )

    def test_rejects_unsupported_axes(self) -> None:
        invalid = (
            ("i686-unknown-linux-gnu", "unwind", "o0"),
            ("x86_64-unknown-linux-gnu", "immediate-abort", "o0"),
            ("x86_64-unknown-linux-gnu", "unwind", "o3"),
        )
        for target, panic_strategy, optimization in invalid:
            with self.subTest(target=target, panic=panic_strategy, opt=optimization):
                with self.assertRaises(ValueError):
                    rust_matrix.validate_cell(target, panic_strategy, optimization)


class RustFlagTests(unittest.TestCase):
    def test_flags_carry_every_declared_axis(self) -> None:
        cell = rust_matrix.validate_cell("aarch64-unknown-linux-gnu", "abort", "o2")

        flags = rust_matrix.rustc_flags(cell, "rust_eh_cdylib", "/checkout")

        self.assertIn("--crate-type", flags)
        self.assertEqual(flags[flags.index("--crate-type") + 1], "cdylib")
        self.assertEqual(
            flags[flags.index("--target") + 1], "aarch64-unknown-linux-gnu"
        )
        self.assertIn("opt-level=2", flags)
        self.assertIn("panic=abort", flags)
        self.assertIn("linker=aarch64-linux-gnu-gcc", flags)

    def test_overflow_checks_are_forced_at_every_optimization_level(self) -> None:
        for optimization in ("o0", "o2"):
            with self.subTest(optimization=optimization):
                cell = rust_matrix.validate_cell(
                    "x86_64-unknown-linux-gnu", "unwind", optimization
                )
                flags = rust_matrix.rustc_flags(cell, "rust_eh_probe", "/checkout")
                self.assertIn("overflow-checks=on", flags)

    def test_every_cell_remaps_the_build_path(self) -> None:
        for cell in rust_matrix.expected_cells():
            for crate_name in cell.artifact_names:
                with self.subTest(cell=cell.key, crate=crate_name):
                    flags = rust_matrix.rustc_flags(cell, crate_name, "/checkout")
                    index = flags.index("--remap-path-prefix")
                    self.assertEqual(flags[index + 1], "/checkout=/testbins")

    def test_native_cells_do_not_override_the_linker(self) -> None:
        cell = rust_matrix.validate_cell("x86_64-apple-darwin", "unwind", "o0")

        flags = rust_matrix.rustc_flags(cell, "rust_eh_probe", "/checkout")

        self.assertFalse(any(flag.startswith("linker=") for flag in flags))


class RustContractTests(unittest.TestCase):
    def test_aborting_cells_claim_no_landing_pads_for_their_own_frames(self) -> None:
        for cell in rust_matrix.expected_cells():
            if cell.panic_strategy != "abort":
                continue
            for crate_name in cell.artifact_names:
                with self.subTest(cell=cell.key, crate=crate_name):
                    contract = rust_matrix.neverd_contract(cell, crate_name)
                    self.assertTrue(contract["expect_no_landing_pads"])
                    self.assertEqual(contract["validation_level"], "unwind-only")
                    self.assertEqual(
                        contract["landing_pad_free_symbols"],
                        list(rust_matrix.probe_symbols(crate_name)),
                    )
                    for key in (
                        "min_landing_pads",
                        "min_drop_glue_pads",
                        "min_catch_unwind_pads",
                        "min_nounwind_guard_pads",
                        "min_panic_sites",
                    ):
                        self.assertEqual(contract[key], 0, key)

    def test_unwinding_itanium_cells_require_every_classification(self) -> None:
        for cell in rust_matrix.expected_cells():
            if cell.panic_strategy != "unwind" or cell.object_format == "pe":
                continue
            for crate_name in cell.artifact_names:
                with self.subTest(cell=cell.key, crate=crate_name):
                    contract = rust_matrix.neverd_contract(cell, crate_name)
                    self.assertEqual(contract["validation_level"], "panic-graph")
                    self.assertFalse(contract["expect_no_landing_pads"])
                    for key in (
                        "min_landing_pads",
                        "min_drop_glue_pads",
                        "min_catch_unwind_pads",
                        "min_nounwind_guard_pads",
                        "min_panic_sites",
                    ):
                        self.assertGreaterEqual(contract[key], 1, key)

    def test_msvc_claims_only_what_the_rust_panic_descriptor_proves(self) -> None:
        cell = rust_matrix.validate_cell("x86_64-pc-windows-msvc", "unwind", "o2")

        contract = rust_matrix.neverd_contract(cell, "rust_eh_probe")

        self.assertEqual(contract["personalities_any"], ["__CxxFrameHandler3"])
        self.assertGreaterEqual(contract["min_catch_unwind_pads"], 1)
        self.assertEqual(contract["min_drop_glue_pads"], 0)
        self.assertEqual(contract["min_nounwind_guard_pads"], 0)
        self.assertEqual(contract["min_panic_sites"], 0)

    def test_unwinder_entry_point_is_the_only_absence_claimed(self) -> None:
        for cell in rust_matrix.expected_cells():
            for crate_name in cell.artifact_names:
                with self.subTest(cell=cell.key, crate=crate_name):
                    forbidden = rust_matrix.forbidden_symbols(cell, crate_name)
                    if cell.panic_strategy == "abort" and cell.object_format != "pe":
                        self.assertEqual(forbidden, ("_Unwind_RaiseException",))
                    else:
                        self.assertEqual(forbidden, ())

    def test_pe_executables_promise_no_symbol_names_but_libraries_do(self) -> None:
        cell = rust_matrix.validate_cell("x86_64-pc-windows-msvc", "unwind", "o0")

        self.assertFalse(rust_matrix.symbol_names_expected("pe", "rust_eh_probe"))
        self.assertEqual(rust_matrix.required_symbols(cell, "rust_eh_probe"), ())
        self.assertTrue(rust_matrix.symbol_names_expected("pe", "rust_eh_cdylib"))
        self.assertEqual(
            rust_matrix.required_symbols(cell, "rust_eh_cdylib"),
            tuple(sorted(rust_matrix.probe_symbols("rust_eh_cdylib"))),
        )

    def test_msvc_unwinding_images_must_carry_the_rust_panic_descriptor(self) -> None:
        unwinding = rust_matrix.validate_cell("x86_64-pc-windows-msvc", "unwind", "o0")
        aborting = rust_matrix.validate_cell("x86_64-pc-windows-msvc", "abort", "o0")

        self.assertEqual(
            rust_matrix.required_strings(unwinding, "rust_eh_probe"), ("rust_panic",)
        )
        self.assertEqual(rust_matrix.required_strings(aborting, "rust_eh_probe"), ())

    def test_except_tables_are_only_required_of_unwinding_builds(self) -> None:
        self.assertIn(
            ".gcc_except_table", rust_matrix.required_sections("elf", "unwind")
        )
        self.assertNotIn(
            ".gcc_except_table", rust_matrix.required_sections("elf", "abort")
        )
        self.assertIn(
            "__gcc_except_tab", rust_matrix.required_sections("macho", "unwind")
        )
        self.assertNotIn(
            "__gcc_except_tab", rust_matrix.required_sections("macho", "abort")
        )


class RustMatrixCommandTests(unittest.TestCase):
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
        matrix = json.loads(payload)
        self.assertEqual(len(matrix["include"]), 20)
        self.assertEqual(len({entry["cell_name"] for entry in matrix["include"]}), 20)
        self.assertEqual(
            {entry["runs_on"] for entry in matrix["include"]},
            {"ubuntu-24.04", "windows-2022", "macos-15"},
        )

    def test_requires_an_output_mode(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)], capture_output=True, text=True
        )

        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
