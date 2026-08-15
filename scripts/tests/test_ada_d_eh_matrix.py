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

import ada_d_eh_matrix as matrix  # noqa: E402

SCRIPT_PATH = SCRIPTS_ROOT / "ada_d_eh_matrix.py"


class AdaDEHMatrixTests(unittest.TestCase):
    def test_matrix_has_six_cells_and_twelve_unique_artifacts(self) -> None:
        cells = matrix.expected_cells()
        paths = matrix.expected_artifact_paths()

        self.assertEqual(len(cells), 6)
        self.assertEqual(len({cell.key for cell in cells}), 6)
        self.assertEqual(len(paths), 12)
        self.assertEqual(len(set(paths)), 12)
        self.assertEqual(list(paths), sorted(paths))
        self.assertTrue(all(len(cell.variants) == 2 for cell in cells))

    def test_matrix_proves_ada_and_all_three_d_personalities(self) -> None:
        personalities = Counter(cell.personality for cell in matrix.expected_cells())

        self.assertEqual(personalities["__gnat_personality_v0"], 2)
        self.assertEqual(personalities["__gdc_personality_v0"], 2)
        self.assertEqual(personalities["__dmd_personality_v0"], 1)
        self.assertEqual(personalities["_d_eh_personality"], 1)

    def test_gcc_frontends_cover_x86_64_and_aarch64(self) -> None:
        for toolchain in ("gnat", "gdc"):
            targets = {
                cell.target
                for cell in matrix.expected_cells()
                if cell.toolchain == toolchain
            }
            self.assertEqual(
                targets, {"x86_64-linux-gnu", "aarch64-linux-gnu"}
            )

    def test_descriptor_abis_are_not_cxx_rtti(self) -> None:
        for cell in matrix.expected_cells():
            contract = matrix.neverd_contract(cell)
            with self.subTest(cell=cell.key):
                self.assertEqual(
                    contract["type_table_interpretation"], "opaque-descriptor"
                )
                self.assertEqual(
                    contract["native_reconstruction"], "address-clauses"
                )
                expected = (
                    "gnat-exception-id" if cell.language == "ada" else "d-classinfo"
                )
                self.assertEqual(contract["descriptor_abi"], expected)
                self.assertNotIn("type_info", str(contract))

    def test_every_cell_pins_its_install_and_release(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                self.assertTrue(cell.version_prefix)
                if cell.toolchain in {"dmd", "ldc"}:
                    self.assertTrue(cell.dlang_compiler)
                    self.assertEqual(cell.apt_packages, ())
                else:
                    self.assertFalse(cell.dlang_compiler)
                    self.assertTrue(cell.apt_packages)

    def test_cross_cells_install_target_runtime(self) -> None:
        gnat = matrix.validate_cell("gnat", "aarch64-linux-gnu")
        gdc = matrix.validate_cell("gdc", "aarch64-linux-gnu")

        self.assertIn("libc6-dev-arm64-cross", gnat.apt_packages)
        self.assertIn("libgnat-13-arm64-cross", gnat.apt_packages)
        self.assertIn("libc6-dev-arm64-cross", gdc.apt_packages)
        self.assertIn("libgphobos-13-dev-arm64-cross", gdc.apt_packages)
        self.assertFalse(gnat.native)
        self.assertFalse(gdc.native)

    def test_flags_remap_gcc_paths_and_keep_d_sources_relative(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                flags = matrix.compiler_flags(cell, variant, "/checkout")
                with self.subTest(cell=cell.key, variant=variant.key):
                    if cell.toolchain in {"gnat", "gdc"}:
                        self.assertIn(
                            "-ffile-prefix-map=/checkout=/testbins", flags
                        )
                        self.assertIn("-g0", flags)
                    else:
                        self.assertFalse(
                            any(flag.startswith("-ffile-prefix-map=") for flag in flags)
                        )
                        self.assertEqual(
                            matrix.build_contract(cell, variant, "/checkout")[
                                "path_strategy"
                            ],
                            "relative-source-no-debug",
                        )

    def test_rejects_unsupported_cells_and_variants(self) -> None:
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("dmd", "aarch64-linux-gnu")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("clang", "x86_64-linux-gnu")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("o3")

    def test_gnat_passes_gcc_flags_through_cargs(self) -> None:
        cell = matrix.validate_cell("gnat", "x86_64-linux-gnu")
        flags = matrix.compiler_flags(cell, matrix.validate_variant("o0"), "/checkout")

        self.assertEqual(flags[0], "-q")
        self.assertIn("-cargs", flags)
        self.assertGreater(flags.index("-cargs"), flags.index("-gnat2022"))
        self.assertGreater(flags.index("-fexceptions"), flags.index("-cargs"))


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
        self.assertEqual(len(include), 6)
        self.assertEqual({entry["runs_on"] for entry in include}, {"ubuntu-24.04"})
        self.assertEqual(
            {entry["cell_name"] for entry in include},
            {cell.key for cell in matrix.expected_cells()},
        )

    def test_the_plan_lists_every_artifact_with_its_contract(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--plan"],
            check=True,
            capture_output=True,
            text=True,
        )

        plan = json.loads(completed.stdout)
        self.assertEqual(plan["artifact_count"], 12)
        self.assertEqual(len(plan["cells"]), 6)
        for entry in plan["artifacts"]:
            self.assertEqual(entry["neverd"]["type_table_interpretation"], "opaque-descriptor")
            self.assertEqual(entry["neverd"]["native_reconstruction"], "address-clauses")

    def test_paths_prints_the_canonical_inventory(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--paths"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            completed.stdout.split(), list(matrix.expected_artifact_paths())
        )

    def test_requires_an_output_mode(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)], capture_output=True, text=True
        )

        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
