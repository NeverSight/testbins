# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "windows_matrix.py"


def _load_matrix_module():
    spec = importlib.util.spec_from_file_location("windows_matrix", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load windows_matrix.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class WindowsMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = _load_matrix_module()

    def test_matrix_contains_exact_supported_capabilities(self) -> None:
        cells = self.matrix.expected_cells()

        self.assertEqual(len(cells), 36)
        self.assertEqual(len({cell.key for cell in cells}), 36)
        self.assertEqual(
            Counter(cell.toolchain for cell in cells),
            Counter({"msvc": 20, "clang-cl": 16}),
        )
        self.assertEqual(
            Counter(cell.architecture for cell in cells),
            Counter({"x86": 8, "x86_64": 12, "arm": 8, "aarch64": 8}),
        )

        msvc_x64 = {
            cell.cxx_format
            for cell in cells
            if cell.toolchain == "msvc" and cell.architecture == "x86_64"
        }
        clang_x64 = {
            cell.cxx_format
            for cell in cells
            if cell.toolchain == "clang-cl" and cell.architecture == "x86_64"
        }
        non_x64 = {cell.cxx_format for cell in cells if cell.architecture != "x86_64"}
        self.assertEqual(msvc_x64, {"fh3", "fh4"})
        self.assertEqual(clang_x64, {"fh3"})
        self.assertEqual(non_x64, {"native"})

    def test_i386_is_only_an_input_alias(self) -> None:
        self.assertEqual(self.matrix.normalize_architecture("i386"), "x86")
        self.assertEqual(self.matrix.normalize_architecture("x86"), "x86")
        self.assertNotIn(
            "i386", {cell.architecture for cell in self.matrix.expected_cells()}
        )

    def test_execution_and_target_triples_match_architecture(self) -> None:
        expected = {
            "x86": ("i686-pc-windows-msvc", True),
            "x86_64": ("x86_64-pc-windows-msvc", True),
            "arm": ("thumbv7-pc-windows-msvc", False),
            "aarch64": ("aarch64-pc-windows-msvc", False),
        }
        for cell in self.matrix.expected_cells():
            with self.subTest(cell=cell.key):
                triple, execute = expected[cell.architecture]
                self.assertEqual(cell.target_triple, triple)
                self.assertEqual(cell.execute, execute)

    def test_artifact_inventory_matches_toolchain_target_capabilities(self) -> None:
        full_inventory = (
            "xcpt4",
            "nested_collided",
            "xframe_eh_dll",
            "xframe_eh_exe",
            "seh_probe",
            "cxx_eh_probe",
        )
        for cell in self.matrix.expected_cells():
            with self.subTest(cell=cell.key):
                expected = (
                    ("cxx_eh_probe",)
                    if cell.toolchain == "clang-cl" and cell.architecture == "arm"
                    else full_inventory
                )
                self.assertEqual(cell.artifact_names, expected)

    def test_rejects_unsupported_format_combinations(self) -> None:
        invalid = (
            ("clang-cl", "x86_64", "fh4"),
            ("msvc", "x86", "fh3"),
            ("msvc", "arm", "fh4"),
            ("clang-cl", "aarch64", "fh3"),
        )
        for toolchain, architecture, cxx_format in invalid:
            with self.subTest(
                toolchain=toolchain,
                architecture=architecture,
                cxx_format=cxx_format,
            ):
                with self.assertRaises(ValueError):
                    self.matrix.validate_cell(
                        toolchain,
                        architecture,
                        cxx_format,
                        "o0",
                        "off",
                    )

    def test_github_output_is_compact_include_matrix(self) -> None:
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
        self.assertEqual(len(matrix["include"]), 36)
        self.assertEqual(len({entry["cell_name"] for entry in matrix["include"]}), 36)
        self.assertTrue(
            all(entry["architecture"] != "i386" for entry in matrix["include"])
        )


if __name__ == "__main__":
    unittest.main()
