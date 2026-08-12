# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import cxx_itanium_matrix as matrix  # noqa: E402

BUILD_SCRIPT = SCRIPTS_ROOT / "build_cxx_itanium_corpus.py"


def _describe(cell: matrix.MatrixCell) -> dict:
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--toolchain",
            cell.toolchain,
            "--target",
            cell.target,
            "--output-root",
            "/unused",
            "--describe-only",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


class BuildScriptConfigurationTests(unittest.TestCase):
    """`--describe-only` resolves a cell without a compiler, so these run anywhere."""

    def test_every_cell_resolves_to_the_matrix_definition(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                configuration = _describe(cell)

                self.assertEqual(configuration["cell_name"], cell.key)
                self.assertEqual(configuration["runs_on"], cell.runs_on)
                self.assertEqual(configuration["object_format"], cell.object_format)
                self.assertEqual(configuration["architecture"], cell.architecture)
                self.assertEqual(configuration["cxx_driver"], cell.cxx_driver)
                self.assertEqual(configuration["c_driver"], cell.c_driver)
                self.assertEqual(configuration["strip_tool"], cell.strip_tool)
                self.assertEqual(len(configuration["artifacts"]), 8)

    def test_each_cell_describes_exactly_the_contract_the_matrix_defines(self) -> None:
        for cell in matrix.expected_cells():
            configuration = _describe(cell)
            described = {entry["path"]: entry for entry in configuration["artifacts"]}
            for variant in cell.variants:
                path = cell.artifact_path(variant)
                with self.subTest(cell=cell.key, variant=variant.key):
                    entry = described[path]
                    self.assertEqual(entry["program"], variant.program)
                    self.assertEqual(entry["execution"], cell.execution(variant))
                    self.assertEqual(entry["source"], variant.source)
                    self.assertEqual(
                        entry["build"],
                        matrix.build_contract(cell, variant, "/checkout"),
                    )
                    self.assertEqual(
                        entry["evidence"], matrix.evidence_contract(cell, variant)
                    )
                    self.assertEqual(
                        entry["neverd"], matrix.neverd_contract(cell, variant)
                    )

    def test_a_shared_object_is_always_described_before_what_links_it(self) -> None:
        for cell in matrix.expected_cells():
            configuration = _describe(cell)
            order = [entry["path"] for entry in configuration["artifacts"]]
            for entry in configuration["artifacts"]:
                for dependency in entry["build"]["linked_artifacts"]:
                    with self.subTest(cell=cell.key, artifact=entry["path"]):
                        self.assertIn(dependency, order)
                        self.assertLess(
                            order.index(dependency), order.index(entry["path"])
                        )

    def test_the_cross_cells_name_everything_their_link_needs(self) -> None:
        configuration = _describe(matrix.validate_cell("gcc", "armv7-linux-gnueabihf"))

        self.assertEqual(configuration["cxx_driver"], "arm-linux-gnueabihf-g++")
        self.assertEqual(configuration["strip_tool"], "arm-linux-gnueabihf-strip")
        self.assertIn("g++-arm-linux-gnueabihf", configuration["apt_packages"])
        self.assertIn("libc6-dev-armhf-cross", configuration["apt_packages"])
        self.assertFalse(configuration["native"])

    def test_the_macos_cells_name_the_xcode_they_are_pinned_to(self) -> None:
        configuration = _describe(matrix.validate_cell("clang", "arm64-apple-darwin"))

        self.assertEqual(configuration["xcode_path"], matrix.MACOS_XCODE_PATH)
        self.assertEqual(configuration["version_prefix"], "17.")
        self.assertTrue(configuration["native"])

    def test_rejects_an_unsupported_target_before_touching_a_compiler(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(BUILD_SCRIPT),
                "--toolchain",
                "gcc",
                "--target",
                "riscv64-linux-gnu",
                "--output-root",
                "/unused",
                "--describe-only",
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported cxx-itanium-eh target", completed.stderr)

    def test_rejects_a_toolchain_that_cannot_build_the_target(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(BUILD_SCRIPT),
                "--toolchain",
                "clang",
                "--target",
                "x86_64-w64-mingw32",
                "--output-root",
                "/unused",
                "--describe-only",
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("does not build", completed.stderr)


if __name__ == "__main__":
    unittest.main()
