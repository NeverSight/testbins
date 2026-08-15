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

import ada_d_eh_matrix as matrix  # noqa: E402
import build_language_eh_corpus as builder  # noqa: E402

BUILD_SCRIPT = SCRIPTS_ROOT / "build_language_eh_corpus.py"


def _describe(cell: matrix.MatrixCell) -> dict:
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--toolchain",
            cell.toolchain,
            "--target",
            cell.target,
            "--describe-only",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


class BuildScriptConfigurationTests(unittest.TestCase):
    def test_every_cell_resolves_to_the_matrix_definition(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                configuration = _describe(cell)

                self.assertEqual(configuration["cell_name"], cell.key)
                self.assertEqual(configuration["compiler"], cell.compiler)
                self.assertEqual(configuration["dlang_compiler"], cell.dlang_compiler)
                self.assertEqual(configuration["apt_packages"], list(cell.apt_packages))
                self.assertEqual(len(configuration["artifacts"]), 2)

    def test_each_cell_describes_exactly_the_contract_the_matrix_defines(self) -> None:
        for cell in matrix.expected_cells():
            configuration = _describe(cell)
            described = {entry["path"]: entry for entry in configuration["artifacts"]}
            for variant in cell.variants:
                path = cell.artifact_path(variant)
                with self.subTest(cell=cell.key, variant=variant.key):
                    entry = described[path]
                    self.assertEqual(entry["execution"], cell.execution())
                    self.assertEqual(entry["source"], cell.source_path)
                    self.assertEqual(
                        entry["build"],
                        matrix.build_contract(cell, variant, "/checkout"),
                    )
                    self.assertEqual(entry["evidence"], matrix.evidence_contract(cell))
                    self.assertEqual(entry["neverd"], matrix.neverd_contract(cell))


class GnatmakeCommandTests(unittest.TestCase):
    def test_places_source_and_output_before_cargs(self) -> None:
        cell = matrix.validate_cell("gnat", "x86_64-linux-gnu")
        flags = list(
            matrix.compiler_flags(cell, matrix.validate_variant("o0"), "/checkout")
        )
        command = builder.gnatmake_command(
            "gnatmake-13",
            flags,
            "/checkout/sources/ada-d-eh/ada_eh_probe.adb",
            "/out/ada_eh_probe",
        )

        self.assertLess(
            command.index("/checkout/sources/ada-d-eh/ada_eh_probe.adb"),
            command.index("-cargs"),
        )
        self.assertLess(command.index("-o"), command.index("-cargs"))
        self.assertLess(command.index("/out/ada_eh_probe"), command.index("-cargs"))
        self.assertEqual(command[command.index("-cargs") + 1], "-fexceptions")


if __name__ == "__main__":
    unittest.main()
