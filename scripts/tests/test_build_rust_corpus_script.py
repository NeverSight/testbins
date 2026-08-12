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

import rust_matrix  # noqa: E402

BUILD_SCRIPT = SCRIPTS_ROOT / "build_rust_corpus.py"


def _describe(cell: rust_matrix.MatrixCell) -> dict:
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--target",
            cell.target,
            "--panic-strategy",
            cell.panic_strategy,
            "--optimization",
            cell.optimization,
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
    """`--describe-only` resolves a cell without a toolchain, so these run anywhere."""

    def test_every_cell_resolves_to_the_matrix_definition(self) -> None:
        for cell in rust_matrix.expected_cells():
            with self.subTest(cell=cell.key):
                configuration = _describe(cell)

                self.assertEqual(configuration["cell_name"], cell.key)
                self.assertEqual(configuration["runs_on"], cell.runs_on)
                self.assertEqual(configuration["rustc_host"], cell.rustc_host)
                self.assertEqual(configuration["object_format"], cell.object_format)
                self.assertEqual(
                    [entry["crate_name"] for entry in configuration["artifacts"]],
                    list(cell.artifact_names),
                )

    def test_each_cell_describes_exactly_the_contract_the_matrix_defines(self) -> None:
        for cell in rust_matrix.expected_cells():
            configuration = _describe(cell)
            for entry in configuration["artifacts"]:
                crate_name = entry["crate_name"]
                with self.subTest(cell=cell.key, crate=crate_name):
                    self.assertEqual(entry["path"], cell.artifact_path(crate_name))
                    self.assertEqual(
                        entry["evidence"],
                        rust_matrix.evidence_contract(cell, crate_name),
                    )
                    self.assertEqual(
                        entry["neverd"], rust_matrix.neverd_contract(cell, crate_name)
                    )
                    self.assertEqual(
                        entry["rustc_flags"],
                        rust_matrix.rustc_flags(cell, crate_name, "/checkout"),
                    )

    def test_the_cross_linux_cell_names_everything_its_link_needs(self) -> None:
        cell = rust_matrix.validate_cell("aarch64-unknown-linux-gnu", "unwind", "o0")

        configuration = _describe(cell)

        self.assertEqual(configuration["linker"], "aarch64-linux-gnu-gcc")
        # The cross libc is as load-bearing as the compiler: without it the
        # link stops at a missing `Scrt1.o`.
        self.assertEqual(
            configuration["apt_packages"],
            ["gcc-aarch64-linux-gnu", "libc6-dev-arm64-cross"],
        )
        self.assertFalse(configuration["native"])

    def test_rejects_an_unsupported_target_before_touching_a_toolchain(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(BUILD_SCRIPT),
                "--target",
                "riscv64gc-unknown-linux-gnu",
                "--panic-strategy",
                "unwind",
                "--optimization",
                "o0",
                "--output-root",
                "/unused",
                "--describe-only",
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported rust-eh target", completed.stderr)

    def test_rejects_an_unsupported_panic_strategy(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(BUILD_SCRIPT),
                "--target",
                "x86_64-unknown-linux-gnu",
                "--panic-strategy",
                "immediate-abort",
                "--optimization",
                "o0",
                "--output-root",
                "/unused",
                "--describe-only",
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
