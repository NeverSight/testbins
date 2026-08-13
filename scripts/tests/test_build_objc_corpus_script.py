# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import build_objc_corpus as build  # noqa: E402
import objc_matrix as matrix  # noqa: E402

BUILD_SCRIPT = SCRIPTS_ROOT / "build_objc_corpus.py"


def _describe(cell: matrix.MatrixCell) -> dict:
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--runtime",
            cell.runtime,
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
    def test_every_cell_resolves_to_the_matrix_definition(self) -> None:
        for cell in matrix.expected_cells():
            configuration = _describe(cell)
            with self.subTest(cell=cell.key):
                self.assertEqual(configuration["cell_name"], cell.key)
                self.assertEqual(configuration["runtime"], cell.runtime)
                self.assertEqual(configuration["target"], cell.target)
                self.assertEqual(configuration["runs_on"], cell.runs_on)
                self.assertEqual(configuration["architecture"], cell.architecture)
                self.assertEqual(configuration["object_format"], "macho")
                self.assertEqual(configuration["driver"], "clang")
                self.assertEqual(configuration["strip_tool"], "strip")
                self.assertEqual(len(configuration["artifacts"]), 6)

    def test_describe_uses_the_exact_matrix_contracts(self) -> None:
        for cell in matrix.expected_cells():
            described = {
                entry["path"]: entry for entry in _describe(cell)["artifacts"]
            }
            for variant in cell.variants:
                entry = described[cell.artifact_path(variant)]
                with self.subTest(cell=cell.key, variant=variant.key):
                    self.assertEqual(entry["arc"], variant.arc)
                    self.assertEqual(entry["exceptions"], variant.exceptions)
                    self.assertEqual(entry["execution"], cell.execution(variant))
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

    def test_describe_names_the_pinned_xcode(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        configuration = _describe(cell)

        self.assertEqual(configuration["xcode_path"], matrix.MACOS_XCODE_PATH)
        self.assertEqual(configuration["version_prefix"], "17.")
        self.assertTrue(configuration["native"])

    def test_rejects_an_unsupported_runtime_before_invoking_clang(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(BUILD_SCRIPT),
                "--runtime",
                "gnustep",
                "--target",
                "arm64-apple-darwin",
                "--output-root",
                "/unused",
                "--describe-only",
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported objc-eh runtime", completed.stderr)


class ToolchainIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cell = matrix.validate_cell("apple", "arm64-apple-darwin")

    @staticmethod
    def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["clang"], 0, stdout=stdout, stderr="")

    def test_reads_an_exact_apple_clang_version_and_banner(self) -> None:
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/clang"):
            with mock.patch.object(
                build,
                "_run",
                side_effect=[
                    self._completed("17.0.0\n"),
                    self._completed(
                        "Apple clang version 17.0.0 (clang-1700.0.13.5)\n"
                        "Target: arm64-apple-darwin\n"
                    ),
                ],
            ):
                identity = build.read_toolchain_identity(self.cell)

        self.assertEqual(identity["version"], "17.0.0")
        self.assertEqual(
            identity["version_string"],
            "Apple clang version 17.0.0 (clang-1700.0.13.5)",
        )

    def test_rejects_a_non_apple_clang_with_the_same_release(self) -> None:
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/clang"):
            with mock.patch.object(
                build,
                "_run",
                side_effect=[
                    self._completed("17.0.0\n"),
                    self._completed("clang version 17.0.0\n"),
                ],
            ):
                with self.assertRaisesRegex(build.BuildError, "Apple clang"):
                    build.read_toolchain_identity(self.cell)

    def test_rejects_a_banner_that_disagrees_with_dumpversion(self) -> None:
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/clang"):
            with mock.patch.object(
                build,
                "_run",
                side_effect=[
                    self._completed("17.0.0\n"),
                    self._completed("Apple clang version 17.0.1\n"),
                ],
            ):
                with self.assertRaisesRegex(build.BuildError, "banner reports"):
                    build.read_toolchain_identity(self.cell)

    def test_rejects_a_release_outside_the_pin(self) -> None:
        with mock.patch.object(build.shutil, "which", return_value="/usr/bin/clang"):
            with mock.patch.object(
                build, "_run", return_value=self._completed("18.1.0\n")
            ):
                with self.assertRaisesRegex(build.BuildError, "matrix pins"):
                    build.read_toolchain_identity(self.cell)


class ExecutionTests(unittest.TestCase):
    def test_probe_requires_the_pass_marker(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        completed = subprocess.CompletedProcess(
            ["probe"], 0, stdout="quiet success\n", stderr=""
        )
        with mock.patch.object(build.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(build.BuildError, "passing run"):
                build.run_probe(cell, Path("/tmp/probe"))

    def test_build_cell_runs_all_native_variants_and_no_cross_variants(self) -> None:
        def fake_build(
            cell: matrix.MatrixCell, variant: matrix.Variant, root: Path
        ) -> Path:
            path = root / cell.artifact_path(variant)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture")
            return path

        def fake_record(
            cell: matrix.MatrixCell,
            variant: matrix.Variant,
            _path: Path,
            _root: Path,
            _version: str,
            _image: str,
        ) -> dict:
            return {"path": cell.artifact_path(variant)}

        for target, expected_runs in (
            ("arm64-apple-darwin", 6),
            ("x86_64-apple-darwin", 0),
        ):
            cell = matrix.validate_cell("apple", target)
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                with mock.patch.object(
                    build,
                    "read_toolchain_identity",
                    return_value={
                        "version": "17.0.0",
                        "version_string": "Apple clang version 17.0.0",
                    },
                ), mock.patch.object(
                    build, "runner_image", return_value="synthetic-macos"
                ), mock.patch.object(
                    build, "repository_revision", return_value="a" * 40
                ), mock.patch.object(
                    build, "build_artifact", side_effect=fake_build
                ), mock.patch.object(
                    build, "artifact_record", side_effect=fake_record
                ), mock.patch.object(
                    build, "run_probe"
                ) as run_probe:
                    fragment = build.build_cell(cell, Path(temp))

                self.assertTrue(fragment.is_file())
                self.assertEqual(run_probe.call_count, expected_runs)


class AtomicWriteTests(unittest.TestCase):
    def test_failed_fragment_write_preserves_the_previous_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fragment.json"
            path.write_text("old\n", encoding="utf-8")
            with mock.patch.object(build.json, "dump", side_effect=RuntimeError("boom")):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    build._write_json(path, {"new": True})

            self.assertEqual(path.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(list(path.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
