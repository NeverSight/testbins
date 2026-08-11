# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_ROOT = Path(__file__).parents[1]
MATRIX_PATH = SCRIPTS_ROOT / "windows_matrix.py"
BUILD_SCRIPT = SCRIPTS_ROOT / "Build-WindowsCorpus.ps1"

spec = importlib.util.spec_from_file_location("windows_matrix", MATRIX_PATH)
assert spec is not None and spec.loader is not None
MATRIX = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = MATRIX
spec.loader.exec_module(MATRIX)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class BuildWindowsCorpusScriptTests(unittest.TestCase):
    def _configuration(self, cell) -> dict:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(BUILD_SCRIPT),
                    "-Toolchain",
                    cell.toolchain,
                    "-Architecture",
                    cell.architecture,
                    "-Optimization",
                    cell.optimization,
                    "-SecurityCookie",
                    cell.security_cookie,
                    "-CxxFormat",
                    cell.cxx_format,
                    "-OutputRoot",
                    temp_dir,
                    "-ValidateConfigurationOnly",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        return json.loads(result.stdout)

    def test_all_capability_cells_validate_without_windows_tools(self) -> None:
        for cell in MATRIX.expected_cells():
            with self.subTest(cell=cell.key):
                configuration = self._configuration(cell)
                self.assertEqual(configuration["cell_name"], cell.key)
                self.assertEqual(configuration["target_triple"], cell.target_triple)
                self.assertEqual(configuration["execute"], cell.execute)

    def test_msvc_x64_fh_controls_are_explicit(self) -> None:
        for cxx_format, expected_flag in (("fh3", "/d2FH4-"), ("fh4", "/d2FH4")):
            cell = MATRIX.validate_cell("msvc", "x86_64", cxx_format, "o0", "off")
            configuration = self._configuration(cell)

            self.assertEqual(configuration["compiler"], "cl.exe")
            self.assertEqual(configuration["linker"], "link.exe")
            self.assertEqual(configuration["cxx_format_flag"], expected_flag)

    def test_clang_cl_uses_explicit_target_and_lld_link(self) -> None:
        cell = MATRIX.validate_cell("clang-cl", "aarch64", "native", "o2", "on")
        configuration = self._configuration(cell)

        self.assertEqual(configuration["compiler"], "clang-cl.exe")
        self.assertEqual(configuration["linker"], "lld-link.exe")
        self.assertIn(
            "--target=aarch64-pc-windows-msvc",
            configuration["common_compiler_flags"],
        )
        self.assertIn("/MACHINE:ARM64", configuration["common_linker_flags"])
        self.assertIsNone(configuration["cxx_format_flag"])

    def test_configuration_advertises_only_buildable_artifacts(self) -> None:
        for cell in (
            MATRIX.validate_cell("msvc", "arm", "native", "o0", "off"),
            MATRIX.validate_cell("clang-cl", "x86", "native", "o0", "off"),
            MATRIX.validate_cell("clang-cl", "aarch64", "native", "o0", "off"),
        ):
            with self.subTest(cell=cell.key):
                configuration = self._configuration(cell)
                self.assertEqual(
                    configuration["artifact_names"], list(cell.artifact_names)
                )

    def test_clang_cl_uses_upstream_xcpt4_skip_profile(self) -> None:
        msvc = self._configuration(
            MATRIX.validate_cell("msvc", "x86_64", "fh3", "o0", "off")
        )
        clang_cl = self._configuration(
            MATRIX.validate_cell("clang-cl", "x86_64", "fh3", "o0", "off")
        )

        self.assertEqual(msvc["xcpt4_compiler_flags"], ["/DBAIL_IN_FINALLY"])
        self.assertEqual(clang_cl["xcpt4_compiler_flags"], [])
        self.assertEqual(
            msvc["xcpt4_additional_compiler_flags"],
            ["/DBAIL_IN_FINALLY", "/EHa", "/d2FH4-"],
        )

    def test_msvc_gs_seh_contract_accepts_both_valid_handlers(self) -> None:
        configuration = self._configuration(
            MATRIX.validate_cell("msvc", "x86_64", "fh4", "o2", "on")
        )

        self.assertEqual(
            configuration["seh_personalities"],
            ["__C_specific_handler", "__GSHandlerCheck_SEH"],
        )
        self.assertNotIn("gs_security_evidence", configuration)

    def test_rejects_clang_cl_fh4_before_importing_visual_studio(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(BUILD_SCRIPT),
                    "-Toolchain",
                    "clang-cl",
                    "-Architecture",
                    "x86_64",
                    "-Optimization",
                    "o0",
                    "-SecurityCookie",
                    "off",
                    "-CxxFormat",
                    "fh4",
                    "-OutputRoot",
                    temp_dir,
                    "-ValidateConfigurationOnly",
                ],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported C++ EH format", result.stderr)

    def test_rejects_clang_cl_arm32_before_importing_visual_studio(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-File",
                    str(BUILD_SCRIPT),
                    "-Toolchain",
                    "clang-cl",
                    "-Architecture",
                    "arm",
                    "-Optimization",
                    "o0",
                    "-SecurityCookie",
                    "off",
                    "-CxxFormat",
                    "native",
                    "-OutputRoot",
                    temp_dir,
                    "-ValidateConfigurationOnly",
                ],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported C++ EH format", result.stderr)


if __name__ == "__main__":
    unittest.main()
