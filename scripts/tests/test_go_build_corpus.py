# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""The cell builder plans exactly what the matrix and the verifier expect.

These tests never invoke a Go toolchain.  What they check is the part of the
builder that has to agree with two other files -- the axes it turns into
`go build` arguments and the structural expectations it writes into a fragment
-- because a disagreement there is a corpus that builds and then fails
verification an hour later in CI.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MATRIX = _load("go_matrix", SCRIPTS_ROOT / "go_matrix.py")
VERIFY = _load("verify_go_corpus", SCRIPTS_ROOT / "verify_go_corpus.py")
BUILD = _load("build_go_corpus", SCRIPTS_ROOT / "build_go_corpus.py")


class GoBuildCorpusTests(unittest.TestCase):
    def test_builder_and_verifier_agree_on_every_structural_expectation(self) -> None:
        for variant in MATRIX.expected_variants():
            with self.subTest(variant=variant.key):
                self.assertEqual(
                    BUILD._expected_required_sections(variant),
                    VERIFY._expected_required_sections(variant),
                )
                self.assertEqual(
                    BUILD._pclntab_location(variant),
                    VERIFY._expected_pclntab_section(variant),
                )

    def test_the_pclntab_is_looked_for_where_each_linker_puts_it(self) -> None:
        # `relro_pclntab` is what splits the two position-independent rows:
        # CL 718065 moved the table out of the relro segment for Go 1.26, so
        # the name a PIE gets depends on the release and not only on the
        # buildmode.  Reading a 1.26 image at the older name finds nothing.
        cases = {
            ("linux", "exe", True): (".gopclntab", True),
            ("linux", "exe", False): (".gopclntab", True),
            ("linux", "pie", True): (".data.rel.ro.gopclntab", True),
            ("linux", "pie", False): (".gopclntab", True),
            ("linux", "c-shared", True): (".data.rel.ro.gopclntab", True),
            ("linux", "c-shared", False): (".gopclntab", True),
            ("darwin", "exe", True): ("__gopclntab", True),
            # The PE linker gives the table no section, so it has to be found
            # by scanning the read-only data it was folded into.
            ("windows", "exe", True): (".rdata", False),
        }
        for (goos, buildmode, relro), expected in cases.items():
            version = "1.20.14" if relro else "1.26.5"
            with self.subTest(goos=goos, buildmode=buildmode, go=version):
                variant = MATRIX.validate_variant(
                    version,
                    goos,
                    "arm64" if goos == "darwin" else "amd64",
                    buildmode,
                    buildmode == "c-shared",
                    True,
                    "default",
                )
                self.assertEqual(variant.release.relro_pclntab, relro)
                self.assertEqual(BUILD._pclntab_location(variant), expected)

    def test_the_declared_floors_are_below_what_the_probe_produces(self) -> None:
        """`eh_probe` has eleven recover sites and thirteen open-coded frames.

        The floors exist to catch a decoder that recovered nothing, so they sit
        well under the real counts and must never drift above them.
        """

        self.assertLessEqual(BUILD._MIN_RECOVER_SITES, 11)
        self.assertLessEqual(BUILD._MIN_OPEN_CODED_DEFER_FUNCS, 13)
        self.assertLessEqual(BUILD._MIN_DEFER_SITES, 10)
        self.assertGreaterEqual(BUILD._MIN_GO_FUNCTIONS, 1)
        self.assertGreaterEqual(BUILD._MIN_PANIC_SITES, 1)

    def test_the_environment_hides_the_runner_from_the_toolchain(self) -> None:
        environment = BUILD._base_environment()
        self.assertEqual(environment["GOFLAGS"], "")
        self.assertEqual(environment["GOPROXY"], "off")
        self.assertEqual(environment["GOTOOLCHAIN"], "local")
        self.assertEqual(environment["GOWORK"], "off")
        self.assertNotIn("GOOS", environment)
        self.assertNotIn("GOARCH", environment)

    def test_the_module_directive_is_low_enough_for_every_pinned_toolchain(
        self,
    ) -> None:
        directive = BUILD._module_go_directive()
        major, minor = (int(part) for part in directive.split("."))
        for version in MATRIX.pinned_go_versions():
            with self.subTest(version=version):
                parts = [int(part) for part in version.split(".")]
                self.assertLessEqual((major, minor), (parts[0], parts[1]))

    def test_configuration_dump_needs_no_toolchain(self) -> None:
        for cell in MATRIX.expected_cells():
            with (
                self.subTest(cell=cell.key),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPTS_ROOT / "build_go_corpus.py"),
                        "--go-version",
                        cell.go_version,
                        "--output-root",
                        temp_dir,
                        "--validate-configuration-only",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                configuration = json.loads(result.stdout)
                self.assertEqual(configuration["cell_name"], cell.key)
                self.assertEqual(
                    configuration["pclntab_version"], cell.release.pclntab_version
                )
                self.assertEqual(
                    configuration["artifact_count"], len(cell.variants)
                )
                self.assertEqual(
                    [entry["key"] for entry in configuration["artifacts"]],
                    [variant.key for variant in cell.variants],
                )

    def test_an_unpinned_toolchain_is_refused_before_anything_is_built(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_ROOT / "build_go_corpus.py"),
                    "--go-version",
                    "1.19.13",
                    "--output-root",
                    temp_dir,
                    "--validate-configuration-only",
                ],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported Go toolchain version", result.stderr)


if __name__ == "__main__":
    unittest.main()
