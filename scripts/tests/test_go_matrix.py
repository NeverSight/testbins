# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""The Go corpus matrix describes exactly the artifacts CI can produce."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

SCRIPT_PATH = Path(__file__).parents[1] / "go_matrix.py"


def _load_matrix_module():
    spec = importlib.util.spec_from_file_location("go_matrix", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load go_matrix.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GoMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = _load_matrix_module()

    def test_every_pclntab_magic_the_decoder_knows_is_covered(self) -> None:
        """The four magics are the whole reason this corpus has a version axis.

        NeverD's `GoRuntimeEH.cpp` recognizes 0xfffffffb, 0xfffffffa,
        0xfffffff0, and 0xfffffff1, and claims a distinct record layout for
        each.  A corpus that skipped one would leave that layout tested only
        against bytes NeverD's own tests wrote.
        """

        produced = {
            variant.release.pclntab_magic for variant in self.matrix.expected_variants()
        }
        self.assertEqual(
            produced, {0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFF0, 0xFFFFFFF1}
        )
        names = {
            variant.release.pclntab_version
            for variant in self.matrix.expected_variants()
        }
        self.assertEqual(names, {"go1.2", "go1.16", "go1.18", "go1.20"})

    def test_every_container_and_pc_quantum_is_covered(self) -> None:
        variants = self.matrix.expected_variants()
        self.assertEqual(
            {variant.target.object_format for variant in variants},
            {"elf", "pe", "macho"},
        )
        self.assertEqual({variant.target.min_lc for variant in variants}, {1, 4})
        self.assertEqual(
            {variant.buildmode for variant in variants}, {"exe", "pie", "c-shared"}
        )
        self.assertEqual({variant.stripped for variant in variants}, {True, False})
        self.assertEqual(
            {variant.optimization for variant in variants}, {"default", "none"}
        )
        self.assertEqual({variant.cgo_enabled for variant in variants}, {True, False})

    def test_a_stripped_elf_and_a_position_independent_elf_are_both_present(
        self,
    ) -> None:
        """The two ELF shapes reach the table through different section names."""

        variants = self.matrix.expected_variants()
        elf = [variant for variant in variants if variant.target.object_format == "elf"]
        self.assertTrue(any(variant.buildmode == "exe" and variant.stripped for variant in elf))
        self.assertTrue(any(variant.buildmode == "pie" for variant in elf))

    def test_cells_partition_the_artifacts(self) -> None:
        cells = self.matrix.expected_cells()
        variants = self.matrix.expected_variants()
        self.assertEqual(
            sum(len(cell.variants) for cell in cells), len(variants)
        )
        self.assertEqual(
            {variant.key for variant in variants},
            {variant.key for cell in cells for variant in cell.variants},
        )
        self.assertEqual(
            [cell.go_version for cell in cells],
            list(self.matrix.pinned_go_versions()),
        )

    def test_paths_and_keys_are_unique_and_repeat_every_axis(self) -> None:
        variants = self.matrix.expected_variants()
        self.assertEqual(len({variant.path for variant in variants}), len(variants))
        self.assertEqual(len({variant.key for variant in variants}), len(variants))
        for variant in variants:
            with self.subTest(variant=variant.key):
                self.assertIn(variant.key, variant.filename)
                self.assertTrue(variant.path.startswith("corpus/go-eh/"))
                self.assertIn(f"/{variant.release.label}/", variant.path)
                self.assertIn(f"/{variant.target.label}/", variant.path)
                self.assertIn(f"/{variant.buildmode}/", variant.path)
                self.assertIn(f"/{variant.cgo_label}/", variant.path)
                self.assertIn(f"/{variant.link_label}/", variant.path)
                self.assertIn(f"/{variant.optimization_label}/", variant.path)

    def test_windows_artifacts_keep_their_extension(self) -> None:
        for variant in self.matrix.expected_variants():
            with self.subTest(variant=variant.key):
                if variant.buildmode == "c-shared":
                    expected = {"linux": ".so", "darwin": ".dylib", "windows": ".dll"}[
                        variant.goos
                    ]
                else:
                    expected = ".exe" if variant.goos == "windows" else ""
                self.assertEqual(variant.extension, expected)

    def test_trimpath_is_not_optional(self) -> None:
        """The checkout path must not survive into a published artifact."""

        for variant in self.matrix.expected_variants():
            with self.subTest(variant=variant.key):
                self.assertIn("-trimpath", variant.build_flags())

    def test_build_flags_follow_the_recorded_axes(self) -> None:
        stripped = self.matrix.validate_variant(
            "1.26.5", "linux", "amd64", "exe", False, True, "default"
        )
        unoptimized = self.matrix.validate_variant(
            "1.26.5", "linux", "amd64", "exe", False, False, "none"
        )
        self.assertEqual(
            stripped.build_flags(), ["-trimpath", "-buildmode=exe", "-ldflags=-s -w"]
        )
        self.assertEqual(
            unoptimized.build_flags(),
            ["-trimpath", "-buildmode=exe", "-gcflags=all=-N -l"],
        )

    def test_build_environment_pins_everything_the_runner_could_change(self) -> None:
        variant = self.matrix.validate_variant(
            "1.26.5", "windows", "amd64", "exe", False, True, "default"
        )
        self.assertEqual(
            variant.build_env(),
            {
                "CGO_ENABLED": "0",
                "GO111MODULE": "on",
                "GOARCH": "amd64",
                "GOFLAGS": "",
                "GOOS": "windows",
                "GOPROXY": "off",
                "GOTOOLCHAIN": "local",
                "GOWORK": "off",
            },
        )

    def test_only_host_native_executables_are_claimed_to_have_run(self) -> None:
        for variant in self.matrix.expected_variants():
            with self.subTest(variant=variant.key):
                if (
                    variant.target.native
                    and variant.buildmode in ("exe", "pie")
                ):
                    self.assertEqual(variant.execution, "passed")
                elif variant.buildmode == "c-shared":
                    self.assertEqual(variant.execution, "not-run-shared-object")
                else:
                    self.assertEqual(variant.execution, "not-run-cross-target")

    def test_rejects_combinations_no_runner_can_build(self) -> None:
        invalid = (
            # darwin/arm64 did not exist before Go 1.16.
            ("1.15.15", "darwin", "arm64", "exe", False, True, "default"),
            # c-shared needs external linking, which needs cgo.
            ("1.26.5", "linux", "amd64", "c-shared", False, True, "default"),
            # cgo cannot cross-compile without a cross C toolchain.
            ("1.26.5", "darwin", "arm64", "exe", True, True, "default"),
            ("1.26.5", "windows", "amd64", "exe", True, True, "default"),
            # PIE on darwin and Windows adds no discovery path of its own.
            ("1.26.5", "darwin", "arm64", "pie", False, True, "default"),
            ("1.26.5", "windows", "amd64", "pie", False, True, "default"),
            # Nothing here pins a toolchain the producer does not install.
            ("1.19.13", "linux", "amd64", "exe", False, True, "default"),
            ("1.26.5", "linux", "386", "exe", False, True, "default"),
            ("1.26.5", "linux", "amd64", "plugin", False, True, "default"),
            ("1.26.5", "linux", "amd64", "exe", False, True, "size"),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                with self.assertRaises(self.matrix.MatrixError):
                    self.matrix.validate_variant(*arguments)

    def test_a_path_round_trips_back_to_its_variant(self) -> None:
        for variant in self.matrix.expected_variants():
            with self.subTest(variant=variant.key):
                self.assertEqual(self.matrix.variant_for_path(variant.path), variant)
        with self.assertRaises(self.matrix.MatrixError):
            self.matrix.variant_for_path("corpus/go-eh/go9.9.9/linux-amd64/x")

    def test_every_focus_variant_records_why_it_exists(self) -> None:
        purposes = self.matrix.variant_purposes()
        keys = {variant.key for variant in self.matrix.expected_variants()}
        self.assertTrue(purposes)
        self.assertTrue(set(purposes) <= keys)
        for key, purpose in purposes.items():
            with self.subTest(key=key):
                self.assertGreater(len(purpose), 20)

    def test_github_output_is_one_compact_entry_per_toolchain(self) -> None:
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
        cells = self.matrix.expected_cells()
        self.assertEqual(len(matrix["include"]), len(cells))
        self.assertEqual(
            {entry["cell_name"] for entry in matrix["include"]},
            {cell.key for cell in cells},
        )
        self.assertEqual(
            sum(entry["artifact_count"] for entry in matrix["include"]),
            len(self.matrix.expected_variants()),
        )

    def test_artifact_budget_stays_small_enough_to_commit(self) -> None:
        """A Go binary is about a megabyte before it does anything.

        The corpus is committed to a git repository that other projects clone
        as a submodule, so the artifact count is itself a design constraint.
        """

        variants = self.matrix.expected_variants()
        self.assertLessEqual(len(variants), 30)
        by_version = Counter(variant.go_version for variant in variants)
        self.assertEqual(set(by_version), set(self.matrix.pinned_go_versions()))
        for version, count in by_version.items():
            with self.subTest(version=version):
                self.assertGreaterEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
