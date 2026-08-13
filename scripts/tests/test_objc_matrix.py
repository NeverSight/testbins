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

import objc_matrix as matrix  # noqa: E402

SCRIPT_PATH = SCRIPTS_ROOT / "objc_matrix.py"


class MatrixShapeTests(unittest.TestCase):
    def test_matrix_is_two_cells_of_six_artifacts(self) -> None:
        cells = matrix.expected_cells()

        self.assertEqual(len(cells), 2)
        self.assertEqual(len({cell.key for cell in cells}), 2)
        self.assertEqual(len(matrix.expected_artifact_paths()), 12)
        for cell in cells:
            with self.subTest(cell=cell.key):
                self.assertEqual(len(cell.variants), 6)

    def test_every_artifact_path_is_unique_and_sorted(self) -> None:
        paths = matrix.expected_artifact_paths()

        self.assertEqual(len(set(paths)), len(paths))
        self.assertEqual(list(paths), sorted(paths))

    def test_targets_determine_architecture_and_execution(self) -> None:
        expected = {
            "arm64-apple-darwin": ("aarch64", True, "passed"),
            "x86_64-apple-darwin": (
                "x86_64",
                False,
                "not-run-cross-target",
            ),
        }
        self.assertEqual(set(matrix.target_names()), set(expected))
        for cell in matrix.expected_cells():
            architecture, native, execution = expected[cell.target]
            with self.subTest(cell=cell.key):
                self.assertEqual(cell.runtime, "apple")
                self.assertEqual(cell.object_format, "macho")
                self.assertEqual(cell.architecture, architecture)
                self.assertEqual(cell.runner_os, "macos")
                self.assertEqual(cell.runner_arch, "arm64")
                self.assertEqual(cell.native, native)
                for variant in cell.variants:
                    self.assertEqual(cell.execution(variant), execution)

    def test_each_cell_has_the_declared_variant_shapes(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")

        self.assertEqual(
            Counter(variant.program for variant in cell.variants),
            Counter(
                {
                    "objc_eh_probe": 4,
                    "objc_eh_probe_mrr": 1,
                    "objc_eh_probe_noexc": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(variant.optimization for variant in cell.variants),
            Counter({"o0": 2, "o2": 4}),
        )
        self.assertEqual(
            Counter(variant.stripped for variant in cell.variants),
            Counter({False: 4, True: 2}),
        )

    def test_artifact_path_repeats_every_axis(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        variant = matrix.validate_variant("objc_eh_probe", "o2", True)

        self.assertEqual(
            cell.artifact_path(variant),
            "corpus/objc-eh/apple/arm64-apple-darwin/o2/stripped/"
            "objc_eh_probe-apple-arm64-apple-darwin-o2-stripped",
        )

    def test_rejects_cells_and_variants_outside_the_matrix(self) -> None:
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("gnustep", "arm64-apple-darwin")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_cell("apple", "aarch64-unknown-linux-gnu")
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("objc_eh_probe_mrr", "o0", False)
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("objc_eh_probe_noexc", "o2", True)
        with self.assertRaises(matrix.MatrixError):
            matrix.validate_variant("objc_eh_probe", "o3", False)


class ToolchainAndFlagTests(unittest.TestCase):
    def test_both_cells_pin_xcode_and_apple_clang_17(self) -> None:
        for cell in matrix.expected_cells():
            with self.subTest(cell=cell.key):
                self.assertEqual(cell.xcode_path, matrix.MACOS_XCODE_PATH)
                self.assertEqual(cell.version_prefix, "17.")
                self.assertEqual(cell.driver, "clang")
                self.assertEqual(cell.strip_tool, "strip")
                self.assertEqual(cell.runs_on, "macos-15")

    def test_toolchain_contract_is_recomputable(self) -> None:
        for cell in matrix.expected_cells():
            contract = matrix.toolchain_contract(cell)
            with self.subTest(cell=cell.key):
                self.assertEqual(contract["cell"], cell.key)
                self.assertEqual(contract["runtime"], "apple")
                self.assertEqual(contract["target"], cell.target)
                self.assertEqual(contract["driver"], "clang")
                self.assertEqual(contract["strip_tool"], "strip")

    def test_every_variant_remaps_paths_and_pins_runtime(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                flags = matrix.compiler_flags(cell, variant, "/checkout")
                with self.subTest(cell=cell.key, variant=variant.key):
                    self.assertIn("-ffile-prefix-map=/checkout=/testbins", flags)
                    self.assertIn("-fobjc-runtime=macosx", flags)
                    self.assertIn("-fasynchronous-unwind-tables", flags)
                    self.assertIn("-g0", flags)
                    self.assertIn("-framework", flags)
                    self.assertIn("Foundation", flags)

    def test_exception_control_differs_only_by_exception_flag(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        throwing = matrix.compiler_flags(
            cell, matrix.validate_variant("objc_eh_probe", "o2", False), "/checkout"
        )
        control = matrix.compiler_flags(
            cell,
            matrix.validate_variant("objc_eh_probe_noexc", "o2", False),
            "/checkout",
        )

        self.assertEqual(
            [flag for flag in throwing if flag != "-fobjc-exceptions"],
            [flag for flag in control if flag != "-fno-objc-exceptions"],
        )

    def test_mrr_control_differs_only_by_arc_flag(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        arc = matrix.compiler_flags(
            cell, matrix.validate_variant("objc_eh_probe", "o2", False), "/checkout"
        )
        mrr = matrix.compiler_flags(
            cell,
            matrix.validate_variant("objc_eh_probe_mrr", "o2", False),
            "/checkout",
        )

        self.assertEqual(
            [flag for flag in arc if flag != "-fobjc-arc"],
            [flag for flag in mrr if flag != "-fno-objc-arc"],
        )

    def test_build_environment_is_pinned(self) -> None:
        self.assertEqual(
            matrix.build_environment(),
            {"LC_ALL": "C", "SOURCE_DATE_EPOCH": "1735689600", "TZ": "UTC"},
        )


class EvidenceContractTests(unittest.TestCase):
    def test_symbol_contract_uses_reader_normalized_source_spellings(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        variant = matrix.validate_variant("objc_eh_probe", "o2", False)
        symbols = set(matrix.required_symbols(cell, variant))

        self.assertEqual(cell.personality_symbol, "__objc_personality_v0")
        self.assertIn("__objc_personality_v0", symbols)
        self.assertIn("objc_exception_throw", symbols)
        self.assertIn("OBJC_EHTYPE_id", symbols)
        self.assertIn("objc_eh_probe_raise", symbols)
        self.assertNotIn("___objc_personality_v0", symbols)
        self.assertNotIn("_objc_exception_throw", symbols)
        self.assertNotIn("_objc_eh_probe_raise", symbols)

    def test_stripped_variants_keep_imports_but_not_probe_names(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        variant = matrix.validate_variant("objc_eh_probe", "o2", True)
        evidence = matrix.evidence_contract(cell, variant)

        self.assertTrue(evidence["symbol_names_expected"])
        self.assertIn("__objc_personality_v0", evidence["required_symbols"])
        self.assertIn("objc_exception_throw", evidence["required_symbols"])
        self.assertNotIn("objc_eh_probe_raise", evidence["required_symbols"])
        self.assertEqual(evidence["required_strings"], ["ObjCEhProbeError"])

    def test_arc_import_is_required_at_both_optimization_levels(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        for optimization in ("o0", "o2"):
            variant = matrix.validate_variant("objc_eh_probe", optimization, False)
            with self.subTest(optimization=optimization):
                self.assertIn(
                    "objc_retainAutoreleasedReturnValue",
                    matrix.required_symbols(cell, variant),
                )

    def test_mrr_forbids_the_arc_discriminator(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        variant = matrix.validate_variant("objc_eh_probe_mrr", "o2", False)

        self.assertIn(
            "objc_retainAutoreleasedReturnValue",
            matrix.forbidden_symbols(cell, variant),
        )
        self.assertNotIn(
            "objc_retainAutoreleasedReturnValue",
            matrix.required_symbols(cell, variant),
        )

    def test_exception_control_forbids_lsda_and_throw_runtime(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        variant = matrix.validate_variant("objc_eh_probe_noexc", "o2", False)

        self.assertEqual(
            matrix.forbidden_sections(cell, variant),
            ("__TEXT,__gcc_except_tab",),
        )
        self.assertIn("__objc_personality_v0", matrix.forbidden_symbols(cell, variant))
        self.assertIn("objc_exception_throw", matrix.forbidden_symbols(cell, variant))
        self.assertEqual(matrix.required_strings(cell, variant), ())

    def test_eh_frame_contract_is_architecture_specific(self) -> None:
        variant = matrix.validate_variant("objc_eh_probe", "o2", False)
        arm = matrix.validate_cell("apple", "arm64-apple-darwin")
        intel = matrix.validate_cell("apple", "x86_64-apple-darwin")

        self.assertTrue(matrix.eh_frame_present(arm, variant))
        self.assertIn("__TEXT,__eh_frame", matrix.required_sections(arm, variant))
        self.assertFalse(matrix.eh_frame_present(intel, variant))
        self.assertNotIn("__TEXT,__eh_frame", matrix.required_sections(intel, variant))

    def test_probe_inventory_splits_on_exception_guard(self) -> None:
        full = set(matrix.probe_symbols("objc_eh_probe"))
        control = set(matrix.probe_symbols("objc_eh_probe_noexc"))

        self.assertEqual(control, set(matrix.quiet_probe_symbols()))
        self.assertEqual(full - control, set(matrix.throwing_probe_symbols()))
        self.assertTrue(control < full)


class ConsumerContractTests(unittest.TestCase):
    def test_throwing_variants_require_an_objective_c_graph(self) -> None:
        for cell in matrix.expected_cells():
            for variant in cell.variants:
                if variant.exceptions == "off":
                    continue
                contract = matrix.neverd_contract(cell, variant)
                with self.subTest(cell=cell.key, variant=variant.key):
                    self.assertEqual(contract["validation_level"], "objc-graph")
                    self.assertEqual(contract["objc_runtime"], "apple")
                    self.assertEqual(
                        contract["personalities_any"], ["__objc_personality_v0"]
                    )
                    self.assertEqual(
                        contract["required_class_names"],
                        ["ObjCEhProbeError", "NSException"],
                    )
                    self.assertFalse(contract["expect_no_lsda"])
                    self.assertTrue(contract["expect_runtime_proven_by_personality"])

    def test_control_claims_no_objective_c_exception_graph(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        variant = matrix.validate_variant("objc_eh_probe_noexc", "o2", False)
        contract = matrix.neverd_contract(cell, variant)

        self.assertEqual(contract["validation_level"], "cfi-only")
        self.assertTrue(contract["expect_no_lsda"])
        self.assertTrue(contract["expect_arc"])
        self.assertFalse(contract["expect_runtime_proven_by_personality"])
        self.assertEqual(contract["personalities_any"], [])
        self.assertEqual(contract["required_class_names"], [])
        for key, value in contract.items():
            if key.startswith("min_"):
                self.assertEqual(value, 0, key)

    def test_expect_arc_follows_the_arc_axis(self) -> None:
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        for variant in cell.variants:
            with self.subTest(variant=variant.key):
                self.assertEqual(
                    matrix.neverd_contract(cell, variant)["expect_arc"],
                    variant.arc == "on",
                )


class CommandTests(unittest.TestCase):
    def test_github_output_is_a_two_cell_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "github-output.txt"
            subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--github-output", str(output)],
                check=True,
            )
            name, payload = output.read_text(encoding="utf-8").strip().split("=", 1)

        self.assertEqual(name, "matrix")
        include = json.loads(payload)["include"]
        self.assertEqual(len(include), 2)
        self.assertEqual(sum(entry["artifact_count"] for entry in include), 12)
        self.assertEqual({entry["runs_on"] for entry in include}, {"macos-15"})
        self.assertEqual(Counter(entry["native"] for entry in include), {True: 1, False: 1})

    def test_plan_and_paths_cover_the_complete_inventory(self) -> None:
        plan = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--plan"],
            check=True,
            capture_output=True,
            text=True,
        )
        paths = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--paths"],
            check=True,
            capture_output=True,
            text=True,
        )

        payload = json.loads(plan.stdout)
        self.assertEqual(payload["artifact_count"], 12)
        self.assertEqual(len(payload["cells"]), 2)
        self.assertEqual(paths.stdout.splitlines(), list(matrix.expected_artifact_paths()))

    def test_requires_an_output_mode(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)], capture_output=True, text=True
        )

        self.assertNotEqual(completed.returncode, 0)


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = (
            SCRIPTS_ROOT.parent / ".github/workflows/build-objc-eh.yml"
        )
        self.text = self.path.read_text(encoding="utf-8")

    def test_workflow_has_all_four_pipeline_jobs(self) -> None:
        for job in (
            "verify-producer:",
            "build-cell:",
            "assemble-corpus:",
            "publish-corpus:",
        ):
            with self.subTest(job=job):
                self.assertIn(f"  {job}", self.text)

    def test_every_action_is_pinned_to_a_full_sha(self) -> None:
        uses = [
            line.strip().split("@", 1)[1].split()[0]
            for line in self.text.splitlines()
            if line.strip().startswith("uses:")
        ]

        self.assertTrue(uses)
        for revision in uses:
            self.assertRegex(revision, r"^[0-9a-f]{40}$")

    def test_path_filters_cover_every_producer_input(self) -> None:
        for path in (
            "schema/objc-eh-manifest.schema.json",
            "scripts/objc_matrix.py",
            "scripts/build_objc_corpus.py",
            "scripts/merge_objc_corpus.py",
            "scripts/verify_objc_corpus.py",
            "scripts/json_schema_check.py",
            "scripts/object_readers.py",
            "scripts/tests/test_objc_matrix.py",
            "scripts/tests/test_objc_sources.py",
            "scripts/tests/test_build_objc_corpus_script.py",
            "scripts/tests/test_verify_objc_corpus.py",
            "scripts/tests/synthetic_objects.py",
            "sources/objc-eh/**",
            "corpus/objc-eh/README.md",
        ):
            with self.subTest(path=path):
                self.assertGreaterEqual(self.text.count(f'"{path}"'), 2)

    def test_publish_is_main_only_and_syncs_only_this_product_line(self) -> None:
        self.assertIn("github.ref == 'refs/heads/main'", self.text)
        self.assertIn("github.event_name == 'workflow_dispatch'", self.text)
        self.assertIn(
            "git add -- corpus/objc-eh manifests/objc-eh.json", self.text
        )
        self.assertIn("corpus/objc-eh/", self.text)
        self.assertIn("manifests/objc-eh.json", self.text)


class SchemaContractTests(unittest.TestCase):
    def setUp(self) -> None:
        path = SCRIPTS_ROOT.parent / "schema/objc-eh-manifest.schema.json"
        self.schema = json.loads(path.read_text(encoding="utf-8"))

    def test_every_typed_object_is_closed(self) -> None:
        def walk(node: object, path: str) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(
                        node.get("additionalProperties"),
                        False,
                        f"{path} is not closed",
                    )
                for key, value in node.items():
                    walk(value, f"{path}/{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{path}/{index}")

        walk(self.schema, "#")

    def test_neverd_schema_matches_matrix_contract_keys_exactly(self) -> None:
        neverd = self.schema["$defs"]["neverd"]
        cell = matrix.validate_cell("apple", "arm64-apple-darwin")
        keys: set[str] | None = None
        for variant in cell.variants:
            current = set(matrix.neverd_contract(cell, variant))
            keys = current if keys is None else keys
            self.assertEqual(current, keys)

        assert keys is not None
        self.assertEqual(set(neverd["required"]), keys)
        self.assertEqual(set(neverd["properties"]), keys)

    def test_artifact_schema_requires_objective_c_axes(self) -> None:
        required = set(self.schema["$defs"]["artifact"]["required"])

        self.assertLessEqual(
            {"runtime", "target", "arc", "exceptions", "program", "optimization"},
            required,
        )


if __name__ == "__main__":
    unittest.main()
