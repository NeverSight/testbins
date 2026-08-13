# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import objc_matrix as matrix  # noqa: E402
import synthetic_objects  # noqa: E402
import verify_objc_corpus as verify  # noqa: E402

REMAPPED_PREFIX = "/Users/runner/work/testbins/testbins"
ARM_CELL = ("apple", "arm64-apple-darwin")
INTEL_CELL = ("apple", "x86_64-apple-darwin")
VERSION = "17.0.0"


def _synthetic_object(
    cell: matrix.MatrixCell,
    variant: matrix.Variant,
    *,
    sections: tuple[str, ...] | None = None,
    symbols: tuple[str, ...] | None = None,
    trailing_bytes: bytes | None = None,
    unwind_info: bytes | None = None,
) -> bytes:
    """Build a minimal Mach-O satisfying one Objective-C evidence contract."""

    evidence = matrix.evidence_contract(cell, variant)
    declared_sections = (
        tuple(evidence["required_sections"]) if sections is None else sections
    )
    declared_symbols = (
        tuple(evidence["required_symbols"]) if symbols is None else symbols
    )
    if trailing_bytes is None:
        trailing_bytes = b"".join(
            text.encode("ascii") + b"\0" for text in evidence["required_strings"]
        )
    return synthetic_objects.build_macho(
        architecture=cell.architecture,
        symbols=declared_symbols,
        sections=tuple(name.split(",", 1)[-1] for name in declared_sections),
        unwind_info=unwind_info,
        trailing_bytes=trailing_bytes,
    )


def _artifact_record(
    cell: matrix.MatrixCell, variant: matrix.Variant, payload: bytes
) -> dict:
    build = matrix.build_contract(cell, variant, REMAPPED_PREFIX)
    build.update(
        {
            "runner_image": "synthetic-macos-15",
            "runner_os": cell.runner_os,
            "runner_arch": cell.runner_arch,
        }
    )
    return {
        "path": cell.artifact_path(variant),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "runtime": cell.runtime,
        "toolchain_version": VERSION,
        "target": cell.target,
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "program": variant.program,
        "arc": variant.arc,
        "exceptions": variant.exceptions,
        "optimization": variant.optimization,
        "stripped": variant.stripped,
        "execution": cell.execution(variant),
        "build": build,
        "evidence": matrix.evidence_contract(cell, variant),
        "neverd": matrix.neverd_contract(cell, variant),
    }


def _toolchain_record(cell: matrix.MatrixCell, version: str = VERSION) -> dict:
    return {
        **matrix.toolchain_contract(cell),
        "version": version,
        "version_string": f"Apple clang version {version} (synthetic)",
    }


def _stage_cells(root: Path, cells: list[matrix.MatrixCell]) -> dict:
    artifacts = []
    for cell in cells:
        for variant in cell.variants:
            payload = _synthetic_object(cell, variant)
            path = root / cell.artifact_path(variant)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            artifacts.append(_artifact_record(cell, variant, payload))
    return {
        "schema_version": 1,
        "corpus": matrix.CORPUS_NAME,
        "producer": {
            "repository_revision": "b" * 40,
            "toolchains": [_toolchain_record(cell) for cell in cells],
        },
        "artifacts": sorted(artifacts, key=lambda entry: entry["path"]),
    }


def _write_manifest(
    root: Path, manifest: dict, name: str = "objc-eh.json"
) -> Path:
    path = root / "manifests" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _replace(root: Path, manifest: dict, path_text: str, payload: bytes) -> dict:
    record = next(
        entry for entry in manifest["artifacts"] if entry["path"] == path_text
    )
    (root / path_text).write_bytes(payload)
    record["sha256"] = hashlib.sha256(payload).hexdigest()
    record["size"] = len(payload)
    return record


def _record_for(
    manifest: dict, cell: matrix.MatrixCell, variant: matrix.Variant
) -> dict:
    return next(
        entry
        for entry in manifest["artifacts"]
        if entry["path"] == cell.artifact_path(variant)
    )


class AcceptanceTests(unittest.TestCase):
    def test_accepts_each_architecture_cell(self) -> None:
        for cell_key in (ARM_CELL, INTEL_CELL):
            cell = matrix.validate_cell(*cell_key)
            with self.subTest(cell=cell.key), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                path = _write_manifest(root, _stage_cells(root, [cell]))

                result = verify.verify_manifest(path, root)

                self.assertEqual(result.artifact_count, 6)
                self.assertGreater(result.total_bytes, 0)

    def test_accepts_exception_and_arc_controls(self) -> None:
        cell = matrix.validate_cell(*ARM_CELL)
        mrr = matrix.validate_variant("objc_eh_probe_mrr", "o2", False)
        noexc = matrix.validate_variant("objc_eh_probe_noexc", "o2", False)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = _stage_cells(root, [cell])
            self.assertFalse(_record_for(manifest, cell, mrr)["neverd"]["expect_arc"])
            self.assertTrue(
                _record_for(manifest, cell, noexc)["neverd"]["expect_no_lsda"]
            )
            path = _write_manifest(root, manifest)

            self.assertEqual(verify.verify_manifest(path, root).artifact_count, 6)


class RejectionTests(unittest.TestCase):
    def _staged(
        self, temp: str, cell_key: tuple[str, str] = ARM_CELL
    ) -> tuple[Path, matrix.MatrixCell, dict]:
        root = Path(temp)
        cell = matrix.validate_cell(*cell_key)
        return root, cell, _stage_cells(root, [cell])

    def test_rejects_schema_additional_properties(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["producer_says_true"] = True
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "schema"):
                verify.verify_manifest(path, root)

    def test_rejects_wrong_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["runtime"] = "gnustep"
            path = _write_manifest(root, manifest)

            with self.assertRaises(verify.VerificationError):
                verify.verify_manifest(path, root)

    def test_rejects_wrong_arc_axis(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            record = next(
                entry
                for entry in manifest["artifacts"]
                if entry["program"] == "objc_eh_probe"
            )
            record["arc"] = "off"
            path = _write_manifest(root, manifest)

            with self.assertRaises(verify.VerificationError):
                verify.verify_manifest(path, root)

    def test_rejects_path_disagreeing_with_axes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            record = manifest["artifacts"][0]
            moved = record["path"].replace("/o0/", "/o2/")
            (root / moved).parent.mkdir(parents=True, exist_ok=True)
            (root / moved).write_bytes((root / record["path"]).read_bytes())
            record["path"] = moved
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "path"):
                verify.verify_manifest(path, root)

    def test_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["sha256"] = "0" * 64
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "SHA-256 mismatch"):
                verify.verify_manifest(path, root)

    def test_rejects_size_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["size"] += 1
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "size mismatch"):
                verify.verify_manifest(path, root)

    def test_rejects_wrong_macho_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            intel = matrix.validate_cell(*INTEL_CELL)
            payload = synthetic_objects.build_macho(
                architecture=intel.architecture,
                symbols=tuple(matrix.required_symbols(cell, variant)),
                sections=tuple(
                    name.split(",", 1)[-1]
                    for name in matrix.required_sections(cell, variant)
                ),
                trailing_bytes=b"ObjCEhProbeError\0",
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "is x86_64"):
                verify.verify_manifest(path, root)

    def test_rejects_missing_exception_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            sections = tuple(
                name
                for name in matrix.required_sections(cell, variant)
                if name != "__TEXT,__gcc_except_tab"
            )
            payload = _synthetic_object(cell, variant, sections=sections)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"section\(s\) missing.*gcc_except_tab"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_control_carrying_exception_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe_noexc", "o2", False)
            sections = matrix.required_sections(cell, variant) + (
                "__TEXT,__gcc_except_tab",
            )
            payload = _synthetic_object(cell, variant, sections=sections)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"forbidden section\(s\) present"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_missing_personality_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            symbols = tuple(
                name
                for name in matrix.required_symbols(cell, variant)
                if name != "__objc_personality_v0"
            )
            payload = _synthetic_object(cell, variant, symbols=symbols)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"symbol\(s\) missing.*objc_personality"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_forbidden_throw_symbol_in_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe_noexc", "o2", False)
            symbols = matrix.required_symbols(cell, variant) + (
                "objc_exception_throw",
            )
            payload = _synthetic_object(cell, variant, symbols=symbols)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "forbidden symbol.*objc_exception_throw"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_missing_objective_c_class_string(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", True)
            payload = _synthetic_object(cell, variant, trailing_bytes=b"")
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "does not contain the string"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_malformed_compact_unwind(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            payload = _synthetic_object(
                cell,
                variant,
                unwind_info=synthetic_objects.compact_unwind_section(version=2),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "unwind tables"):
                verify.verify_manifest(path, root)

    def test_rejects_arm64_image_without_eh_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            sections = tuple(
                name
                for name in matrix.required_sections(cell, variant)
                if name != "__TEXT,__eh_frame"
            )
            payload = _synthetic_object(cell, variant, sections=sections)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"section\(s\) missing.*eh_frame"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_x86_64_image_with_unexpected_eh_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp, INTEL_CELL)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            sections = matrix.required_sections(cell, variant) + (
                "__TEXT,__eh_frame",
            )
            payload = _synthetic_object(cell, variant, sections=sections)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "compact unwind only"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_binary_leaking_build_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("objc_eh_probe", "o2", False)
            payload = _synthetic_object(
                cell,
                variant,
                trailing_bytes=b"ObjCEhProbeError\0"
                + REMAPPED_PREFIX.encode("utf-8"),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "leaks the build path"):
                verify.verify_manifest(path, root)

    def test_rejects_build_without_prefix_map(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            flags = manifest["artifacts"][0]["build"]["compiler_flags"]
            manifest["artifacts"][0]["build"]["compiler_flags"] = [
                flag for flag in flags if not flag.startswith("-ffile-prefix-map=")
            ]
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "file-prefix-map"):
                verify.verify_manifest(path, root)

    def test_rejects_weakened_neverd_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            record = next(
                entry
                for entry in manifest["artifacts"]
                if entry["exceptions"] == "on"
            )
            record["neverd"]["min_landing_pads"] = 0
            path = _write_manifest(root, manifest)

            with self.assertRaises(verify.VerificationError):
                verify.verify_manifest(path, root)

    def test_rejects_artifact_version_disagreeing_with_producer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["toolchain_version"] = "17.0.1"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "disagrees with producer.toolchains"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_malformed_apple_clang_banner(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["producer"]["toolchains"][0][
                "version_string"
            ] = "Apple clang version 17.0.0spoof"
            path = _write_manifest(root, manifest)

            with self.assertRaises(verify.VerificationError):
                verify.verify_manifest(path, root)


class CompleteMatrixTests(unittest.TestCase):
    def _inventory(self) -> dict:
        return {
            "schema_version": 1,
            "corpus": matrix.CORPUS_NAME,
            "producer": {
                "repository_revision": "b" * 40,
                "toolchains": [
                    _toolchain_record(cell) for cell in matrix.expected_cells()
                ],
            },
            "artifacts": [{"path": path} for path in matrix.expected_artifact_paths()],
        }

    def test_accepts_two_cells_and_twelve_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            self.assertEqual(len(manifest["artifacts"]), 12)
            path = _write_manifest(Path(temp), manifest)

            verify.verify_complete_matrix(path)

    def test_rejects_missing_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            del manifest["producer"]["toolchains"][0]
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "producer.toolchains lists"
            ):
                verify.verify_complete_matrix(path)

    def test_rejects_incomplete_artifact_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            del manifest["artifacts"][0]
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(verify.VerificationError, "incomplete"):
                verify.verify_complete_matrix(path)

    def test_rejects_duplicate_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(verify.VerificationError, "duplicate"):
                verify.verify_complete_matrix(path)


class MergeTests(unittest.TestCase):
    def _fragment(self, root: Path, cell: matrix.MatrixCell) -> Path:
        manifest = _stage_cells(root, [cell])
        fragment = root / "fragments" / f"{cell.key}.json"
        fragment.parent.mkdir(parents=True, exist_ok=True)
        fragment.write_text(json.dumps(manifest), encoding="utf-8")
        return fragment

    def test_merges_both_cells_and_toolchain_records(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cells = [matrix.validate_cell(*key) for key in (ARM_CELL, INTEL_CELL)]
            fragments = [self._fragment(root, cell) for cell in cells]
            output = root / "manifests/objc-eh.json"

            result = verify.merge_manifests(fragments, output, root)

            self.assertEqual(result.artifact_count, 12)
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                [record["cell"] for record in merged["producer"]["toolchains"]],
                sorted(cell.key for cell in cells),
            )
            self.assertEqual(
                [entry["path"] for entry in merged["artifacts"]],
                sorted(entry["path"] for entry in merged["artifacts"]),
            )

    def test_rejects_fragments_from_different_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fragments = []
            for index, cell_key in enumerate((ARM_CELL, INTEL_CELL)):
                cell = matrix.validate_cell(*cell_key)
                manifest = _stage_cells(root, [cell])
                manifest["producer"]["repository_revision"] = str(index) * 40
                fragment = root / "fragments" / f"{cell.key}.json"
                fragment.parent.mkdir(parents=True, exist_ok=True)
                fragment.write_text(json.dumps(manifest), encoding="utf-8")
                fragments.append(fragment)

            with self.assertRaisesRegex(
                verify.VerificationError, "disagree about the producer"
            ):
                verify.merge_manifests(fragments, root / "manifests/out.json", root)

    def test_rejects_conflicting_duplicate_toolchain_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cell = matrix.validate_cell(*ARM_CELL)
            first_manifest = _stage_cells(root, [cell])
            second_manifest = copy.deepcopy(first_manifest)
            second_manifest["producer"]["toolchains"][0]["version"] = "17.0.1"
            second_manifest["producer"]["toolchains"][0][
                "version_string"
            ] = "Apple clang version 17.0.1 (synthetic)"
            for artifact in second_manifest["artifacts"]:
                artifact["toolchain_version"] = "17.0.1"
            fragments = []
            for name, manifest in (
                ("first.json", first_manifest),
                ("second.json", second_manifest),
            ):
                path = root / "fragments" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(manifest), encoding="utf-8")
                fragments.append(path)

            with self.assertRaisesRegex(
                verify.VerificationError, "disagree about the .* toolchain"
            ):
                verify.merge_manifests(fragments, root / "manifests/out.json", root)

    def test_rejects_empty_fragment_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(
                verify.VerificationError, "no manifest fragments"
            ):
                verify.merge_manifests([], root / "manifests/out.json", root)


class AtomicWriteTests(unittest.TestCase):
    def test_failed_atomic_write_preserves_previous_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_text("old\n", encoding="utf-8")
            with mock.patch.object(verify.json, "dump", side_effect=RuntimeError("boom")):
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    verify._write_json(path, {"new": True})

            self.assertEqual(path.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(list(path.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
