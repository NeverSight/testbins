# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import ada_d_eh_matrix as matrix  # noqa: E402
import synthetic_objects  # noqa: E402
import verify_ada_d_eh_corpus as verify  # noqa: E402

REMAPPED_PREFIX = "/home/runner/work/testbins/testbins"
ELF_CELL = ("gnat", "x86_64-linux-gnu")
D_CELL = ("dmd", "x86_64-linux-gnu")


def _version(cell: matrix.MatrixCell) -> str:
    if cell.version_prefix.endswith("."):
        return f"{cell.version_prefix}3.0"
    return cell.version_prefix


def _synthetic_object(
    cell: matrix.MatrixCell,
    *,
    sections: tuple[str, ...] | None = None,
    symbols: tuple[str, ...] | None = None,
    trailing_bytes: bytes | None = None,
    eh_frame: bytes | None = None,
) -> bytes:
    evidence = matrix.evidence_contract(cell)
    declared_sections = (
        tuple(evidence["required_sections"]) if sections is None else sections
    )
    declared_symbols = (
        tuple(evidence["required_symbols"]) if symbols is None else symbols
    )
    if trailing_bytes is None:
        trailing_bytes = b"".join(
            text.encode("ascii") + b"\x00" for text in evidence["required_strings"]
        )
    overrides = {}
    if eh_frame is not None:
        overrides[".eh_frame"] = eh_frame
    return synthetic_objects.build_elf(
        architecture=cell.architecture,
        symbols=declared_symbols,
        sections=declared_sections,
        section_overrides=overrides or None,
        trailing_bytes=trailing_bytes,
    )


def _artifact_record(
    cell: matrix.MatrixCell, variant: matrix.Variant, payload: bytes
) -> dict:
    build = matrix.build_contract(cell, variant, REMAPPED_PREFIX)
    build.update(
        {
            "runner_image": "synthetic-linux",
            "runner_os": cell.runner_os,
            "runner_arch": cell.runner_arch,
        }
    )
    return {
        "path": cell.artifact_path(variant),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "toolchain": cell.toolchain,
        "toolchain_version": _version(cell),
        "target": cell.target,
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "source_language": cell.language,
        "optimization": variant.optimization,
        "execution": cell.execution(),
        "exception_model": "itanium-dwarf",
        "build": build,
        "evidence": matrix.evidence_contract(cell),
        "neverd": matrix.neverd_contract(cell),
    }


def _toolchain_record(cell: matrix.MatrixCell) -> dict:
    return {
        **matrix.toolchain_contract(cell),
        "version": _version(cell),
        "version_string": f"synthetic {cell.toolchain} {_version(cell)}",
    }


def _stage_cells(root: Path, cells: list[matrix.MatrixCell]) -> dict:
    artifacts = []
    for cell in cells:
        for variant in cell.variants:
            payload = _synthetic_object(cell)
            path = root / cell.artifact_path(variant)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            artifacts.append(_artifact_record(cell, variant, payload))
    return {
        "schema_version": 1,
        "corpus": "ada-d-eh",
        "producer": {
            "repository_revision": "b" * 40,
            "toolchains": [_toolchain_record(cell) for cell in cells],
        },
        "artifacts": sorted(artifacts, key=lambda entry: entry["path"]),
    }


def _write_manifest(root: Path, manifest: dict, name: str = "ada-d-eh.json") -> Path:
    path = root / "manifests" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _replace(root: Path, manifest: dict, path_text: str, payload: bytes) -> dict:
    record = next(entry for entry in manifest["artifacts"] if entry["path"] == path_text)
    (root / path_text).write_bytes(payload)
    record["sha256"] = hashlib.sha256(payload).hexdigest()
    record["size"] = len(payload)
    return record


class AcceptanceTests(unittest.TestCase):
    def test_accepts_one_ada_cell_and_one_d_cell(self) -> None:
        for toolchain, target in (ELF_CELL, D_CELL):
            cell = matrix.validate_cell(toolchain, target)
            with self.subTest(cell=cell.key), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                path = _write_manifest(root, _stage_cells(root, [cell]))

                result = verify.verify_manifest(path, root)

                self.assertEqual(result.artifact_count, 2)

    def test_accepts_the_complete_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cells = list(matrix.expected_cells())
            path = _write_manifest(root, _stage_cells(root, cells))

            result = verify.verify_manifest(path, root)
            verify.verify_complete_matrix(path)

            self.assertEqual(result.artifact_count, 12)


class RejectionTests(unittest.TestCase):
    def _staged(self, temp: str, cell_key: tuple[str, str] = ELF_CELL):
        root = Path(temp)
        cell = matrix.validate_cell(*cell_key)
        return root, cell, _stage_cells(root, [cell])

    def test_rejects_a_manifest_the_schema_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["unexpected_field"] = True
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "schema"):
                verify.verify_manifest(path, root)

    def test_rejects_a_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["sha256"] = "0" * 64
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "SHA-256 mismatch"):
                verify.verify_manifest(path, root)

    def test_rejects_a_missing_except_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("o0")
            payload = _synthetic_object(cell, sections=(".text", ".eh_frame"))
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, r"missing section"):
                verify.verify_manifest(path, root)

    def test_rejects_a_missing_personality(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("o2")
            payload = _synthetic_object(cell, symbols=())
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"missing symbol __gnat_personality_v0"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_cxx_rtti_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            record = manifest["artifacts"][0]
            record["neverd"] = copy.deepcopy(record["neverd"])
            record["neverd"]["type_table_interpretation"] = "cxx-rtti"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "schema|neverd"):
                verify.verify_manifest(path, root)

    def test_rejects_a_leaked_checkout_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("o0")
            evidence = matrix.evidence_contract(cell)
            payload = _synthetic_object(
                cell,
                trailing_bytes=b"".join(
                    text.encode("ascii") + b"\x00"
                    for text in evidence["required_strings"]
                )
                + REMAPPED_PREFIX.encode("utf-8"),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "leaks its checkout"):
                verify.verify_manifest(path, root)

    def test_rejects_an_incomplete_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "complete Ada/D"):
                verify.verify_complete_matrix(path)


class MergeTests(unittest.TestCase):
    def test_merges_two_cell_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cells = [
                matrix.validate_cell(*ELF_CELL),
                matrix.validate_cell(*D_CELL),
            ]
            fragments = []
            for cell in cells:
                fragment = _stage_cells(root, [cell])
                path = root / "fragments" / f"{cell.key}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(fragment), encoding="utf-8")
                fragments.append(path)
            output = root / "manifests" / "ada-d-eh.json"

            result = verify.merge_manifests(fragments, output, root)

            self.assertEqual(result.artifact_count, 4)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
