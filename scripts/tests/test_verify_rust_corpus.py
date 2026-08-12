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

import rust_matrix  # noqa: E402
import synthetic_objects  # noqa: E402
import verify_rust_corpus as verify  # noqa: E402

# Something long enough to be a plausible checkout path, and distinctive enough
# that finding it inside an artifact can only mean the remap failed.
REMAPPED_PREFIX = "/home/runner/work/testbins/testbins"


def _synthetic_object(cell: rust_matrix.MatrixCell, crate_name: str) -> bytes:
    """Build an image that satisfies the cell's declared evidence."""

    evidence = rust_matrix.evidence_contract(cell, crate_name)
    sections = tuple(evidence["required_sections"])
    symbols = tuple(evidence["required_symbols"])
    trailing = b"".join(
        text.encode("ascii") + b"\x00" for text in evidence["required_strings"]
    )
    if cell.object_format == "elf":
        return synthetic_objects.build_elf(
            architecture=cell.architecture,
            symbols=symbols,
            sections=sections,
            trailing_bytes=trailing,
        )
    if cell.object_format == "macho":
        return synthetic_objects.build_macho(
            architecture=cell.architecture,
            symbols=symbols,
            sections=sections,
            trailing_bytes=trailing,
        )
    return synthetic_objects.build_pe(
        architecture=cell.architecture,
        exports=symbols,
        sections=sections,
        trailing_bytes=trailing,
    )


def _artifact_record(
    cell: rust_matrix.MatrixCell, crate_name: str, payload: bytes
) -> dict:
    return {
        "path": cell.artifact_path(crate_name),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "target_triple": cell.target,
        "crate_name": crate_name,
        "crate_type": rust_matrix.crate_type(crate_name),
        "panic_strategy": cell.panic_strategy,
        "optimization": cell.optimization,
        "execution": cell.execution(crate_name),
        "build": {
            "edition": rust_matrix.edition(),
            "linker": cell.linker,
            "rustc_flags": rust_matrix.rustc_flags(cell, crate_name, REMAPPED_PREFIX),
            "rustc_host": cell.rustc_host,
            "runner_image": f"synthetic-{cell.runner_os}",
            "runner_os": cell.runner_os,
            "runner_arch": cell.runner_arch,
        },
        "evidence": rust_matrix.evidence_contract(cell, crate_name),
        "neverd": rust_matrix.neverd_contract(cell, crate_name),
    }


def _producer() -> dict:
    return {
        "rustc": {
            "release": verify.pinned_toolchain_channel(),
            "commit_hash": "a" * 40,
            "commit_date": "2026-07-14",
            "llvm_version": "22.1.6",
        },
        "toolchain_channel": verify.pinned_toolchain_channel(),
        "repository_revision": "b" * 40,
    }


def _stage_cells(root: Path, cells: list[rust_matrix.MatrixCell]) -> dict:
    """Write every artifact of every cell and return the matching manifest."""

    artifacts = []
    for cell in cells:
        for crate_name in cell.artifact_names:
            payload = _synthetic_object(cell, crate_name)
            path = root / cell.artifact_path(crate_name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            artifacts.append(_artifact_record(cell, crate_name, payload))
    return {
        "schema_version": 1,
        "corpus": "rust-eh",
        "producer": _producer(),
        "artifacts": artifacts,
    }


def _write_manifest(root: Path, manifest: dict, name: str = "rust-eh.json") -> Path:
    path = root / "manifests" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class AcceptanceTests(unittest.TestCase):
    def test_accepts_one_artifact_from_every_object_format(self) -> None:
        for target in rust_matrix.target_names():
            cell = rust_matrix.validate_cell(target, "unwind", "o2")
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest = _stage_cells(root, [cell])
                path = _write_manifest(root, manifest)

                result = verify.verify_manifest(path, root)

                self.assertEqual(result.artifact_count, 2)

    def test_accepts_the_aborting_negative_controls(self) -> None:
        for target in rust_matrix.target_names():
            cell = rust_matrix.validate_cell(target, "abort", "o0")
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                manifest = _stage_cells(root, [cell])
                self.assertTrue(
                    all(
                        entry["neverd"]["expect_no_landing_pads"]
                        for entry in manifest["artifacts"]
                    )
                )
                path = _write_manifest(root, manifest)

                self.assertEqual(verify.verify_manifest(path, root).artifact_count, 2)


class RejectionTests(unittest.TestCase):
    def _staged(
        self, temp: str, *, panic_strategy: str = "unwind"
    ) -> tuple[Path, dict]:
        root = Path(temp)
        cell = rust_matrix.validate_cell(
            "x86_64-unknown-linux-gnu", panic_strategy, "o2"
        )
        return root, _stage_cells(root, [cell])

    def test_rejects_a_manifest_the_schema_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["artifacts"][0]["unexpected_field"] = True
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "schema"):
                verify.verify_manifest(path, root)

    def test_rejects_a_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["artifacts"][0]["sha256"] = "0" * 64
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "SHA-256 mismatch"):
                verify.verify_manifest(path, root)

    def test_rejects_a_size_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["artifacts"][0]["size"] += 1
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "size mismatch"):
                verify.verify_manifest(path, root)

    def test_rejects_a_missing_required_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cell = rust_matrix.validate_cell("x86_64-unknown-linux-gnu", "unwind", "o2")
            manifest = _stage_cells(root, [cell])
            record = manifest["artifacts"][0]
            payload = synthetic_objects.build_elf(
                architecture=cell.architecture,
                symbols=tuple(record["evidence"]["required_symbols"]),
                sections=(".text", ".eh_frame"),
            )
            (root / record["path"]).write_bytes(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"section\(s\) missing: \.gcc_except_table"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_missing_required_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cell = rust_matrix.validate_cell("aarch64-apple-darwin", "unwind", "o0")
            manifest = _stage_cells(root, [cell])
            record = manifest["artifacts"][0]
            kept = [
                name
                for name in record["evidence"]["required_symbols"]
                if name != "rust_eh_personality"
            ]
            payload = synthetic_objects.build_macho(
                architecture=cell.architecture,
                symbols=tuple(kept),
                sections=tuple(record["evidence"]["required_sections"]),
            )
            (root / record["path"]).write_bytes(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "symbol\\(s\\) missing: rust_eh_personality"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_an_aborting_image_that_can_still_raise(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cell = rust_matrix.validate_cell("x86_64-unknown-linux-gnu", "abort", "o2")
            manifest = _stage_cells(root, [cell])
            record = manifest["artifacts"][0]
            payload = synthetic_objects.build_elf(
                architecture=cell.architecture,
                symbols=tuple(record["evidence"]["required_symbols"])
                + ("_Unwind_RaiseException",),
                sections=tuple(record["evidence"]["required_sections"]),
            )
            (root / record["path"]).write_bytes(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "forbidden symbol.*_Unwind_RaiseException"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_an_msvc_image_without_the_rust_panic_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cell = rust_matrix.validate_cell("x86_64-pc-windows-msvc", "unwind", "o0")
            manifest = _stage_cells(root, [cell])
            record = manifest["artifacts"][0]
            payload = synthetic_objects.build_pe(
                sections=tuple(record["evidence"]["required_sections"])
            )
            (root / record["path"]).write_bytes(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "does not contain the string 'rust_panic'"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_binary_that_leaks_its_build_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cell = rust_matrix.validate_cell("x86_64-unknown-linux-gnu", "unwind", "o0")
            manifest = _stage_cells(root, [cell])
            record = manifest["artifacts"][0]
            payload = synthetic_objects.build_elf(
                architecture=cell.architecture,
                symbols=tuple(record["evidence"]["required_symbols"]),
                sections=tuple(record["evidence"]["required_sections"]),
                trailing_bytes=REMAPPED_PREFIX.encode("ascii"),
            )
            (root / record["path"]).write_bytes(payload)
            record["sha256"] = hashlib.sha256(payload).hexdigest()
            record["size"] = len(payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "leaks the build path"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_build_without_a_path_remap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            flags = manifest["artifacts"][0]["build"]["rustc_flags"]
            index = flags.index("--remap-path-prefix")
            del flags[index : index + 2]
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "remap-path-prefix"):
                verify.verify_manifest(path, root)

    def test_rejects_flags_that_disagree_with_the_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            flags = manifest["artifacts"][0]["build"]["rustc_flags"]
            flags[flags.index("overflow-checks=on")] = "overflow-checks=off"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "not the flags the matrix defines"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_weakened_consumer_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["artifacts"][0]["neverd"]["min_catch_unwind_pads"] = 0
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "min_catch_unwind_pads"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_path_that_disagrees_with_the_axes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            record = manifest["artifacts"][0]
            moved = record["path"].replace("/unwind/", "/abort/")
            (root / moved).parent.mkdir(parents=True, exist_ok=True)
            (root / moved).write_bytes((root / record["path"]).read_bytes())
            record["path"] = moved
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "path"):
                verify.verify_manifest(path, root)

    def test_rejects_a_toolchain_the_repository_does_not_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["producer"]["toolchain_channel"] = "1.0.0"
            manifest["producer"]["rustc"]["release"] = "1.0.0"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "rust-toolchain.toml pins"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_producer_whose_channel_and_compiler_disagree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["producer"]["rustc"]["release"] = "1.0.0"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "disagrees"):
                verify.verify_manifest(path, root)

    def test_rejects_a_cell_built_on_the_wrong_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, manifest = self._staged(temp)
            manifest["artifacts"][0]["build"]["runner_os"] = "macos"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "runner_os"):
                verify.verify_manifest(path, root)


class CompleteMatrixTests(unittest.TestCase):
    def _inventory(self) -> dict:
        artifacts = []
        for cell in rust_matrix.expected_cells():
            for crate_name in cell.artifact_names:
                artifacts.append(
                    {
                        "path": cell.artifact_path(crate_name),
                        "crate_name": crate_name,
                        "target_triple": cell.target,
                        "panic_strategy": cell.panic_strategy,
                        "optimization": cell.optimization,
                    }
                )
        return {"schema_version": 1, "corpus": "rust-eh", "artifacts": artifacts}

    def test_accepts_twenty_cells_and_forty_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            self.assertEqual(len(manifest["artifacts"]), 40)
            path = _write_manifest(Path(temp), manifest)

            verify.verify_complete_matrix(path)

    def test_rejects_a_missing_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            del manifest["artifacts"][:2]
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(verify.VerificationError, "incomplete"):
                verify.verify_complete_matrix(path)

    def test_rejects_a_cell_missing_one_crate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            del manifest["artifacts"][0]
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(verify.VerificationError, "crate set differs"):
                verify.verify_complete_matrix(path)

    def test_rejects_a_duplicated_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(verify.VerificationError, "duplicate"):
                verify.verify_complete_matrix(path)


class MergeTests(unittest.TestCase):
    def test_merges_fragments_from_three_runner_operating_systems(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cells = [
                rust_matrix.validate_cell("x86_64-unknown-linux-gnu", "unwind", "o0"),
                rust_matrix.validate_cell("x86_64-pc-windows-msvc", "unwind", "o0"),
                rust_matrix.validate_cell("aarch64-apple-darwin", "abort", "o2"),
            ]
            fragments = []
            for cell in cells:
                manifest = _stage_cells(root, [cell])
                fragment = root / "fragments" / f"{cell.key}.json"
                fragment.parent.mkdir(parents=True, exist_ok=True)
                fragment.write_text(json.dumps(manifest), encoding="utf-8")
                fragments.append(fragment)

            output = root / "manifests/rust-eh.json"
            result = verify.merge_manifests(fragments, output, root)

            self.assertEqual(result.artifact_count, 6)
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                {entry["build"]["runner_os"] for entry in merged["artifacts"]},
                {"linux", "windows", "macos"},
            )
            self.assertEqual(
                [entry["path"] for entry in merged["artifacts"]],
                sorted(entry["path"] for entry in merged["artifacts"]),
            )

    def test_rejects_fragments_built_by_different_compilers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fragments = []
            for index, target in enumerate(
                ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin")
            ):
                cell = rust_matrix.validate_cell(target, "unwind", "o0")
                manifest = _stage_cells(root, [cell])
                manifest["producer"]["rustc"]["commit_hash"] = str(index) * 40
                fragment = root / "fragments" / f"{cell.key}.json"
                fragment.parent.mkdir(parents=True, exist_ok=True)
                fragment.write_text(json.dumps(manifest), encoding="utf-8")
                fragments.append(fragment)

            with self.assertRaisesRegex(
                verify.VerificationError, "inconsistent envelopes"
            ):
                verify.merge_manifests(fragments, root / "manifests/out.json", root)

    def test_rejects_an_empty_fragment_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            with self.assertRaisesRegex(
                verify.VerificationError, "no manifest fragments"
            ):
                verify.merge_manifests([], root / "manifests/out.json", root)


class ToolchainPinTests(unittest.TestCase):
    def test_repository_pins_an_exact_release(self) -> None:
        channel = verify.pinned_toolchain_channel()

        self.assertRegex(channel, r"^[0-9]+\.[0-9]+\.[0-9]+$")


if __name__ == "__main__":
    unittest.main()
