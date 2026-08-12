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

import cxx_itanium_matrix as matrix  # noqa: E402
import synthetic_objects  # noqa: E402
import verify_cxx_itanium_corpus as verify  # noqa: E402

# Something long enough to be a plausible checkout path, and distinctive enough
# that finding it inside an artifact can only mean the remap failed.
REMAPPED_PREFIX = "/home/runner/work/testbins/testbins"

# One representative cell per object format and per unwind model.
ELF_CELL = ("gcc", "x86_64-linux-gnu")
ARM_CELL = ("gcc", "armv7-linux-gnueabihf")
MACHO_CELL = ("clang", "arm64-apple-darwin")
PE_CELL = ("gcc", "x86_64-w64-mingw32")


def _version(cell: matrix.MatrixCell) -> str:
    """A version the cell would accept, whichever way its compiler numbers itself.

    A prefix ending in a dot names a series and leaves the rest to the release;
    one that does not is already the whole version the driver reports.
    """

    if cell.version_prefix.endswith("."):
        return f"{cell.version_prefix}2.1"
    return cell.version_prefix


def _synthetic_object(
    cell: matrix.MatrixCell,
    variant: matrix.Variant,
    *,
    sections: tuple[str, ...] | None = None,
    symbols: tuple[str, ...] | None = None,
    trailing_bytes: bytes | None = None,
    eh_frame: bytes | None = None,
    exidx_entries: int | None = None,
) -> bytes:
    """Build an image that satisfies the cell's declared evidence."""

    evidence = matrix.evidence_contract(cell, variant)
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

    if cell.object_format == "elf":
        overrides: dict[str, bytes] = {}
        if ".ARM.exidx" in declared_sections:
            count = (
                evidence["min_arm_exidx_entries"] + 2
                if exidx_entries is None
                else exidx_entries
            )
            overrides[".ARM.exidx"] = synthetic_objects.arm_exidx_section(count)
        if eh_frame is not None:
            overrides[".eh_frame"] = eh_frame
        return synthetic_objects.build_elf(
            architecture=cell.architecture,
            elf_class=32 if cell.architecture == "arm" else 64,
            symbols=declared_symbols,
            sections=declared_sections,
            section_overrides=overrides or None,
            trailing_bytes=trailing_bytes,
        )
    if cell.object_format == "macho":
        return synthetic_objects.build_macho(
            architecture=cell.architecture,
            symbols=declared_symbols,
            # The manifest names Mach-O sections by segment; the fixture takes
            # the bare name and puts everything in `__TEXT`.
            sections=tuple(name.split(",", 1)[-1] for name in declared_sections),
            trailing_bytes=trailing_bytes,
        )
    return synthetic_objects.build_pe(
        architecture=cell.architecture,
        symbols=declared_symbols,
        sections=declared_sections,
        trailing_bytes=trailing_bytes,
    )


def _artifact_record(
    cell: matrix.MatrixCell, variant: matrix.Variant, payload: bytes
) -> dict:
    build = matrix.build_contract(cell, variant, REMAPPED_PREFIX)
    build.update(
        {
            "runner_image": f"synthetic-{cell.runner_os}",
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
        "program": variant.program,
        "artifact_kind": variant.artifact_kind,
        "source_language": variant.source_language,
        "exceptions": variant.exceptions,
        "optimization": variant.optimization,
        "stripped": variant.stripped,
        "execution": cell.execution(variant),
        "build": build,
        "evidence": matrix.evidence_contract(cell, variant),
        "neverd": matrix.neverd_contract(cell, variant),
    }


def _toolchain_record(cell: matrix.MatrixCell) -> dict:
    return {
        **matrix.toolchain_contract(cell),
        "version": _version(cell),
        "version_string": f"synthetic {cell.toolchain} {_version(cell)}",
    }


def _stage_cells(root: Path, cells: list[matrix.MatrixCell]) -> dict:
    """Write every artifact of every cell and return the matching manifest."""

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
        "corpus": "cxx-itanium-eh",
        "producer": {
            "repository_revision": "b" * 40,
            "toolchains": [_toolchain_record(cell) for cell in cells],
        },
        "artifacts": sorted(artifacts, key=lambda entry: entry["path"]),
    }


def _write_manifest(
    root: Path, manifest: dict, name: str = "cxx-itanium-eh.json"
) -> Path:
    path = root / "manifests" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _replace(root: Path, manifest: dict, path_text: str, payload: bytes) -> dict:
    """Swap one staged artifact's bytes and keep the manifest self-consistent."""

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
    def test_accepts_one_cell_from_every_object_format(self) -> None:
        for toolchain, target in (ELF_CELL, ARM_CELL, MACHO_CELL, PE_CELL):
            cell = matrix.validate_cell(toolchain, target)
            with self.subTest(cell=cell.key), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                path = _write_manifest(root, _stage_cells(root, [cell]))

                result = verify.verify_manifest(path, root)

                self.assertEqual(result.artifact_count, 8)

    def test_accepts_the_exception_free_negative_control(self) -> None:
        cell = matrix.validate_cell(*ELF_CELL)
        control = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = _stage_cells(root, [cell])
            record = _record_for(manifest, cell, control)
            self.assertTrue(record["neverd"]["expect_no_lsda"])
            self.assertEqual(
                record["evidence"]["forbidden_sections"], [".gcc_except_table"]
            )
            path = _write_manifest(root, manifest)

            self.assertEqual(verify.verify_manifest(path, root).artifact_count, 8)


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

    def test_rejects_a_size_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["size"] += 1
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "size mismatch"):
                verify.verify_manifest(path, root)

    def test_rejects_a_missing_except_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe", "o2", False)
            payload = _synthetic_object(
                cell, variant, sections=(".text", ".eh_frame", ".eh_frame_hdr")
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"section\(s\) missing: \.gcc_except_table"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_control_that_still_carries_an_except_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
            payload = _synthetic_object(
                cell,
                variant,
                sections=(".text", ".eh_frame", ".eh_frame_hdr", ".gcc_except_table"),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError,
                r"forbidden section\(s\) present: \.gcc_except_table",
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_control_that_can_still_throw(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe_noexc", "o2", False)
            record = _record_for(manifest, cell, variant)
            payload = _synthetic_object(
                cell,
                variant,
                symbols=tuple(record["evidence"]["required_symbols"])
                + ("__cxa_throw",),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "forbidden symbol.*__cxa_throw"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_missing_personality(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp, MACHO_CELL)
            variant = matrix.validate_variant("cxx_eh_probe", "o0", False)
            record = _record_for(manifest, cell, variant)
            kept = tuple(
                name
                for name in record["evidence"]["required_symbols"]
                if name != "__gxx_personality_v0"
            )
            payload = _synthetic_object(cell, variant, symbols=kept)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, r"symbol\(s\) missing: __gxx_personality_v0"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_stripped_image_without_its_rtti(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe", "o2", True)
            payload = _synthetic_object(cell, variant, trailing_bytes=b"")
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError,
                "does not contain the string '15CxxEhProbeError'",
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_frame_section_that_describes_no_function(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe", "o0", False)
            payload = _synthetic_object(
                cell,
                variant,
                eh_frame=synthetic_objects.dwarf_frame_section_without_descriptions(),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "describes no function"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_an_ehabi_index_shorter_than_the_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp, ARM_CELL)
            variant = matrix.validate_variant("cxx_eh_probe", "o2", False)
            payload = _synthetic_object(cell, variant, exidx_entries=1)
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "EHABI index holds"):
                verify.verify_manifest(path, root)

    def test_rejects_an_ehabi_index_nobody_declared(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe", "o2", False)
            record = _record_for(manifest, cell, variant)
            payload = _synthetic_object(
                cell,
                variant,
                sections=tuple(record["evidence"]["required_sections"])
                + (".ARM.exidx",),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "EHABI index the manifest does not declare"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_binary_that_leaks_its_build_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            variant = matrix.validate_variant("cxx_eh_probe", "o0", False)
            payload = _synthetic_object(
                cell,
                variant,
                trailing_bytes=b"15CxxEhProbeError\x00"
                + REMAPPED_PREFIX.encode("ascii"),
            )
            _replace(root, manifest, cell.artifact_path(variant), payload)
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "leaks the build path"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_build_without_a_path_remap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            flags = manifest["artifacts"][0]["build"]["compiler_flags"]
            manifest["artifacts"][0]["build"]["compiler_flags"] = [
                flag for flag in flags if not flag.startswith("-ffile-prefix-map=")
            ]
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "file-prefix-map"):
                verify.verify_manifest(path, root)

    def test_rejects_flags_that_disagree_with_the_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            flags = manifest["artifacts"][0]["build"]["compiler_flags"]
            flags[flags.index("-g0")] = "-g3"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "build disagrees with the matrix"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_an_unpinned_build_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["build"]["environment"]["LC_ALL"] = "en_US.UTF-8"
            path = _write_manifest(root, manifest)

            with self.assertRaises(verify.VerificationError):
                verify.verify_manifest(path, root)

    def test_rejects_a_weakened_consumer_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["neverd"]["min_landing_pads"] = 0
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "min_landing_pads"):
                verify.verify_manifest(path, root)

    def test_rejects_a_path_that_disagrees_with_the_axes(self) -> None:
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

    def test_rejects_a_compiler_outside_the_pinned_release_series(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["producer"]["toolchains"][0]["version"] = "3.4.5"
            for record in manifest["artifacts"]:
                record["toolchain_version"] = "3.4.5"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(verify.VerificationError, "the matrix pins"):
                verify.verify_manifest(path, root)

    def test_rejects_a_producer_that_renames_its_own_driver(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["producer"]["toolchains"][0]["cxx_driver"] = "g++-9"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "disagrees with the matrix on: cxx_driver"
            ):
                verify.verify_manifest(path, root)

    def test_rejects_an_artifact_whose_version_the_producer_does_not_share(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["toolchain_version"] = f"{cell.version_prefix}9.9"
            path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                verify.VerificationError,
                "toolchain_version disagrees with producer.toolchains",
            ):
                verify.verify_manifest(path, root)

    def test_rejects_a_cell_built_on_the_wrong_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root, _cell, manifest = self._staged(temp)
            manifest["artifacts"][0]["build"]["runner_os"] = "macos"
            path = _write_manifest(root, manifest)

            with self.assertRaises(verify.VerificationError):
                verify.verify_manifest(path, root)


class CompleteMatrixTests(unittest.TestCase):
    def _inventory(self) -> dict:
        return {
            "schema_version": 1,
            "corpus": "cxx-itanium-eh",
            "producer": {
                "repository_revision": "b" * 40,
                "toolchains": [
                    _toolchain_record(cell) for cell in matrix.expected_cells()
                ],
            },
            "artifacts": [{"path": path} for path in matrix.expected_artifact_paths()],
        }

    def test_accepts_nine_cells_and_seventy_two_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            self.assertEqual(len(manifest["artifacts"]), 72)
            path = _write_manifest(Path(temp), manifest)

            verify.verify_complete_matrix(path)

    def test_rejects_a_missing_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            del manifest["producer"]["toolchains"][0]
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(
                verify.VerificationError, "producer.toolchains lists"
            ):
                verify.verify_complete_matrix(path)

    def test_rejects_a_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manifest = self._inventory()
            del manifest["artifacts"][0]
            path = _write_manifest(Path(temp), manifest)

            with self.assertRaisesRegex(verify.VerificationError, "incomplete"):
                verify.verify_complete_matrix(path)

    def test_rejects_a_duplicated_artifact(self) -> None:
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

    def test_merges_fragments_from_both_runner_operating_systems(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cells = [
                matrix.validate_cell(*ELF_CELL),
                matrix.validate_cell(*ARM_CELL),
                matrix.validate_cell(*MACHO_CELL),
            ]
            fragments = [self._fragment(root, cell) for cell in cells]

            output = root / "manifests/cxx-itanium-eh.json"
            result = verify.merge_manifests(fragments, output, root)

            self.assertEqual(result.artifact_count, 24)
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                [record["cell"] for record in merged["producer"]["toolchains"]],
                sorted(cell.key for cell in cells),
            )
            self.assertEqual(
                {entry["build"]["runner_os"] for entry in merged["artifacts"]},
                {"linux", "macos"},
            )
            self.assertEqual(
                [entry["path"] for entry in merged["artifacts"]],
                sorted(entry["path"] for entry in merged["artifacts"]),
            )

    def test_rejects_fragments_from_different_producer_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fragments = []
            for index, cell_key in enumerate((ELF_CELL, MACHO_CELL)):
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

    def test_rejects_an_empty_fragment_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            with self.assertRaisesRegex(
                verify.VerificationError, "no manifest fragments"
            ):
                verify.merge_manifests([], root / "manifests/out.json", root)


if __name__ == "__main__":
    unittest.main()
