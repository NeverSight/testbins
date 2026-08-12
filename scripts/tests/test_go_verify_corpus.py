# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Behaviour of the Go corpus verifier against images built in a tempdir."""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
TESTS_ROOT = Path(__file__).parent


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
FIXTURES = _load("test_go_object_fixtures", TESTS_ROOT / "test_go_object_fixtures.py")

_PADDING = b"\0" * 96


def _sections_for(variant, *, function_count: int) -> list:
    """Assemble the section list a real image of this shape would have."""

    release = variant.release
    target = variant.target
    header = FIXTURES.pclntab_header(
        release.pclntab_magic,
        min_lc=target.min_lc,
        pointer_size=target.pointer_size,
        function_count=function_count,
    )
    required = BUILD._expected_required_sections(variant)
    pclntab_section, at_start = BUILD._pclntab_location(variant)
    sections = []
    address = 0x1000
    for name in required:
        if name == pclntab_section:
            # The PE linker folds the table into read-only data, so the header
            # sits at an offset inside the section rather than at its start.
            body = header + _PADDING if at_start else _PADDING + header + _PADDING
        elif name.endswith("text"):
            body = b"\x90" * 128
        else:
            body = b"\0" * 64
        sections.append(FIXTURES.SectionSpec(name, body, address))
        address += 0x10000
    if target.object_format == "pe":
        for name in (".pdata", ".xdata"):
            sections.append(FIXTURES.SectionSpec(name, b"\0" * 32, address))
            address += 0x1000
    if variant.cgo_enabled and target.object_format == "elf":
        for name in (".eh_frame", ".eh_frame_hdr"):
            sections.append(FIXTURES.SectionSpec(name, b"\0" * 32, address))
            address += 0x1000
    return sections


def _symbols_for(variant) -> list[str]:
    """The names a real link leaves in the image.

    `-ldflags=-s -w` empties the symbol table on ELF and PE, but the Mach-O
    link still emits an `LC_SYMTAB` carrying `_go.func.*`.  A fixture that
    strips darwin as thoroughly as linux would let a schema or verifier rule
    that only holds for ELF pass unnoticed.
    """

    if not variant.stripped:
        return ["runtime.gopanic", variant.release.gofunc_symbol, "main.main"]
    if variant.target.object_format == "macho":
        return [variant.release.gofunc_symbol]
    return []


def _materialize(root: Path, variant, *, function_count: int = 1500) -> Path:
    spec = FIXTURES.ImageSpec(
        sections=_sections_for(variant, function_count=function_count),
        symbols=_symbols_for(variant),
    )
    payload = FIXTURES.BUILDERS[variant.target.object_format](spec)
    path = root / Path(*variant.path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _toolchain(version: str) -> dict:
    return {
        "go_version": version,
        "go_version_string": f"go version go{version} linux/amd64",
        "go_env": {
            "GOAMD64": "v1",
            "GOARM64": "",
            "GOEXPERIMENT": "",
            "GOFLAGS": "",
            "GOHOSTARCH": "amd64",
            "GOHOSTOS": "linux",
            "GOTOOLCHAIN": "local",
            "GOVERSION": f"go{version}",
        },
    }


def _manifest(root: Path, variants, *, function_count: int = 1500) -> dict:
    artifacts = []
    versions = []
    for variant in variants:
        path = _materialize(root, variant, function_count=function_count)
        artifacts.append(BUILD._artifact_record(variant, path, root))
        if variant.go_version not in versions:
            versions.append(variant.go_version)
    return {
        "schema_version": 1,
        "corpus": "go-eh",
        "producer": {
            "repository_revision": "1" * 40,
            "runner_image": "ubuntu24-test",
            "runner_os": "linux",
            "runner_arch": "x64",
            "module_path": "neversight.dev/goeh",
            "module_go_directive": "1.15",
            "package": "./cmd/eh_probe",
            "toolchains": [_toolchain(version) for version in sorted(versions)],
        },
        "artifacts": artifacts,
    }


def _write(root: Path, manifest: dict, name: str = "manifests/go-eh.json") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _variant(**overrides):
    defaults = {
        "go_version": "1.26.5",
        "goos": "linux",
        "goarch": "amd64",
        "buildmode": "exe",
        "cgo_enabled": False,
        "stripped": True,
        "optimization": "default",
    }
    defaults.update(overrides)
    return MATRIX.validate_variant(**defaults)


class GoObjectParsingTests(unittest.TestCase):
    def test_reads_the_header_out_of_every_container(self) -> None:
        for variant in (
            _variant(),
            _variant(goos="windows"),
            _variant(goos="darwin", goarch="arm64"),
            _variant(buildmode="pie"),
        ):
            with (
                self.subTest(variant=variant.key),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                path = _materialize(root, variant, function_count=4321)
                image = VERIFY.parse_object(
                    path.read_bytes(), variant.target.object_format
                )
                section, at_start = BUILD._pclntab_location(variant)
                header = VERIFY.locate_pclntab(image, section, at_start)

                self.assertEqual(header.magic, variant.release.pclntab_magic)
                self.assertEqual(header.min_lc, variant.target.min_lc)
                self.assertEqual(header.pointer_size, 8)
                self.assertEqual(header.function_count, 4321)

    def test_rejects_a_header_whose_reserved_bytes_are_not_zero(self) -> None:
        self.assertIsNone(
            VERIFY.read_pclntab_header(FIXTURES.pclntab_header(pad=b"\x01\0"), 0)
        )

    def test_rejects_a_header_with_an_impossible_pc_quantum(self) -> None:
        header = bytearray(FIXTURES.pclntab_header())
        header[6] = 3
        self.assertIsNone(VERIFY.read_pclntab_header(bytes(header), 0))

    def test_rejects_a_header_that_claims_no_functions(self) -> None:
        self.assertIsNone(
            VERIFY.read_pclntab_header(FIXTURES.pclntab_header(function_count=0), 0)
        )

    def test_refuses_an_image_holding_two_plausible_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            variant = _variant()
            sections = _sections_for(variant, function_count=1500)
            sections.append(
                FIXTURES.SectionSpec(
                    ".decoy", FIXTURES.pclntab_header() + _PADDING, 0xF0000
                )
            )
            payload = FIXTURES.build_elf(FIXTURES.ImageSpec(sections=sections))
            path = root / "decoy"
            path.write_bytes(payload)
            image = VERIFY.parse_object(path.read_bytes(), "elf")

            with self.assertRaisesRegex(VERIFY.VerificationError, "plausible Go"):
                VERIFY.locate_pclntab(image, ".gopclntab", True)

    def test_classifies_symbol_tables_by_what_survived(self) -> None:
        cases = (
            (["runtime.gopanic", "go:func.*"], "go-names", "go:func.*"),
            (["_mh_execute_header", "dyld_stub_binder"], "loader-only", None),
            ([], "absent", None),
        )
        for symbols, expected_kind, expected_gofunc in cases:
            with self.subTest(symbols=symbols):
                payload = FIXTURES.build_elf(
                    FIXTURES.ImageSpec(
                        sections=[FIXTURES.SectionSpec(".text", b"\x90" * 32, 0x1000)],
                        symbols=symbols,
                    )
                )
                image = VERIFY.parse_object(payload, "elf")
                self.assertEqual(image.symbol_table_kind(), expected_kind)
                self.assertEqual(image.gofunc_symbol(), expected_gofunc)

    def test_finds_the_underscored_gofunc_symbol_a_macho_link_produces(self) -> None:
        payload = FIXTURES.build_macho(
            FIXTURES.ImageSpec(
                sections=[FIXTURES.SectionSpec("__text", b"\x90" * 32, 0x1000)],
                symbols=["go.func.*"],
            )
        )
        image = VERIFY.parse_object(payload, "macho")
        self.assertEqual(image.gofunc_symbol(), "go.func.*")

    def test_rejects_a_container_that_is_not_what_the_manifest_says(self) -> None:
        payload = FIXTURES.build_pe(
            FIXTURES.ImageSpec(sections=[FIXTURES.SectionSpec(".text", b"\x90" * 32, 0x1000)])
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "object format mismatch"):
            VERIFY.parse_object(payload, "elf")


class GoManifestTests(unittest.TestCase):
    def test_accepts_one_artifact_of_every_container_and_magic(self) -> None:
        variants = (
            _variant(),
            _variant(goos="windows"),
            _variant(goos="darwin", goarch="arm64"),
            _variant(buildmode="pie"),
            _variant(go_version="1.15.15", goos="darwin"),
            _variant(go_version="1.16.15"),
            _variant(go_version="1.18.10"),
            _variant(go_version="1.20.14"),
        )
        for variant in variants:
            with (
                self.subTest(variant=variant.key),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                manifest_path = _write(root, _manifest(root, [variant]))

                result = VERIFY.verify_manifest(manifest_path, root)
                self.assertEqual(result.artifact_count, 1)

    def test_applies_the_published_schema_when_it_can(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            applied = VERIFY.validate_against_schema(manifest)
            if not applied:
                self.skipTest("jsonschema is not installed")
            manifest["artifacts"][0]["evidence"]["pclntab_min_lc"] = 2
            with self.assertRaisesRegex(VERIFY.VerificationError, "JSON Schema"):
                VERIFY.validate_against_schema(manifest)

    def test_rejects_a_hash_that_does_not_match_the_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            manifest["artifacts"][0]["sha256"] = "0" * 64
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "SHA-256 mismatch"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_size_that_does_not_match_the_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            manifest["artifacts"][0]["size"] += 1
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "size mismatch"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_magic_the_pinned_toolchain_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            variant = _variant(go_version="1.20.14")
            path = _materialize(root, variant)
            payload = bytearray(path.read_bytes())
            offset = payload.find(struct.pack("<I", 0xFFFFFFF1))
            struct.pack_into("<I", payload, offset, 0xFFFFFFFA)
            path.write_bytes(bytes(payload))
            manifest = {
                "schema_version": 1,
                "corpus": "go-eh",
                "producer": _manifest(root, [])["producer"],
                "artifacts": [BUILD._artifact_record(variant, path, root)],
            }
            manifest["producer"]["toolchains"] = [_toolchain("1.20.14")]
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "magic"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_path_outside_the_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            record = manifest["artifacts"][0]
            moved = record["path"].replace("/exe/", "/exe-x/")
            target = root / Path(*moved.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((root / Path(*record["path"].split("/"))).read_bytes())
            record["path"] = moved
            manifest_path = _write(root, manifest)

            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_build_that_dropped_trimpath(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            flags = manifest["artifacts"][0]["build"]["flags"]
            flags.remove("-trimpath")
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "trimpath|flags"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_stripped_artifact_that_still_names_go_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            variant = _variant(stripped=True)
            spec = FIXTURES.ImageSpec(
                sections=_sections_for(variant, function_count=1500),
                symbols=["runtime.gopanic", "go:func.*"],
            )
            path = root / Path(*variant.path.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(FIXTURES.build_elf(spec))
            manifest = {
                "schema_version": 1,
                "corpus": "go-eh",
                "producer": _manifest(root, [])["producer"],
                "artifacts": [BUILD._artifact_record(variant, path, root)],
            }
            manifest["producer"]["toolchains"] = [_toolchain("1.26.5")]
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "stripped|symbol"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_function_floor_the_table_cannot_meet(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()], function_count=64)
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(
                VERIFY.VerificationError, "min_go_functions"
            ):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_open_coded_defers_claimed_for_an_unoptimized_build(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            variant = _variant(optimization="none")
            manifest = _manifest(root, [variant])
            manifest["artifacts"][0]["neverd"]["min_open_coded_defer_funcs"] = 3
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(
                VERIFY.VerificationError, "open.coded|open_coded"
            ):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_complete_parse_claimed_for_a_go12_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant(go_version="1.15.15")])
            manifest["artifacts"][0]["neverd"]["allowed_parse_status"] = ["complete"]
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(
                VERIFY.VerificationError, "partial|allowed_parse_status"
            ):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_cgo_artifact_with_no_dwarf_unwind_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            variant = _variant(cgo_enabled=True, stripped=False)
            sections = [
                section
                for section in _sections_for(variant, function_count=1500)
                if not section.name.startswith(".eh_frame")
            ]
            spec = FIXTURES.ImageSpec(
                sections=sections,
                symbols=["runtime.gopanic", "go:func.*"],
            )
            path = root / Path(*variant.path.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(FIXTURES.build_elf(spec))
            manifest = {
                "schema_version": 1,
                "corpus": "go-eh",
                "producer": _manifest(root, [])["producer"],
                "artifacts": [BUILD._artifact_record(variant, path, root)],
            }
            manifest["producer"]["toolchains"] = [_toolchain("1.26.5")]
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(
                VERIFY.VerificationError, "unwind|eh_frame"
            ):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_producer_that_omits_a_toolchain_it_used(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            manifest["producer"]["toolchains"] = [_toolchain("1.15.15")]
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "toolchain"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_a_producer_that_lets_goflags_through(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _manifest(root, [_variant()])
            manifest["producer"]["toolchains"][0]["go_env"]["GOFLAGS"] = "-mod=mod"
            manifest_path = _write(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "GOFLAGS"):
                VERIFY.verify_manifest(manifest_path, root)


class GoCompleteMatrixTests(unittest.TestCase):
    def _inventory(self) -> dict:
        return {
            "schema_version": 1,
            "corpus": "go-eh",
            "producer": {
                "repository_revision": "1" * 40,
                "runner_image": "ubuntu24-test",
                "runner_os": "linux",
                "runner_arch": "x64",
                "module_path": "neversight.dev/goeh",
                "module_go_directive": "1.15",
                "package": "./cmd/eh_probe",
                "toolchains": [
                    _toolchain(version) for version in MATRIX.pinned_go_versions()
                ],
            },
            "artifacts": [
                {"path": variant.path} for variant in MATRIX.expected_variants()
            ],
        }

    def test_accepts_the_declared_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = self._inventory()
            self.assertEqual(
                len(manifest["artifacts"]), len(MATRIX.expected_variants())
            )
            VERIFY.verify_complete_matrix(_write(root, manifest))

    def test_rejects_a_missing_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = self._inventory()
            manifest["artifacts"] = [
                artifact
                for artifact in manifest["artifacts"]
                if "/go1.18.10/" not in artifact["path"]
            ]
            with self.assertRaisesRegex(VERIFY.VerificationError, "incomplete"):
                VERIFY.verify_complete_matrix(_write(root, manifest))

    def test_rejects_a_duplicate_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = self._inventory()
            manifest["artifacts"].append(dict(manifest["artifacts"][0]))
            with self.assertRaisesRegex(VERIFY.VerificationError, "duplicate"):
                VERIFY.verify_complete_matrix(_write(root, manifest))

    def test_rejects_an_unpinned_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = self._inventory()
            manifest["producer"]["toolchains"].pop()
            with self.assertRaisesRegex(VERIFY.VerificationError, "pinned set"):
                VERIFY.verify_complete_matrix(_write(root, manifest))


class GoMergeTests(unittest.TestCase):
    def test_unions_the_toolchains_the_fragments_installed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fragments = []
            for version in ("1.16.15", "1.26.5"):
                manifest = _manifest(root, [_variant(go_version=version)])
                fragments.append(
                    _write(root, manifest, f"fragments/go{version}.json")
                )

            output = root / "manifests/go-eh.json"
            result = VERIFY.merge_manifests(fragments, output, root)

            self.assertEqual(result.artifact_count, 2)
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                [entry["go_version"] for entry in merged["producer"]["toolchains"]],
                ["1.16.15", "1.26.5"],
            )

    def test_rejects_fragments_from_different_producer_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fragments = []
            for index, version in enumerate(("1.16.15", "1.26.5")):
                manifest = _manifest(root, [_variant(go_version=version)])
                manifest["producer"]["repository_revision"] = str(index + 1) * 40
                fragments.append(
                    _write(root, manifest, f"fragments/go{version}.json")
                )

            with self.assertRaisesRegex(VERIFY.VerificationError, "producer"):
                VERIFY.merge_manifests(fragments, root / "manifests/go-eh.json", root)


if __name__ == "__main__":
    unittest.main()
