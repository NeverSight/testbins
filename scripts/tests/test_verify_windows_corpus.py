# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS_ROOT = Path(__file__).parents[1]
for module_name in ("windows_matrix", "verify_windows_corpus"):
    module_path = SCRIPTS_ROOT / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

MATRIX = sys.modules["windows_matrix"]
VERIFY = sys.modules["verify_windows_corpus"]


_MACHINES = {
    "x86": (0x014C, 0x10B),
    "x86_64": (0x8664, 0x20B),
    "arm": (0x01C4, 0x10B),
    "aarch64": (0xAA64, 0x20B),
}

_TARGET_TRIPLES = {
    "x86": "i686-pc-windows-msvc",
    "x86_64": "x86_64-pc-windows-msvc",
    "arm": "thumbv7-pc-windows-msvc",
    "aarch64": "aarch64-pc-windows-msvc",
}

_LINKER_MACHINES = {
    "x86": "X86",
    "x86_64": "X64",
    "arm": "ARM",
    "aarch64": "ARM64",
}


def _write_minimal_pe(
    path: Path,
    architecture: str = "x86_64",
    import_names: tuple[str, ...] = (),
    *,
    arm_unwind_word: int | None = None,
    arm_xdata_words: tuple[int, ...] = (),
    exception_size: int | None = None,
    unwind_section_name: bytes = b".xdata",
    xdata_raw_size: int = 0x300,
) -> None:
    machine, magic = _MACHINES[architecture]
    pe32_plus = magic == 0x20B
    optional_size = 0xF0 if pe32_plus else 0xE0
    data = bytearray(0xA00)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)

    pe = 0x80
    data[pe : pe + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", data, pe + 4, machine, 3, 0, 0, 0, optional_size, 0x0022
    )
    optional = pe + 24
    struct.pack_into("<H", data, optional, magic)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    if pe32_plus:
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
        directory_count_offset = optional + 108
        directory_offset = optional + 112
    else:
        struct.pack_into("<I", data, optional + 28, 0x400000)
        directory_count_offset = optional + 92
        directory_offset = optional + 96
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x4000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, directory_count_offset, 16)

    has_exception_table = architecture != "x86"
    if has_exception_table:
        default_size = 12 if architecture == "x86_64" else 8
        struct.pack_into(
            "<II",
            data,
            directory_offset + 3 * 8,
            0x2000,
            default_size if exception_size is None else exception_size,
        )
    if import_names:
        struct.pack_into("<II", data, directory_offset + 8, 0x3000, 0x100)

    section_table = optional + optional_size
    sections = (
        (b".text", 0x1000, 0x200, 0x200, 0x200, 0x60000020),
        (b".pdata", 0x2000, 0x200, 0x200, 0x400, 0x40000040),
        (
            unwind_section_name,
            0x3000,
            xdata_raw_size,
            xdata_raw_size,
            0x600,
            0x40000040,
        ),
    )
    for index, (name, rva, virtual_size, raw_size, raw_offset, flags) in enumerate(
        sections
    ):
        offset = section_table + index * 40
        data[offset : offset + 8] = name.ljust(8, b"\0")
        struct.pack_into(
            "<IIIIIIHHI",
            data,
            offset + 8,
            virtual_size,
            rva,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            flags,
        )

    if architecture == "x86_64":
        struct.pack_into("<III", data, 0x400, 0x1000, 0x1010, 0x3000)
    elif architecture in ("arm", "aarch64"):
        packed = arm_unwind_word if arm_unwind_word is not None else ((4 << 2) | 1)
        struct.pack_into("<II", data, 0x400, 0x1000, packed)
        for index, word in enumerate(arm_xdata_words):
            struct.pack_into("<I", data, 0x600 + index * 4, word)

    if import_names:
        xdata = 0x600
        descriptor_original_thunk = 0x3040
        descriptor_name = 0x3080
        descriptor_first_thunk = 0x3060
        struct.pack_into(
            "<IIIII",
            data,
            xdata,
            descriptor_original_thunk,
            0,
            0,
            descriptor_name,
            descriptor_first_thunk,
        )
        data[xdata + 0x80 : xdata + 0x80 + 15] = b"vcruntime140\0\0\0"
        entry_size = 8 if pe32_plus else 4
        name_offset = xdata + 0xA0
        for index, import_name in enumerate(import_names):
            name_rva = 0x3000 + name_offset - xdata
            entry_format = "<Q" if pe32_plus else "<I"
            struct.pack_into(
                entry_format, data, xdata + 0x40 + index * entry_size, name_rva
            )
            struct.pack_into(
                entry_format, data, xdata + 0x60 + index * entry_size, name_rva
            )
            struct.pack_into("<H", data, name_offset, 0)
            encoded_name = import_name.encode("ascii") + b"\0"
            data[name_offset + 2 : name_offset + 2 + len(encoded_name)] = encoded_name
            name_offset += 2 + len(encoded_name)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _artifact_path(
    root: Path,
    *,
    toolchain: str,
    architecture: str,
    cxx_format: str,
    security_cookie: bool,
    optimization: str,
    name: str = "cxx_eh_probe",
) -> Path:
    suite = "abi-probe" if name.endswith("_probe") else "windows-seh-tests"
    extension = ".dll" if name == "xframe_eh_dll" else ".exe"
    cookie_label = "gs" if security_cookie else "no-gs"
    filename = (
        "-".join(
            (
                name,
                toolchain,
                architecture,
                cxx_format,
                cookie_label,
                optimization,
            )
        )
        + extension
    )
    return (
        root
        / "corpus/windows-eh"
        / toolchain
        / architecture
        / cxx_format
        / cookie_label
        / optimization
        / suite
        / filename
    )


def _valid_manifest(
    root: Path,
    artifact: Path,
    *,
    toolchain: str = "msvc",
    architecture: str = "x86_64",
    cxx_format: str = "fh3",
    security_cookie: bool = False,
    optimization: str = "o0",
    name: str = "cxx_eh_probe",
) -> dict:
    payload = artifact.read_bytes()
    is_x64 = architecture == "x86_64"
    is_x86 = architecture == "x86"
    is_arm = architecture in ("arm", "aarch64")
    personality = "__CxxFrameHandler3" if is_x64 else None
    compiler_name = "cl.exe" if toolchain == "msvc" else "clang-cl.exe"
    linker_name = "link.exe" if toolchain == "msvc" else "lld-link.exe"
    execution = (
        "passed" if architecture in ("x86", "x86_64") else "not-run-cross-target"
    )
    validation_level = (
        "exception-graph" if is_x64 else "load-only" if is_x86 else "unwind-only"
    )
    required_sections = [".text"] if is_x86 else [".pdata"]
    required_imports = [[personality]] if personality else []
    compiler_flags = [
        "/Od" if optimization == "o0" else "/O2",
        "/GS" if security_cookie else "/GS-",
    ]
    if toolchain == "msvc" and is_x64:
        compiler_flags.append("/d2FH4" if cxx_format == "fh4" else "/d2FH4-")
    if toolchain == "clang-cl":
        compiler_flags.append(f"--target={_TARGET_TRIPLES[architecture]}")
    return {
        "schema_version": 2,
        "corpus": "windows-eh",
        "source": {
            "windows_seh_tests": {
                "repository": "https://github.com/microsoft/windows_seh_tests.git",
                "revision": "2e8b7bb654d9aebf03f28801c4b1400489ba6a0c",
                "license": "MIT",
            }
        },
        "producer": {
            "repository_revision": "1" * 40,
            "runner_image": "windows-2022",
            "runner_arch": "x64",
        },
        "artifacts": [
            {
                "path": artifact.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "architecture": architecture,
                "suite": "abi-probe"
                if name.endswith("_probe")
                else "windows-seh-tests",
                "name": name,
                "kind": "cxx" if name == "cxx_eh_probe" else "seh",
                "build": {
                    "toolchain": toolchain,
                    "compiler": {
                        "name": compiler_name,
                        "product_version": "test-compiler",
                        "file_version": "test-compiler",
                    },
                    "linker": {
                        "name": linker_name,
                        "product_version": "test-linker",
                        "file_version": "test-linker",
                    },
                    "target_triple": _TARGET_TRIPLES[architecture],
                    "optimization": optimization,
                    "security_cookie": security_cookie,
                    "cxx_format": cxx_format,
                    "execution": execution,
                    "compiler_flags": compiler_flags,
                    "linker_flags": [
                        "/INCREMENTAL:NO",
                        f"/MACHINE:{_LINKER_MACHINES[architecture]}",
                    ],
                },
                "evidence": {
                    "required_sections": required_sections,
                    "required_imports_any": required_imports,
                    "require_exception_directory": not is_x86,
                    "require_unwind_records": is_x64 or is_arm,
                },
                "neverd": {
                    "validation_level": validation_level,
                    "allowed_parse_status": ["complete"],
                    "personalities_any": [personality] if personality else [],
                    "min_exception_functions": 0 if is_x86 else 1,
                    "min_cxx_functions": 1 if is_x64 else 0,
                    "min_try_blocks": 1 if is_x64 else 0,
                    "min_seh_scopes": 0,
                },
            }
        ],
    }


def _write_manifest(root: Path, manifest: dict) -> Path:
    path = root / "manifests/windows-eh.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _complete_inventory() -> dict:
    artifacts = []
    for cell in MATRIX.expected_cells():
        for name in cell.artifact_names:
            security_cookie = cell.security_cookie == "on"
            artifacts.append(
                {
                    "path": _artifact_path(
                        Path("."),
                        toolchain=cell.toolchain,
                        architecture=cell.architecture,
                        cxx_format=cell.cxx_format,
                        security_cookie=security_cookie,
                        optimization=cell.optimization,
                        name=name,
                    ).as_posix(),
                    "architecture": cell.architecture,
                    "name": name,
                    "build": {
                        "toolchain": cell.toolchain,
                        "optimization": cell.optimization,
                        "security_cookie": security_cookie,
                        "cxx_format": cell.cxx_format,
                    },
                }
            )
    return {"schema_version": 2, "corpus": "windows-eh", "artifacts": artifacts}


class VerifyWindowsCorpusTests(unittest.TestCase):
    def test_accepts_schema_v2_x64_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="x86_64",
                cxx_format="fh3",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, import_names=("__CxxFrameHandler3",))
            manifest_path = _write_manifest(root, _valid_manifest(root, artifact))

            result = VERIFY.verify_manifest(manifest_path, root)

            self.assertEqual(result.artifact_count, 1)
            self.assertEqual(result.total_bytes, artifact.stat().st_size)

    def test_accepts_all_four_pe_machine_targets(self) -> None:
        combinations = (
            ("x86", "native", "load-only"),
            ("x86_64", "fh3", "exception-graph"),
            ("arm", "native", "unwind-only"),
            ("aarch64", "native", "unwind-only"),
        )
        for architecture, cxx_format, validation_level in combinations:
            with (
                self.subTest(architecture=architecture),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                artifact = _artifact_path(
                    root,
                    toolchain="msvc",
                    architecture=architecture,
                    cxx_format=cxx_format,
                    security_cookie=False,
                    optimization="o0",
                )
                imports = ("__CxxFrameHandler3",) if architecture == "x86_64" else ()
                _write_minimal_pe(artifact, architecture, imports)
                manifest = _valid_manifest(
                    root,
                    artifact,
                    architecture=architecture,
                    cxx_format=cxx_format,
                )
                self.assertEqual(
                    manifest["artifacts"][0]["neverd"]["validation_level"],
                    validation_level,
                )
                manifest_path = _write_manifest(root, manifest)

                result = VERIFY.verify_manifest(manifest_path, root)
                self.assertEqual(result.artifact_count, 1)

    def test_accepts_linker_merged_unwind_data_sections(self) -> None:
        combinations = (
            ("x86_64", "fh3", ("__CxxFrameHandler3",)),
            ("aarch64", "native", ()),
        )
        for architecture, cxx_format, imports in combinations:
            with (
                self.subTest(architecture=architecture),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                artifact = _artifact_path(
                    root,
                    toolchain="msvc",
                    architecture=architecture,
                    cxx_format=cxx_format,
                    security_cookie=False,
                    optimization="o0",
                )
                _write_minimal_pe(
                    artifact,
                    architecture,
                    imports,
                    unwind_section_name=b".rdata",
                )
                manifest = _valid_manifest(
                    root,
                    artifact,
                    architecture=architecture,
                    cxx_format=cxx_format,
                )
                manifest["artifacts"][0]["evidence"]["required_sections"] = [".pdata"]
                manifest_path = _write_manifest(root, manifest)

                result = VERIFY.verify_manifest(manifest_path, root)
                self.assertEqual(result.artifact_count, 1)

    def test_accepts_valid_gs_seh_personality_alternatives(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="x86_64",
                cxx_format="fh3",
                security_cookie=True,
                optimization="o2",
                name="seh_probe",
            )
            _write_minimal_pe(
                artifact,
                import_names=("__C_specific_handler", "__security_check_cookie"),
            )
            manifest = _valid_manifest(
                root,
                artifact,
                architecture="x86_64",
                cxx_format="fh3",
                security_cookie=True,
                optimization="o2",
                name="seh_probe",
            )
            record = manifest["artifacts"][0]
            record["build"]["compiler_flags"].remove("/d2FH4-")
            personalities = ["__C_specific_handler", "__GSHandlerCheck_SEH"]
            record["evidence"]["required_imports_any"] = [
                personalities,
                ["__security_check_cookie"],
            ]
            record["neverd"].update(
                {
                    "personalities_any": personalities,
                    "min_cxx_functions": 0,
                    "min_try_blocks": 0,
                    "min_seh_scopes": 1,
                }
            )
            manifest_path = _write_manifest(root, manifest)

            result = VERIFY.verify_manifest(manifest_path, root)
            self.assertEqual(result.artifact_count, 1)

    def test_rejects_truncated_arm_runtime_function_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="arm",
                cxx_format="native",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, "arm", exception_size=7)
            manifest = _valid_manifest(
                root,
                artifact,
                toolchain="msvc",
                architecture="arm",
                cxx_format="native",
            )
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "runtime-function"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_arm_unpacked_reference_outside_xdata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="aarch64",
                cxx_format="native",
                security_cookie=False,
                optimization="o2",
            )
            _write_minimal_pe(artifact, "aarch64", arm_unwind_word=0x7000)
            manifest = _valid_manifest(
                root,
                artifact,
                architecture="aarch64",
                cxx_format="native",
                optimization="o2",
            )
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "xdata"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_truncated_arm_exception_handler_parameter(self) -> None:
        for architecture, code_words_bit in (
            ("arm", 1 << 28),
            ("aarch64", 1 << 27),
        ):
            with (
                self.subTest(architecture=architecture),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                artifact = _artifact_path(
                    root,
                    toolchain="msvc",
                    architecture=architecture,
                    cxx_format="native",
                    security_cookie=False,
                    optimization="o0",
                )
                first_word = 4 | (1 << 20) | (1 << 21) | code_words_bit
                _write_minimal_pe(
                    artifact,
                    architecture,
                    arm_unwind_word=0x3000,
                    arm_xdata_words=(first_word, 0, 0x1234),
                    xdata_raw_size=12,
                )
                manifest = _valid_manifest(
                    root,
                    artifact,
                    architecture=architecture,
                    cxx_format="native",
                )
                manifest_path = _write_manifest(root, manifest)

                with self.assertRaisesRegex(
                    VERIFY.VerificationError, "xdata body is truncated"
                ):
                    VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_clang_cl_fh4_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="clang-cl",
                architecture="x86_64",
                cxx_format="fh4",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, import_names=("__CxxFrameHandler4",))
            manifest = _valid_manifest(
                root,
                artifact,
                toolchain="clang-cl",
                architecture="x86_64",
                cxx_format="fh4",
            )
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(
                VERIFY.VerificationError, "unsupported C\\+\\+ EH format"
            ):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_axis_that_disagrees_with_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="x86_64",
                cxx_format="fh3",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, import_names=("__CxxFrameHandler3",))
            manifest = _valid_manifest(root, artifact)
            manifest["artifacts"][0]["build"]["optimization"] = "o2"
            manifest["artifacts"][0]["build"]["compiler_flags"][0] = "/O2"
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "artifact layout"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_cross_target_execution_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="arm",
                cxx_format="native",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, "arm")
            manifest = _valid_manifest(
                root, artifact, architecture="arm", cxx_format="native"
            )
            manifest["artifacts"][0]["build"]["execution"] = "passed"
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "execution"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_missing_per_artifact_tool_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="x86_64",
                cxx_format="fh3",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, import_names=("__CxxFrameHandler3",))
            manifest = _valid_manifest(root, artifact)
            del manifest["artifacts"][0]["build"]["compiler"]
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "compiler"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = _artifact_path(
                root,
                toolchain="msvc",
                architecture="x86_64",
                cxx_format="fh3",
                security_cookie=False,
                optimization="o0",
            )
            _write_minimal_pe(artifact, import_names=("__CxxFrameHandler3",))
            manifest = _valid_manifest(root, artifact)
            manifest["artifacts"][0]["sha256"] = "0" * 64
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "SHA-256 mismatch"):
                VERIFY.verify_manifest(manifest_path, root)

    def test_complete_matrix_accepts_32_cells_and_168_capability_artifacts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _complete_inventory()
            self.assertEqual(len(manifest["artifacts"]), 168)
            manifest_path = _write_manifest(root, manifest)

            VERIFY.verify_complete_matrix(manifest_path)

    def test_complete_matrix_rejects_missing_cell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _complete_inventory()
            del manifest["artifacts"][:6]
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "matrix"):
                VERIFY.verify_complete_matrix(manifest_path)

    def test_complete_matrix_rejects_duplicate_artifact_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = _complete_inventory()
            manifest["artifacts"].append(dict(manifest["artifacts"][0]))
            manifest_path = _write_manifest(root, manifest)

            with self.assertRaisesRegex(VERIFY.VerificationError, "duplicate"):
                VERIFY.verify_complete_matrix(manifest_path)

    def test_merges_msvc_and_clang_cl_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fragments = []
            for toolchain in ("msvc", "clang-cl"):
                artifact = _artifact_path(
                    root,
                    toolchain=toolchain,
                    architecture="x86_64",
                    cxx_format="fh3",
                    security_cookie=False,
                    optimization="o0",
                )
                _write_minimal_pe(artifact, import_names=("__CxxFrameHandler3",))
                manifest = _valid_manifest(root, artifact, toolchain=toolchain)
                fragment = root / "fragments" / f"{toolchain}.json"
                fragment.parent.mkdir(parents=True, exist_ok=True)
                fragment.write_text(json.dumps(manifest), encoding="utf-8")
                fragments.append(fragment)

            output = root / "manifests/windows-eh.json"
            result = VERIFY.merge_manifests(fragments, output, root)

            self.assertEqual(result.artifact_count, 2)
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                {entry["build"]["toolchain"] for entry in merged["artifacts"]},
                {"msvc", "clang-cl"},
            )


if __name__ == "__main__":
    unittest.main()
