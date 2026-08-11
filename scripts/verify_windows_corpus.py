#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Validate the Windows multi-toolchain exception corpus and its manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from windows_matrix import artifact_cell_key, expected_cells, validate_cell


class VerificationError(ValueError):
    """Raised when the corpus contract or a PE artifact is invalid."""


_ARTIFACT_LAYOUT = {
    "xcpt4": ("windows-seh-tests", ".exe", "mixed"),
    "nested_collided": ("windows-seh-tests", ".exe", "seh"),
    "xframe_eh_dll": ("windows-seh-tests", ".dll", "seh"),
    "xframe_eh_exe": ("windows-seh-tests", ".exe", "seh"),
    "seh_probe": ("abi-probe", ".exe", "seh"),
    "cxx_eh_probe": ("abi-probe", ".exe", "cxx"),
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

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REVISION_RE = re.compile(r"[0-9a-f]{40}")
_MAX_RUNTIME_FUNCTIONS = 1 << 20
_MAX_XDATA_WORDS = 1 << 20


@dataclass(frozen=True)
class VerificationResult:
    artifact_count: int
    total_bytes: int


@dataclass(frozen=True)
class _Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    def contains_rva(self, rva: int, size: int = 1) -> bool:
        if size < 0 or rva < self.virtual_address:
            return False
        delta = rva - self.virtual_address
        return delta <= self.raw_size and size <= self.raw_size - delta


class _PEImage:
    _MACHINE_NAMES = {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C4: "arm",
        0xAA64: "aarch64",
    }

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.machine = 0
        self.architecture = "unknown"
        self.sections: dict[str, _Section] = {}
        self.imports: set[str] = set()
        self._directories: list[tuple[int, int]] = []
        self._size_of_headers = 0
        self._image_base = 0
        self._is_pe32_plus = False
        self._parse()

    def _unpack(self, fmt: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self._payload):
            raise VerificationError("truncated PE structure")
        return struct.unpack_from(fmt, self._payload, offset)

    def _parse(self) -> None:
        if len(self._payload) < 0x40 or self._payload[:2] != b"MZ":
            raise VerificationError("artifact is not a DOS/PE image")
        (pe_offset,) = self._unpack("<I", 0x3C)
        if pe_offset + 24 > len(self._payload):
            raise VerificationError("PE header is out of bounds")
        if self._payload[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise VerificationError("invalid PE signature")

        (
            self.machine,
            section_count,
            _timestamp,
            _symbol_offset,
            _symbol_count,
            optional_size,
            _characteristics,
        ) = self._unpack("<HHIIIHH", pe_offset + 4)
        self.architecture = self._MACHINE_NAMES.get(self.machine, "unknown")
        if self.architecture == "unknown":
            raise VerificationError(f"unsupported PE machine 0x{self.machine:04x}")
        if not 1 <= section_count <= 96:
            raise VerificationError("invalid PE section count")

        optional_offset = pe_offset + 24
        if optional_offset + optional_size > len(self._payload):
            raise VerificationError("optional header is out of bounds")
        (magic,) = self._unpack("<H", optional_offset)
        if magic == 0x20B:
            directory_count_offset = optional_offset + 108
            directory_offset = optional_offset + 112
            self._is_pe32_plus = True
            (self._image_base,) = self._unpack("<Q", optional_offset + 24)
        elif magic == 0x10B:
            directory_count_offset = optional_offset + 92
            directory_offset = optional_offset + 96
            (self._image_base,) = self._unpack("<I", optional_offset + 28)
        else:
            raise VerificationError("unsupported PE optional-header magic")

        if self._is_pe32_plus != (self.architecture in ("x86_64", "aarch64")):
            raise VerificationError("PE optional-header bitness disagrees with machine")
        (self._size_of_headers,) = self._unpack("<I", optional_offset + 60)
        (directory_count,) = self._unpack("<I", directory_count_offset)
        directory_count = min(directory_count, 16)
        if directory_offset + directory_count * 8 > optional_offset + optional_size:
            raise VerificationError("PE data directories exceed the optional header")
        for index in range(directory_count):
            rva, size = self._unpack("<II", directory_offset + index * 8)
            self._directories.append((int(rva), int(size)))

        section_offset = optional_offset + optional_size
        if section_offset + section_count * 40 > len(self._payload):
            raise VerificationError("PE section table is truncated")
        for index in range(section_count):
            offset = section_offset + index * 40
            raw_name = self._payload[offset : offset + 8].split(b"\0", 1)[0]
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError as error:
                raise VerificationError("PE section name is not ASCII") from error
            virtual_size, virtual_address, raw_size, raw_offset = self._unpack(
                "<IIII", offset + 8
            )
            (characteristics,) = self._unpack("<I", offset + 36)
            if not name or name in self.sections:
                raise VerificationError("empty or duplicate PE section name")
            if raw_size and (
                raw_offset > len(self._payload)
                or raw_size > len(self._payload) - raw_offset
            ):
                raise VerificationError(f"section {name} raw data is out of bounds")
            self.sections[name] = _Section(
                name,
                int(virtual_address),
                int(virtual_size),
                int(raw_offset),
                int(raw_size),
                int(characteristics),
            )

        self._parse_imports()

    def section_for_rva(self, rva: int, size: int = 1) -> _Section | None:
        for section in self.sections.values():
            if section.contains_rva(rva, size):
                return section
        return None

    def rva_to_offset(self, rva: int, size: int) -> int:
        if size < 0 or rva < 0:
            raise VerificationError("negative PE range")
        if rva < self._size_of_headers:
            if rva > len(self._payload) or size > len(self._payload) - rva:
                raise VerificationError("header RVA is not file-backed")
            return rva
        section = self.section_for_rva(rva, size)
        if section is None:
            raise VerificationError(f"RVA 0x{rva:x} is not file-backed")
        return section.raw_offset + (rva - section.virtual_address)

    def directory(self, index: int) -> tuple[int, int]:
        if index >= len(self._directories):
            return (0, 0)
        return self._directories[index]

    def has_file_backed_directory(self, index: int) -> bool:
        rva, size = self.directory(index)
        if not rva or not size:
            return False
        self.rva_to_offset(rva, size)
        return True

    def verify_security_cookie(self) -> None:
        load_config_rva, load_config_size = self.directory(10)
        pointer_size = 8 if self._is_pe32_plus else 4
        cookie_field_offset = 88 if self._is_pe32_plus else 60
        minimum_size = cookie_field_offset + pointer_size
        if not load_config_rva or load_config_size < minimum_size:
            raise VerificationError(
                "PE load-config security cookie field is absent or truncated"
            )

        load_config_offset = self.rva_to_offset(load_config_rva, minimum_size)
        (reported_size,) = self._unpack("<I", load_config_offset)
        if reported_size < minimum_size:
            raise VerificationError(
                "PE load-config security cookie field is outside the structure"
            )
        (cookie_va,) = self._unpack(
            "<Q" if self._is_pe32_plus else "<I",
            load_config_offset + cookie_field_offset,
        )
        if cookie_va < self._image_base:
            raise VerificationError("PE load-config security cookie VA is invalid")

        cookie_rva = cookie_va - self._image_base
        cookie_section = self.section_for_rva(cookie_rva, pointer_size)
        if (
            cookie_section is None
            or cookie_section.executable
            or not cookie_section.writable
        ):
            raise VerificationError(
                "PE load-config security cookie is not backed by writable data"
            )
        cookie_offset = self.rva_to_offset(cookie_rva, pointer_size)
        (cookie_value,) = self._unpack(
            "<Q" if self._is_pe32_plus else "<I", cookie_offset
        )
        if cookie_value == 0:
            raise VerificationError("PE load-config security cookie is zero")

    def _read_c_string(self, offset: int, limit: int = 4096) -> str:
        if offset < 0 or offset >= len(self._payload):
            raise VerificationError("PE string is out of bounds")
        end_limit = min(len(self._payload), offset + limit)
        end = self._payload.find(b"\0", offset, end_limit)
        if end == -1:
            raise VerificationError("unterminated PE string")
        try:
            return self._payload[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise VerificationError("PE import name is not ASCII") from error

    def _parse_imports(self) -> None:
        import_rva, import_size = self.directory(1)
        if not import_rva or not import_size:
            return
        descriptor_offset = self.rva_to_offset(import_rva, min(import_size, 20))
        max_descriptors = min(import_size // 20, 4096)
        for descriptor_index in range(max_descriptors):
            offset = descriptor_offset + descriptor_index * 20
            original_thunk, timestamp, forwarder, name_rva, first_thunk = self._unpack(
                "<IIIII", offset
            )
            if not any((original_thunk, timestamp, forwarder, name_rva, first_thunk)):
                return
            self._read_c_string(self.rva_to_offset(name_rva, 1))
            thunk_rva = original_thunk or first_thunk
            entry_size = 8 if self._is_pe32_plus else 4
            ordinal_mask = 1 << (entry_size * 8 - 1)
            for thunk_index in range(65536):
                thunk_offset = self.rva_to_offset(
                    thunk_rva + thunk_index * entry_size, entry_size
                )
                (value,) = self._unpack("<Q" if entry_size == 8 else "<I", thunk_offset)
                if value == 0:
                    break
                if value & ordinal_mask:
                    continue
                hint_name_offset = self.rva_to_offset(value, 3)
                self.imports.add(self._read_c_string(hint_name_offset + 2))
            else:
                raise VerificationError("PE import thunk budget exceeded")
        raise VerificationError("PE import descriptor table is unterminated")

    def verify_unwind_records(self) -> int:
        exception_rva, exception_size = self.directory(3)
        if not exception_rva or not exception_size:
            raise VerificationError("PE exception directory is absent")
        if self.architecture == "x86_64":
            return self._verify_x64_runtime_functions(exception_rva, exception_size)
        if self.architecture in ("arm", "aarch64"):
            return self._verify_arm_runtime_functions(exception_rva, exception_size)
        raise VerificationError(
            f"{self.architecture} does not use table-based runtime-function records"
        )

    def _verify_x64_runtime_functions(self, rva: int, size: int) -> int:
        entry_size = 12
        if size % entry_size != 0:
            raise VerificationError("misaligned x64 runtime-function table")
        count = size // entry_size
        if not 1 <= count <= _MAX_RUNTIME_FUNCTIONS:
            raise VerificationError("invalid x64 runtime-function count")
        offset = self.rva_to_offset(rva, size)
        seen_zero = False
        verified = 0
        for index in range(count):
            begin, end, unwind_rva = self._unpack("<III", offset + index * entry_size)
            if begin == end == unwind_rva == 0:
                seen_zero = True
                continue
            if seen_zero:
                raise VerificationError(
                    "x64 runtime-function table has interior padding"
                )
            if begin >= end:
                raise VerificationError("x64 runtime-function code range is invalid")
            code_section = self.section_for_rva(begin, end - begin)
            if code_section is None or not code_section.executable:
                raise VerificationError(
                    "x64 runtime-function code range is not executable"
                )
            unwind_section = self.section_for_rva(unwind_rva, 4)
            if unwind_section is None or unwind_section.executable:
                raise VerificationError(
                    "x64 unwind RVA is not backed by non-executable data"
                )
            verified += 1
        if verified == 0:
            raise VerificationError("x64 runtime-function table is empty")
        return verified

    def _verify_arm_runtime_functions(self, rva: int, size: int) -> int:
        entry_size = 8
        if size % entry_size != 0:
            raise VerificationError("misaligned ARM runtime-function table")
        count = size // entry_size
        if not 1 <= count <= _MAX_RUNTIME_FUNCTIONS:
            raise VerificationError("invalid ARM runtime-function count")
        offset = self.rva_to_offset(rva, size)
        seen_zero = False
        verified = 0
        for index in range(count):
            begin, unwind_word = self._unpack("<II", offset + index * entry_size)
            if begin == unwind_word == 0:
                seen_zero = True
                continue
            if seen_zero:
                raise VerificationError(
                    "ARM runtime-function table has interior padding"
                )
            flag = unwind_word & 0x3
            if flag == 3:
                raise VerificationError("ARM runtime-function uses reserved flags")
            if flag == 0:
                length = self._verify_arm_xdata(unwind_word & ~0x3)
            else:
                scale = 4 if self.architecture == "aarch64" else 2
                length = ((unwind_word & 0x00001FFC) >> 2) * scale
            if length == 0:
                raise VerificationError("ARM runtime-function has zero length")
            code_rva = begin & ~1 if self.architecture == "arm" else begin
            code_section = self.section_for_rva(code_rva, length)
            if code_section is None or not code_section.executable:
                raise VerificationError(
                    "ARM runtime-function code range is not executable"
                )
            verified += 1
        if verified == 0:
            raise VerificationError("ARM runtime-function table is empty")
        return verified

    def _verify_arm_xdata(self, xdata_rva: int) -> int:
        section = self.section_for_rva(xdata_rva, 4)
        if section is None or section.executable:
            raise VerificationError(
                "ARM xdata RVA is not backed by non-executable data"
            )
        offset = self.rva_to_offset(xdata_rva, 4)
        (first_word,) = self._unpack("<I", offset)
        if ((first_word >> 18) & 0x3) != 0:
            raise VerificationError("ARM xdata version is unsupported")

        if self.architecture == "aarch64":
            header_words = 1 if first_word & 0xFFC00000 else 2
            function_length = (first_word & 0x0003FFFF) * 4
            short_epilogues = (first_word >> 22) & 0x1F
            short_codes = (first_word >> 27) & 0x1F
        else:
            header_words = 1 if first_word & 0xFF800000 else 2
            function_length = (first_word & 0x0003FFFF) * 2
            short_epilogues = (first_word >> 23) & 0x1F
            short_codes = (first_word >> 28) & 0x0F
        if function_length == 0:
            raise VerificationError("ARM xdata function length is zero")

        epilogue_count = short_epilogues
        code_words = short_codes
        if header_words == 2:
            second_offset = self.rva_to_offset(xdata_rva, 8) + 4
            (second_word,) = self._unpack("<I", second_offset)
            epilogue_count = second_word & 0xFFFF
            code_words = (second_word >> 16) & 0xFF
        has_single_epilogue = bool(first_word & 0x00200000)
        has_handler = bool(first_word & 0x00100000)
        total_words = (
            header_words
            + (0 if has_single_epilogue else epilogue_count)
            + code_words
            + (2 if has_handler else 0)
        )
        if total_words <= 0 or total_words > _MAX_XDATA_WORDS:
            raise VerificationError("ARM xdata structural size is invalid")
        total_bytes = total_words * 4
        body_section = self.section_for_rva(xdata_rva, total_bytes)
        if body_section is None or body_section.executable:
            raise VerificationError("ARM xdata body is truncated")
        self.rva_to_offset(xdata_rva, total_bytes)
        return function_length


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context} must be an object")
    return value


def _require_array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{context} must be an array")
    return value


def _require_string(container: dict[str, Any], key: str, context: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{context}.{key} must be a non-empty string")
    return value


def _require_bool(container: dict[str, Any], key: str, context: str) -> bool:
    value = container.get(key)
    if not isinstance(value, bool):
        raise VerificationError(f"{context}.{key} must be boolean")
    return value


def _require_nonnegative_int(container: dict[str, Any], key: str, context: str) -> int:
    value = container.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise VerificationError(f"{context}.{key} must be a non-negative integer")
    return value


def _require_string_array(
    container: dict[str, Any], key: str, context: str, *, allow_empty: bool
) -> list[str]:
    values = _require_array(container.get(key), f"{context}.{key}")
    if not allow_empty and not values:
        raise VerificationError(f"{context}.{key} must not be empty")
    if any(not isinstance(value, str) or not value for value in values):
        raise VerificationError(f"{context}.{key} must contain non-empty strings")
    return list(values)


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read manifest {path}: {error}") from error
    return _require_object(payload, "manifest")


def _validate_manifest_identity(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 2:
        raise VerificationError("unsupported manifest schema_version")
    if manifest.get("corpus") != "windows-eh":
        raise VerificationError("unsupported corpus identity")


def _validate_source_and_producer(manifest: dict[str, Any]) -> None:
    source = _require_object(manifest.get("source"), "source")
    upstream = _require_object(
        source.get("windows_seh_tests"), "source.windows_seh_tests"
    )
    _require_string(upstream, "repository", "source.windows_seh_tests")
    revision = _require_string(upstream, "revision", "source.windows_seh_tests")
    if not _REVISION_RE.fullmatch(revision):
        raise VerificationError("source.windows_seh_tests.revision must be a full SHA")
    _require_string(upstream, "license", "source.windows_seh_tests")

    producer = _require_object(manifest.get("producer"), "producer")
    producer_revision = _require_string(producer, "repository_revision", "producer")
    if not _REVISION_RE.fullmatch(producer_revision):
        raise VerificationError("producer.repository_revision must be a full SHA")
    _require_string(producer, "runner_image", "producer")
    _require_string(producer, "runner_arch", "producer")


def _validate_tool_identity(value: Any, context: str, *, expected_name: str) -> None:
    identity = _require_object(value, context)
    name = _require_string(identity, "name", context)
    if name.lower() != expected_name.lower():
        raise VerificationError(
            f"{context}.name is {name!r}, expected {expected_name!r}"
        )
    _require_string(identity, "product_version", context)
    _require_string(identity, "file_version", context)


def _expected_personalities(
    *, toolchain: str, cxx_format: str, security_cookie: bool, name: str
) -> tuple[str, ...]:
    if name == "cxx_eh_probe":
        if toolchain == "clang-cl":
            return ("__CxxFrameHandler3",)
        if cxx_format == "fh4":
            if security_cookie:
                return ("__CxxFrameHandler4", "__GSHandlerCheck_EH4")
            return ("__CxxFrameHandler4",)
        if security_cookie:
            return ("__CxxFrameHandler3", "__GSHandlerCheck_EH")
        return ("__CxxFrameHandler3",)
    if name == "seh_probe":
        if toolchain == "msvc" and security_cookie:
            return ("__C_specific_handler", "__GSHandlerCheck_SEH")
        return ("__C_specific_handler",)
    return ()


def _validate_build(
    build: dict[str, Any], architecture: str, context: str, *, uses_cxx: bool
) -> tuple[str, str, bool, str, str]:
    toolchain = _require_string(build, "toolchain", context)
    cxx_format = _require_string(build, "cxx_format", context)
    optimization = _require_string(build, "optimization", context)
    security_cookie = _require_bool(build, "security_cookie", context)
    execution = _require_string(build, "execution", context)
    try:
        cell = validate_cell(
            toolchain,
            architecture,
            cxx_format,
            optimization,
            "on" if security_cookie else "off",
        )
    except ValueError as error:
        raise VerificationError(str(error)) from error

    target_triple = _require_string(build, "target_triple", context)
    if target_triple != cell.target_triple:
        raise VerificationError(f"{context}.target_triple disagrees with architecture")
    expected_execution = "passed" if cell.execute else "not-run-cross-target"
    if execution != expected_execution:
        raise VerificationError(
            f"{context}.execution must be {expected_execution!r} for {architecture}"
        )

    compiler_name = "cl.exe" if toolchain == "msvc" else "clang-cl.exe"
    linker_name = "link.exe" if toolchain == "msvc" else "lld-link.exe"
    _validate_tool_identity(
        build.get("compiler"), f"{context}.compiler", expected_name=compiler_name
    )
    _validate_tool_identity(
        build.get("linker"), f"{context}.linker", expected_name=linker_name
    )
    compiler_flags = _require_string_array(
        build, "compiler_flags", context, allow_empty=False
    )
    linker_flags = _require_string_array(
        build, "linker_flags", context, allow_empty=False
    )

    required_optimization = "/Od" if optimization == "o0" else "/O2"
    required_cookie = "/GS" if security_cookie else "/GS-"
    if (
        required_optimization not in compiler_flags
        or required_cookie not in compiler_flags
    ):
        raise VerificationError(f"{context}.compiler_flags omit declared build axes")
    machine_flag = f"/MACHINE:{_LINKER_MACHINES[architecture]}"
    if machine_flag not in linker_flags:
        raise VerificationError(f"{context}.linker_flags omit {machine_flag}")

    fh_flags = [flag for flag in compiler_flags if flag.lower().startswith("/d2fh4")]
    if toolchain == "msvc" and architecture == "x86_64" and uses_cxx:
        expected_fh_flag = "/d2FH4" if cxx_format == "fh4" else "/d2FH4-"
        if fh_flags != [expected_fh_flag]:
            raise VerificationError(
                f"{context}.compiler_flags must contain exactly {expected_fh_flag}"
            )
    elif fh_flags:
        raise VerificationError(
            f"{context}.compiler_flags contain unsupported FH4 control"
        )
    if toolchain == "clang-cl":
        target_flag = f"--target={_TARGET_TRIPLES[architecture]}"
        if target_flag not in compiler_flags:
            raise VerificationError(f"{context}.compiler_flags omit {target_flag}")

    return toolchain, cxx_format, security_cookie, optimization, cell.cookie_label


def _validate_neverd(
    value: Any,
    *,
    architecture: str,
    name: str,
    expected_personalities: tuple[str, ...],
    context: str,
) -> None:
    neverd = _require_object(value, context)
    level = _require_string(neverd, "validation_level", context)
    expected_level = {
        "x86": "load-only",
        "x86_64": "exception-graph",
        "arm": "unwind-only",
        "aarch64": "unwind-only",
    }[architecture]
    if level != expected_level:
        raise VerificationError(
            f"{context}.validation_level must be {expected_level!r} for {architecture}"
        )
    statuses = _require_string_array(
        neverd, "allowed_parse_status", context, allow_empty=False
    )
    if any(status not in ("complete", "partial") for status in statuses):
        raise VerificationError(f"{context}.allowed_parse_status is invalid")
    if level == "exception-graph" and statuses != ["complete"]:
        raise VerificationError(
            f"{context} exception graphs must require complete status"
        )
    personalities = _require_string_array(
        neverd, "personalities_any", context, allow_empty=True
    )
    min_functions = _require_nonnegative_int(neverd, "min_exception_functions", context)
    min_cxx = _require_nonnegative_int(neverd, "min_cxx_functions", context)
    min_try = _require_nonnegative_int(neverd, "min_try_blocks", context)
    min_seh = _require_nonnegative_int(neverd, "min_seh_scopes", context)

    if level == "load-only":
        if personalities or any((min_functions, min_cxx, min_try, min_seh)):
            raise VerificationError(
                f"{context} load-only contract claims exception parsing"
            )
    elif level == "unwind-only":
        if personalities or min_functions < 1 or any((min_cxx, min_try, min_seh)):
            raise VerificationError(f"{context} unwind-only contract is inconsistent")
    elif expected_personalities:
        if personalities != list(expected_personalities):
            raise VerificationError(
                f"{context} probe personality contract is inconsistent"
            )
        if min_functions < 1:
            raise VerificationError(f"{context} graph contract requires a function")
        if name == "cxx_eh_probe" and (min_cxx < 1 or min_try < 1):
            raise VerificationError(f"{context} C++ probe graph contract is too weak")
        if name == "seh_probe" and min_seh < 1:
            raise VerificationError(f"{context} SEH probe graph contract is too weak")


def _validate_evidence(
    value: Any,
    *,
    image: _PEImage,
    architecture: str,
    security_cookie: bool,
    name: str,
    expected_personalities: tuple[str, ...],
    context: str,
) -> None:
    evidence = _require_object(value, context)
    required_sections = _require_string_array(
        evidence, "required_sections", context, allow_empty=False
    )
    missing_sections = sorted(set(required_sections) - set(image.sections))
    if missing_sections:
        raise VerificationError(
            f"{context} required section(s) missing: {', '.join(missing_sections)}"
        )
    groups = _require_array(
        evidence.get("required_imports_any"), f"{context}.required_imports_any"
    )
    normalized_groups: list[list[str]] = []
    for index, raw_group in enumerate(groups):
        group = _require_array(raw_group, f"{context}.required_imports_any[{index}]")
        if not group or any(not isinstance(name, str) or not name for name in group):
            raise VerificationError(
                f"{context}.required_imports_any[{index}] must contain names"
            )
        normalized_groups.append(list(group))
    for group in normalized_groups:
        if not any(name in image.imports for name in group):
            raise VerificationError(
                f"{context} required import alternative is absent: {group}"
            )
    if expected_personalities and not any(
        all(personality in group for personality in expected_personalities)
        for group in normalized_groups
    ):
        raise VerificationError(f"{context} omits required personality evidence")

    require_directory = _require_bool(evidence, "require_exception_directory", context)
    require_unwind = _require_bool(evidence, "require_unwind_records", context)
    table_based = architecture != "x86"
    if require_directory != table_based or require_unwind != table_based:
        raise VerificationError(f"{context} table-unwind requirements are inconsistent")
    if require_directory and not image.has_file_backed_directory(3):
        raise VerificationError(f"{context} exception directory is not file-backed")
    if require_unwind:
        image.verify_unwind_records()

    require_security_cookie = _require_bool(
        evidence, "require_security_cookie", context
    )
    expected_security_cookie = security_cookie and name.endswith("_probe")
    if require_security_cookie != expected_security_cookie:
        raise VerificationError(
            f"{context} security cookie requirement is inconsistent"
        )
    if require_security_cookie:
        image.verify_security_cookie()


def _validate_artifact(
    artifact: dict[str, Any], index: int, root: Path
) -> tuple[str, int]:
    context = f"artifacts[{index}]"
    relative_text = _require_string(artifact, "path", context)
    relative = PurePosixPath(relative_text)
    if (
        relative.is_absolute()
        or relative.as_posix() != relative_text
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise VerificationError(f"{context}.path is not a normalized relative path")

    architecture = _require_string(artifact, "architecture", context)
    if architecture not in _TARGET_TRIPLES:
        raise VerificationError(f"{context}.architecture is unsupported")
    name = _require_string(artifact, "name", context)
    if name not in _ARTIFACT_LAYOUT:
        raise VerificationError(f"{context}.name is unsupported")
    suite = _require_string(artifact, "suite", context)
    kind = _require_string(artifact, "kind", context)
    expected_suite, extension, expected_kind = _ARTIFACT_LAYOUT[name]
    if suite != expected_suite or kind != expected_kind:
        raise VerificationError(f"{context} artifact identity is inconsistent")

    build = _require_object(artifact.get("build"), f"{context}.build")
    toolchain, cxx_format, security_cookie, optimization, cookie_label = (
        _validate_build(
            build,
            architecture,
            f"{context}.build",
            uses_cxx=kind in ("cxx", "mixed"),
        )
    )
    expected_filename = (
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
    expected_path = PurePosixPath(
        "corpus",
        "windows-eh",
        toolchain,
        architecture,
        cxx_format,
        cookie_label,
        optimization,
        suite,
        expected_filename,
    )
    if relative != expected_path:
        raise VerificationError(
            f"{context} artifact layout disagrees with build axes: {relative_text}"
        )

    expected_personalities: tuple[str, ...] = ()
    if architecture == "x86_64":
        expected_personalities = _expected_personalities(
            toolchain=toolchain,
            cxx_format=cxx_format,
            security_cookie=security_cookie,
            name=name,
        )
    _validate_neverd(
        artifact.get("neverd"),
        architecture=architecture,
        name=name,
        expected_personalities=expected_personalities,
        context=f"{context}.neverd",
    )

    expected_hash = _require_string(artifact, "sha256", context)
    if not _SHA256_RE.fullmatch(expected_hash):
        raise VerificationError(f"{context}.sha256 is not lowercase SHA-256")
    expected_size = _require_nonnegative_int(artifact, "size", context)
    if expected_size == 0:
        raise VerificationError(f"{context}.size must be positive")

    root_resolved = root.resolve()
    artifact_path = (root / Path(*relative.parts)).resolve()
    try:
        artifact_path.relative_to(root_resolved)
    except ValueError as error:
        raise VerificationError(f"{context}.path escapes the corpus root") from error
    try:
        payload = artifact_path.read_bytes()
    except OSError as error:
        raise VerificationError(
            f"cannot read artifact {relative_text}: {error}"
        ) from error
    if len(payload) != expected_size:
        raise VerificationError(f"{context} size mismatch")
    if hashlib.sha256(payload).hexdigest() != expected_hash:
        raise VerificationError(f"{context} SHA-256 mismatch")

    image = _PEImage(payload)
    if image.architecture != architecture:
        raise VerificationError(
            f"{context} architecture mismatch: PE is {image.architecture}, "
            f"manifest says {architecture}"
        )
    _validate_evidence(
        artifact.get("evidence"),
        image=image,
        architecture=architecture,
        security_cookie=security_cookie,
        name=name,
        expected_personalities=expected_personalities,
        context=f"{context}.evidence",
    )
    return relative_text, len(payload)


def verify_manifest(path: Path, root: Path) -> VerificationResult:
    manifest = _load_manifest(path)
    _validate_manifest_identity(manifest)
    _validate_source_and_producer(manifest)
    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    if not artifacts:
        raise VerificationError("manifest contains no artifacts")

    seen_paths: set[str] = set()
    total_bytes = 0
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        relative_path, size = _validate_artifact(artifact, index, root)
        if relative_path in seen_paths:
            raise VerificationError(f"duplicate artifact path: {relative_path}")
        seen_paths.add(relative_path)
        total_bytes += size
    return VerificationResult(len(artifacts), total_bytes)


def verify_complete_matrix(path: Path) -> None:
    manifest = _load_manifest(path)
    _validate_manifest_identity(manifest)
    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    names_by_cell: dict[str, set[str]] = {}
    paths: set[str] = set()
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        name = _require_string(artifact, "name", f"artifacts[{index}]")
        architecture = _require_string(artifact, "architecture", f"artifacts[{index}]")
        build = _require_object(artifact.get("build"), f"artifacts[{index}].build")
        try:
            key = artifact_cell_key(build, architecture)
        except ValueError as error:
            raise VerificationError(str(error)) from error
        path_text = _require_string(artifact, "path", f"artifacts[{index}]")
        if path_text in paths:
            raise VerificationError(f"duplicate artifact path: {path_text}")
        paths.add(path_text)
        cell_names = names_by_cell.setdefault(key, set())
        if name in cell_names:
            raise VerificationError(f"duplicate artifact name {name!r} in cell {key}")
        cell_names.add(name)

    expected_names_by_cell = {
        cell.key: set(cell.artifact_names) for cell in expected_cells()
    }
    expected_keys = set(expected_names_by_cell)
    if set(names_by_cell) != expected_keys:
        missing = sorted(expected_keys - set(names_by_cell))
        extra = sorted(set(names_by_cell) - expected_keys)
        raise VerificationError(
            f"incomplete Windows EH matrix; missing={missing}, extra={extra}"
        )
    for key, names in names_by_cell.items():
        expected_names = expected_names_by_cell[key]
        if names != expected_names:
            raise VerificationError(
                f"matrix cell {key} artifact set differs: "
                f"missing={sorted(expected_names - names)}, "
                f"extra={sorted(names - expected_names)}"
            )
    expected_count = sum(len(names) for names in expected_names_by_cell.values())
    if len(artifacts) != expected_count:
        raise VerificationError(
            f"matrix contains {len(artifacts)} artifacts, expected {expected_count}"
        )


def merge_manifests(
    fragment_paths: list[Path], output_path: Path, root: Path
) -> VerificationResult:
    if not fragment_paths:
        raise VerificationError("no manifest fragments were found")
    envelopes: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for fragment_path in sorted(fragment_paths, key=lambda item: item.as_posix()):
        verify_manifest(fragment_path, root)
        fragment = _load_manifest(fragment_path)
        envelope = {
            "schema_version": fragment["schema_version"],
            "corpus": fragment["corpus"],
            "source": fragment["source"],
            "producer": fragment["producer"],
        }
        envelopes.append(envelope)
        artifacts.extend(_require_array(fragment.get("artifacts"), "artifacts"))
    first = envelopes[0]
    for envelope in envelopes[1:]:
        if envelope != first:
            raise VerificationError("manifest fragments have inconsistent envelopes")

    artifacts.sort(key=lambda artifact: str(artifact.get("path", "")))
    merged = dict(first)
    merged["artifacts"] = artifacts
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(merged, stream, indent=2, sort_keys=True)
            stream.write("\n")
        Path(temporary_name).replace(output_path)
    except BaseException:
        try:
            Path(temporary_name).unlink()
        except FileNotFoundError:
            pass
        raise
    return verify_manifest(output_path, root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--require-complete-matrix", action="store_true")
    args = parser.parse_args()
    result = verify_manifest(args.manifest, args.root)
    if args.require_complete_matrix:
        verify_complete_matrix(args.manifest)
    print(f"verified {result.artifact_count} artifact(s), {result.total_bytes} byte(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
