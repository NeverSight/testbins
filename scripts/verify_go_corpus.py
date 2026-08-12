#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Validate the Go runtime-metadata corpus and its manifest.

Everything the manifest claims about a Go image is re-derived here from the
bytes: the container's section table is parsed, the `runtime.pcHeader` is
located and its eight-byte prefix decoded, the symbol table is read to see
whether any Go name survived the link, and the whole image is swept for a
second table that would make the decoder's own scan ambiguous.

Only the standard library is used.  A corpus verifier that needs a package
index to run is a verifier that cannot be trusted to run on the machine that
found the problem.  If `jsonschema` happens to be importable the manifest is
additionally checked against `schema/go-eh-manifest.schema.json`, but the
structural checks below never depend on it.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from go_matrix import (
    ARTIFACT_NAME,
    MODULE_PACKAGE,
    MatrixError,
    Variant,
    expected_variants,
    pinned_go_versions,
    variant_for_path,
)


class VerificationError(ValueError):
    """Raised when the corpus contract or a Go artifact is invalid."""


_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REVISION_RE = re.compile(r"[0-9a-f]{40}")
_GO_VERSION_STRING_RE = re.compile(
    r"go version go[0-9]+\.[0-9]+(\.[0-9]+)? [a-z0-9]+/[a-z0-9]+"
)

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema/go-eh-manifest.schema.json"

#: `internal/abi.PCLnTabMagic`.  Each value is chosen so that reading it with
#: the wrong endianness does not produce another valid magic, which is what
#: makes a four-byte match worth following up on at all.
PCLNTAB_MAGICS = {
    0xFFFFFFFB: "go1.2",
    0xFFFFFFFA: "go1.16",
    0xFFFFFFF0: "go1.18",
    0xFFFFFFF1: "go1.20",
}

#: `internal/abi.MaxFunctionCount` has no name in Go, but the linker will not
#: produce anything near this and the decoder refuses to walk past it.
_MAX_FUNCTION_COUNT = 1 << 22

_GOFUNC_SYMBOLS = ("go:func.*", "go.func.*")

_NATIVE_UNWIND_SECTIONS = {
    "elf": (".eh_frame", ".eh_frame_hdr"),
    "macho": ("__eh_frame", "__unwind_info"),
    "pe": (".pdata", ".xdata"),
}

_ELF_PCLNTAB_SECTIONS = {
    "exe": ".gopclntab",
    "pie": ".data.rel.ro.gopclntab",
    "c-shared": ".data.rel.ro.gopclntab",
}


@dataclass(frozen=True)
class VerificationResult:
    artifact_count: int
    total_bytes: int


@dataclass(frozen=True)
class ObjectSection:
    name: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    #: False for sections such as `.bss` whose contents are not in the file.
    file_backed: bool


@dataclass(frozen=True)
class PclnTabHeader:
    """The eight bytes every `pclntab` layout starts with, plus `nfunc`."""

    file_offset: int
    magic: int
    min_lc: int
    pointer_size: int
    function_count: int

    @property
    def version(self) -> str:
        return PCLNTAB_MAGICS[self.magic]


@dataclass
class ObjectImage:
    """The parts of a container this verifier needs, and nothing else."""

    object_format: str
    payload: bytes
    sections: dict[str, ObjectSection] = field(default_factory=dict)
    symbol_names: set[str] = field(default_factory=set)
    has_symbol_table: bool = False

    def section(self, name: str) -> ObjectSection:
        section = self.sections.get(name)
        if section is None:
            raise VerificationError(f"section {name} is absent")
        return section

    def native_unwind_sections(self) -> list[str]:
        candidates = _NATIVE_UNWIND_SECTIONS[self.object_format]
        return sorted(name for name in candidates if name in self.sections)

    def gofunc_symbol(self) -> str | None:
        for candidate in _GOFUNC_SYMBOLS:
            if candidate in self.symbol_names or f"_{candidate}" in self.symbol_names:
                return candidate
        return None

    def symbol_table_kind(self) -> str:
        """Classify the symbol table by what it can still tell a reader.

        The distinction that matters is not whether a table exists but whether
        anything in it names a Go function: a stripped Mach-O image keeps the
        handful of entries the dynamic loader requires, and a stripped
        position-independent ELF keeps `.dynsym`, yet neither can point the
        decoder at `go:func.*` or at a single function body.
        """

        if self.gofunc_symbol() is not None:
            return "go-names"
        for name in self.symbol_names:
            stem = name[1:] if name.startswith("_") else name
            if stem.startswith("runtime.") or stem.startswith("main."):
                return "go-names"
        return "loader-only" if self.has_symbol_table else "absent"


def _unpack(payload: bytes, fmt: str, offset: int) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(payload):
        raise VerificationError("truncated object structure")
    return struct.unpack_from(fmt, payload, offset)


def _read_c_string(payload: bytes, offset: int, limit: int = 4096) -> str:
    if offset < 0 or offset >= len(payload):
        raise VerificationError("object string is out of bounds")
    end = payload.find(b"\0", offset, min(len(payload), offset + limit))
    if end == -1:
        raise VerificationError("unterminated object string")
    return payload[offset:end].decode("utf-8", errors="replace")


#===========================================================================
# ELF
#===========================================================================

_SHT_SYMTAB = 2
_SHT_DYNSYM = 11
_SHT_NOBITS = 8


def _parse_elf(payload: bytes) -> ObjectImage:
    if len(payload) < 64 or payload[:4] != b"\x7fELF":
        raise VerificationError("artifact is not an ELF image")
    if payload[4] != 2:
        raise VerificationError("only 64-bit ELF images are part of this corpus")
    if payload[5] != 1:
        raise VerificationError("only little-endian ELF images are part of this corpus")

    (section_offset,) = _unpack(payload, "<Q", 0x28)
    entry_size, section_count, string_index = _unpack(payload, "<HHH", 0x3A)
    if entry_size < 64 or not 1 <= section_count <= 4096:
        raise VerificationError("invalid ELF section table geometry")
    if string_index >= section_count:
        raise VerificationError("ELF section name table index is out of range")

    raw: list[tuple[int, int, int, int, int, int, int]] = []
    for index in range(section_count):
        base = section_offset + index * entry_size
        name, kind, _flags, address, offset, size, link = _unpack(
            payload, "<IIQQQQI", base
        )
        raw.append((name, kind, address, offset, size, link, index))

    _, _, _, string_offset, string_size, _, _ = raw[string_index]
    names = payload[string_offset : string_offset + string_size]

    image = ObjectImage("elf", payload)
    for name, kind, address, offset, size, _link, _index in raw:
        end = names.find(b"\0", name)
        if end == -1:
            raise VerificationError("unterminated ELF section name")
        text = names[name:end].decode("ascii", errors="replace")
        if not text:
            continue
        file_backed = kind != _SHT_NOBITS
        if file_backed and (offset > len(payload) or size > len(payload) - offset):
            raise VerificationError(f"ELF section {text} is out of bounds")
        image.sections[text] = ObjectSection(
            text,
            int(address),
            int(size),
            int(offset),
            int(size) if file_backed else 0,
            file_backed,
        )

    for _name, kind, _address, offset, size, link, _index in raw:
        if kind not in (_SHT_SYMTAB, _SHT_DYNSYM):
            continue
        if link >= len(raw):
            raise VerificationError("ELF symbol table names an invalid string table")
        _, _, _, str_offset, str_size, _, _ = raw[link]
        strings = payload[str_offset : str_offset + str_size]
        if size % 24 != 0:
            raise VerificationError("misaligned ELF symbol table")
        count = size // 24
        if count > 1:
            image.has_symbol_table = True
        for index in range(count):
            (name_offset,) = _unpack(payload, "<I", offset + index * 24)
            end = strings.find(b"\0", name_offset)
            if end == -1:
                continue
            text = strings[name_offset:end].decode("utf-8", errors="replace")
            if text:
                image.symbol_names.add(text)
    return image


#===========================================================================
# PE
#===========================================================================


def _parse_pe(payload: bytes) -> ObjectImage:
    if len(payload) < 0x40 or payload[:2] != b"MZ":
        raise VerificationError("artifact is not a DOS/PE image")
    (pe_offset,) = _unpack(payload, "<I", 0x3C)
    if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise VerificationError("invalid PE signature")

    (
        machine,
        section_count,
        _timestamp,
        symbol_offset,
        symbol_count,
        optional_size,
        _characteristics,
    ) = _unpack(payload, "<HHIIIHH", pe_offset + 4)
    if machine not in (0x8664, 0xAA64):
        raise VerificationError(f"unsupported PE machine 0x{machine:04x}")
    if not 1 <= section_count <= 96:
        raise VerificationError("invalid PE section count")

    optional_offset = pe_offset + 24
    (magic,) = _unpack(payload, "<H", optional_offset)
    if magic != 0x20B:
        raise VerificationError("only PE32+ images are part of this corpus")

    image = ObjectImage("pe", payload)
    table = optional_offset + optional_size
    long_name_base = symbol_offset + symbol_count * 18 if symbol_count else 0
    for index in range(section_count):
        base = table + index * 40
        raw_name = payload[base : base + 8]
        text = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
        if text.startswith("/") and long_name_base:
            # A COFF section name longer than eight bytes is spelled as a
            # decimal offset into the string table, which is where the Go
            # linker puts its DWARF sections.
            try:
                text = _read_c_string(payload, long_name_base + int(text[1:]))
            except (ValueError, VerificationError):
                pass
        virtual_size, address, raw_size, raw_offset = _unpack(payload, "<IIII", base + 8)
        if raw_size and (
            raw_offset > len(payload) or raw_size > len(payload) - raw_offset
        ):
            raise VerificationError(f"PE section {text} is out of bounds")
        if not text or text in image.sections:
            raise VerificationError("empty or duplicate PE section name")
        image.sections[text] = ObjectSection(
            text,
            int(address),
            int(virtual_size),
            int(raw_offset),
            int(raw_size),
            bool(raw_size),
        )

    if symbol_offset and symbol_count:
        image.has_symbol_table = True
        (string_size,) = _unpack(payload, "<I", long_name_base)
        strings = payload[long_name_base : long_name_base + max(string_size, 4)]
        index = 0
        while index < symbol_count:
            base = symbol_offset + index * 18
            record = payload[base : base + 18]
            if len(record) < 18:
                raise VerificationError("truncated PE symbol record")
            if record[:4] == b"\0\0\0\0":
                (offset,) = struct.unpack_from("<I", record, 4)
                end = strings.find(b"\0", offset)
                text = (
                    strings[offset:end].decode("utf-8", errors="replace")
                    if end != -1
                    else ""
                )
            else:
                text = record[:8].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            if text:
                image.symbol_names.add(text)
            index += 1 + record[17]
    return image


#===========================================================================
# Mach-O
#===========================================================================

_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x02


def _parse_macho(payload: bytes) -> ObjectImage:
    if len(payload) < 32:
        raise VerificationError("artifact is too small to be a Mach-O image")
    (magic,) = _unpack(payload, "<I", 0)
    if magic != 0xFEEDFACF:
        raise VerificationError("only 64-bit little-endian Mach-O is part of this corpus")
    (command_count,) = _unpack(payload, "<I", 16)
    if command_count > 4096:
        raise VerificationError("invalid Mach-O load command count")

    image = ObjectImage("macho", payload)
    offset = 32
    for _ in range(command_count):
        command, command_size = _unpack(payload, "<II", offset)
        if command_size < 8 or offset + command_size > len(payload):
            raise VerificationError("truncated Mach-O load command")
        if command == _LC_SEGMENT_64:
            (section_count,) = _unpack(payload, "<I", offset + 64)
            cursor = offset + 72
            for _index in range(section_count):
                name = payload[cursor : cursor + 16].split(b"\0", 1)[0]
                text = name.decode("ascii", errors="replace")
                address, size = _unpack(payload, "<QQ", cursor + 32)
                (file_offset,) = _unpack(payload, "<I", cursor + 48)
                if not text:
                    raise VerificationError("empty Mach-O section name")
                # A zero file offset on a Mach-O section means the section is
                # zero filled, exactly as `.bss` is on ELF.
                file_backed = file_offset != 0
                if file_backed and (
                    file_offset > len(payload) or size > len(payload) - file_offset
                ):
                    raise VerificationError(f"Mach-O section {text} is out of bounds")
                image.sections.setdefault(
                    text,
                    ObjectSection(
                        text,
                        int(address),
                        int(size),
                        int(file_offset),
                        int(size) if file_backed else 0,
                        file_backed,
                    ),
                )
                cursor += 80
        elif command == _LC_SYMTAB:
            symbol_offset, symbol_count, string_offset, string_size = _unpack(
                payload, "<IIII", offset + 8
            )
            if symbol_count:
                image.has_symbol_table = True
            strings = payload[string_offset : string_offset + string_size]
            for index in range(min(symbol_count, 1 << 20)):
                (name_offset,) = _unpack(payload, "<I", symbol_offset + index * 16)
                end = strings.find(b"\0", name_offset)
                if end == -1:
                    continue
                text = strings[name_offset:end].decode("utf-8", errors="replace")
                if text:
                    image.symbol_names.add(text)
        offset += command_size
    return image


_PARSERS = {"elf": _parse_elf, "pe": _parse_pe, "macho": _parse_macho}


def detect_object_format(payload: bytes) -> str:
    if payload[:4] == b"\x7fELF":
        return "elf"
    if payload[:2] == b"MZ":
        return "pe"
    if payload[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    raise VerificationError("artifact is not an ELF, PE, or Mach-O image")


def parse_object(payload: bytes, expected_format: str) -> ObjectImage:
    detected = detect_object_format(payload)
    if detected != expected_format:
        raise VerificationError(
            f"object format mismatch: image is {detected}, manifest says "
            f"{expected_format}"
        )
    return _PARSERS[expected_format](payload)


#===========================================================================
# pclntab
#===========================================================================


def read_pclntab_header(payload: bytes, offset: int) -> PclnTabHeader | None:
    """Decode a `runtime.pcHeader` at \\p offset, or return None.

    The checks are the ones `runtime.moduledataverify1` makes, which is what
    separates a real header from four bytes that happen to match the magic:
    the two bytes after the magic are reserved and zero, `minLC` is one of the
    three pc quanta any Go port uses, and `ptrSize` is a pointer width.
    `nfunc` follows immediately in every layout the magic can name, including
    the Go 1.2 one that has no offset block after it.
    """

    if offset < 0 or offset + 8 > len(payload):
        return None
    (magic,) = struct.unpack_from("<I", payload, offset)
    if magic not in PCLNTAB_MAGICS:
        return None
    pad_one, pad_two, min_lc, pointer_size = payload[offset + 4 : offset + 8]
    if pad_one != 0 or pad_two != 0:
        return None
    if min_lc not in (1, 2, 4) or pointer_size not in (4, 8):
        return None
    count_format = "<Q" if pointer_size == 8 else "<I"
    count_size = struct.calcsize(count_format)
    if offset + 8 + count_size > len(payload):
        return None
    (function_count,) = struct.unpack_from(count_format, payload, offset + 8)
    if not 1 <= function_count <= _MAX_FUNCTION_COUNT:
        return None
    return PclnTabHeader(offset, magic, min_lc, pointer_size, function_count)


def scan_pclntab_headers(payload: bytes, limit: int = 8) -> list[PclnTabHeader]:
    """Sweep the whole image the way the decoder sweeps a PE.

    The decoder has no section to consult on PE, so it walks mapped data
    looking for the magic.  Finding more than one plausible header would make
    that walk pick arbitrarily, so the sweep is reproduced here and the count
    is part of the contract.
    """

    found: list[PclnTabHeader] = []
    for magic in PCLNTAB_MAGICS:
        needle = struct.pack("<I", magic)
        cursor = payload.find(needle)
        while cursor != -1:
            if cursor % 4 == 0:
                header = read_pclntab_header(payload, cursor)
                if header is not None:
                    found.append(header)
                    if len(found) > limit:
                        return sorted(found, key=lambda item: item.file_offset)
            cursor = payload.find(needle, cursor + 1)
    return sorted(found, key=lambda item: item.file_offset)


def locate_pclntab(
    image: ObjectImage, section_name: str, at_section_start: bool
) -> PclnTabHeader:
    """Find the header where the manifest says it is, and prove it is alone."""

    section = image.section(section_name)
    if not section.file_backed or section.file_size < 16:
        raise VerificationError(
            f"section {section_name} carries no file-backed contents to hold a "
            "pclntab"
        )
    if at_section_start:
        header = read_pclntab_header(image.payload, section.file_offset)
        if header is None:
            raise VerificationError(
                f"section {section_name} does not start with a Go pclntab header"
            )
    else:
        window = image.payload[
            section.file_offset : section.file_offset + section.file_size
        ]
        candidates = [
            header
            for header in scan_pclntab_headers(window)
            if header.file_offset % 4 == 0
        ]
        if len(candidates) != 1:
            raise VerificationError(
                f"section {section_name} holds {len(candidates)} plausible Go "
                "pclntab headers, expected exactly one"
            )
        found = candidates[0]
        header = PclnTabHeader(
            section.file_offset + found.file_offset,
            found.magic,
            found.min_lc,
            found.pointer_size,
            found.function_count,
        )

    whole_image = scan_pclntab_headers(image.payload)
    if len(whole_image) != 1:
        offsets = ", ".join(f"0x{item.file_offset:x}" for item in whole_image)
        raise VerificationError(
            f"image holds {len(whole_image)} plausible Go pclntab headers "
            f"({offsets}); a structural scan could not choose between them"
        )
    if whole_image[0].file_offset != header.file_offset:
        raise VerificationError(
            "the pclntab a structural scan finds is not the one "
            f"{section_name} holds"
        )
    return header


#===========================================================================
# Manifest structure
#===========================================================================


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
    if manifest.get("schema_version") != 1:
        raise VerificationError("unsupported manifest schema_version")
    if manifest.get("corpus") != "go-eh":
        raise VerificationError("unsupported corpus identity")


def _validate_producer(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    producer = _require_object(manifest.get("producer"), "producer")
    revision = _require_string(producer, "repository_revision", "producer")
    if not _REVISION_RE.fullmatch(revision):
        raise VerificationError("producer.repository_revision must be a full SHA")
    _require_string(producer, "runner_image", "producer")
    if producer.get("runner_os") != "linux" or producer.get("runner_arch") != "x64":
        raise VerificationError(
            "the Go corpus is cross-compiled from one linux/x64 host; "
            "producer.runner_os and producer.runner_arch must say so"
        )
    if producer.get("module_path") != "neversight.dev/goeh":
        raise VerificationError("producer.module_path is not the corpus module")
    if producer.get("package") != MODULE_PACKAGE:
        raise VerificationError("producer.package is not the corpus command")
    _require_string(producer, "module_go_directive", "producer")

    toolchains = _require_array(producer.get("toolchains"), "producer.toolchains")
    if not toolchains:
        raise VerificationError("producer.toolchains must not be empty")
    by_version: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(toolchains):
        context = f"producer.toolchains[{index}]"
        entry = _require_object(raw, context)
        version = _require_string(entry, "go_version", context)
        version_string = _require_string(entry, "go_version_string", context)
        if not _GO_VERSION_STRING_RE.fullmatch(version_string):
            raise VerificationError(f"{context}.go_version_string is malformed")
        if f"go{version} " not in f"{version_string} ":
            raise VerificationError(
                f"{context}.go_version_string does not report go{version}"
            )
        environment = _require_object(entry.get("go_env"), f"{context}.go_env")
        for key in (
            "GOAMD64",
            "GOARM64",
            "GOEXPERIMENT",
            "GOFLAGS",
            "GOHOSTARCH",
            "GOHOSTOS",
            "GOTOOLCHAIN",
            "GOVERSION",
        ):
            if not isinstance(environment.get(key), str):
                raise VerificationError(f"{context}.go_env.{key} must be a string")
        if environment["GOFLAGS"] != "":
            raise VerificationError(
                f"{context}.go_env.GOFLAGS must be empty so the runner cannot "
                "inject a flag the manifest does not record"
            )
        if environment["GOHOSTOS"] != "linux" or environment["GOHOSTARCH"] != "amd64":
            raise VerificationError(f"{context}.go_env does not describe a linux/x64 host")
        if version in by_version:
            raise VerificationError(f"duplicate producer toolchain {version}")
        by_version[version] = entry
    return by_version


def _validate_build(
    build: dict[str, Any], variant: Variant, context: str
) -> None:
    if build.get("package") != MODULE_PACKAGE:
        raise VerificationError(f"{context}.package is not the corpus command")
    flags = _require_string_array(build, "flags", context, allow_empty=False)
    expected_flags = variant.build_flags()
    if flags != expected_flags:
        raise VerificationError(
            f"{context}.flags are {flags}, but the axes recorded beside them "
            f"require {expected_flags}"
        )
    if "-trimpath" not in flags:
        raise VerificationError(
            f"{context}.flags omit -trimpath, so the build path would be "
            "published inside the artifact"
        )
    environment = _require_object(build.get("env"), f"{context}.env")
    expected_env = variant.build_env()
    if environment != expected_env:
        raise VerificationError(
            f"{context}.env disagrees with the recorded build axes"
        )
    execution = _require_string(build, "execution", context)
    if execution != variant.execution:
        raise VerificationError(
            f"{context}.execution must be {variant.execution!r} for this variant"
        )


def _expected_required_sections(variant: Variant) -> list[str]:
    """The sections the container must have for the manifest to be believable."""

    object_format = variant.target.object_format
    if object_format == "elf":
        return sorted((_ELF_PCLNTAB_SECTIONS[variant.buildmode], ".noptrdata", ".text"))
    if object_format == "macho":
        return sorted(("__gopclntab", "__noptrdata", "__text"))
    return sorted((".rdata", ".data", ".text"))


def _expected_pclntab_section(variant: Variant) -> tuple[str, bool]:
    object_format = variant.target.object_format
    if object_format == "elf":
        return _ELF_PCLNTAB_SECTIONS[variant.buildmode], True
    if object_format == "macho":
        return "__gopclntab", True
    # The PE linker gives the table no section of its own, so the decoder has
    # to find it by scanning the read-only data it was folded into.
    return ".rdata", False


def _validate_evidence(
    value: Any, *, image: ObjectImage, variant: Variant, context: str
) -> int:
    evidence = _require_object(value, context)

    required_sections = _require_string_array(
        evidence, "required_sections", context, allow_empty=False
    )
    expected_sections = _expected_required_sections(variant)
    if sorted(required_sections) != expected_sections:
        raise VerificationError(
            f"{context}.required_sections are {sorted(required_sections)}, but a "
            f"{variant.target.object_format} {variant.buildmode} image must "
            f"declare {expected_sections}"
        )
    missing = sorted(set(required_sections) - set(image.sections))
    if missing:
        raise VerificationError(
            f"{context} required section(s) missing from the image: "
            f"{', '.join(missing)}"
        )

    section_name = _require_string(evidence, "pclntab_section", context)
    at_start = _require_bool(evidence, "pclntab_at_section_start", context)
    expected_section, expected_at_start = _expected_pclntab_section(variant)
    if section_name != expected_section or at_start != expected_at_start:
        raise VerificationError(
            f"{context} claims the pclntab is at {section_name} "
            f"(at_start={at_start}); this variant must carry it at "
            f"{expected_section} (at_start={expected_at_start})"
        )

    header = locate_pclntab(image, section_name, at_start)
    magic = _require_nonnegative_int(evidence, "pclntab_magic", context)
    if magic != header.magic:
        raise VerificationError(
            f"{context}.pclntab_magic is 0x{magic:08x}, image has "
            f"0x{header.magic:08x}"
        )
    if magic != variant.release.pclntab_magic:
        raise VerificationError(
            f"{context}.pclntab_magic disagrees with what Go "
            f"{variant.go_version} writes"
        )
    min_lc = _require_nonnegative_int(evidence, "pclntab_min_lc", context)
    if min_lc != header.min_lc or min_lc != variant.target.min_lc:
        raise VerificationError(
            f"{context}.pclntab_min_lc is {min_lc}; the image says "
            f"{header.min_lc} and {variant.goarch} uses "
            f"{variant.target.min_lc}"
        )
    pointer_size = _require_nonnegative_int(evidence, "pclntab_ptr_size", context)
    if pointer_size != header.pointer_size or pointer_size != variant.target.pointer_size:
        raise VerificationError(
            f"{context}.pclntab_ptr_size is {pointer_size}; the image says "
            f"{header.pointer_size}"
        )
    function_count = _require_nonnegative_int(evidence, "pclntab_function_count", context)
    if function_count != header.function_count:
        raise VerificationError(
            f"{context}.pclntab_function_count is {function_count}, image has "
            f"{header.function_count}"
        )

    symbol_table = _require_string(evidence, "symbol_table", context)
    observed_symbol_table = image.symbol_table_kind()
    if symbol_table != observed_symbol_table:
        raise VerificationError(
            f"{context}.symbol_table is {symbol_table!r}, image is "
            f"{observed_symbol_table!r}"
        )
    # `-ldflags=-s -w` empties the symbol table on ELF and PE.  Mach-O is the
    # exception: the link still emits an `LC_SYMTAB` naming `_go.func.*`, so a
    # stripped darwin image legitimately keeps Go names, and demanding
    # otherwise would reject an artifact the toolchain cannot produce.
    if (
        variant.stripped
        and symbol_table == "go-names"
        and variant.target.object_format != "macho"
    ):
        raise VerificationError(
            f"{context} claims a stripped artifact that still names Go functions"
        )
    if not variant.stripped and symbol_table != "go-names":
        raise VerificationError(
            f"{context} claims an unstripped artifact whose symbol table names "
            "no Go function"
        )

    gofunc_symbol = evidence.get("gofunc_symbol")
    observed_gofunc = image.gofunc_symbol()
    if gofunc_symbol is not None and not isinstance(gofunc_symbol, str):
        raise VerificationError(f"{context}.gofunc_symbol must be a string or null")
    if gofunc_symbol != observed_gofunc:
        raise VerificationError(
            f"{context}.gofunc_symbol is {gofunc_symbol!r}, image has "
            f"{observed_gofunc!r}"
        )
    if observed_gofunc is not None and observed_gofunc != variant.release.gofunc_symbol:
        raise VerificationError(
            f"{context}.gofunc_symbol is {observed_gofunc!r}, but Go "
            f"{variant.go_version} spells it {variant.release.gofunc_symbol!r}"
        )

    unwind_sections = _require_string_array(
        evidence, "native_unwind_sections", context, allow_empty=True
    )
    observed_unwind = image.native_unwind_sections()
    if sorted(unwind_sections) != observed_unwind:
        raise VerificationError(
            f"{context}.native_unwind_sections are {sorted(unwind_sections)}, "
            f"image has {observed_unwind}"
        )
    if variant.target.object_format != "pe":
        # Go emits no platform unwind table for its own code.  Anything here
        # came from a C object, which only cgo links.
        if variant.cgo_enabled and not observed_unwind:
            raise VerificationError(
                f"{context} is a cgo artifact with no DWARF unwind section, so "
                "the C toolchain contributed nothing and the cell proves "
                "nothing it was added to prove"
            )
        if not variant.cgo_enabled and observed_unwind:
            raise VerificationError(
                f"{context} is a pure Go artifact that unexpectedly carries "
                f"{observed_unwind}"
            )
    return header.function_count


def _validate_neverd(
    value: Any, *, variant: Variant, function_count: int, context: str
) -> None:
    neverd = _require_object(value, context)
    release = variant.release

    level = _require_string(neverd, "validation_level", context)
    expected_level = "table-only" if release.pclntab_version == "go1.2" else "runtime-graph"
    if level != expected_level:
        raise VerificationError(
            f"{context}.validation_level must be {expected_level!r} for a "
            f"{release.pclntab_version} table"
        )

    statuses = _require_string_array(
        neverd, "allowed_parse_status", context, allow_empty=False
    )
    if any(status not in ("complete", "partial") for status in statuses):
        raise VerificationError(f"{context}.allowed_parse_status is invalid")
    if not release.has_unsafe_point_table:
        # The decoder records a diagnostic for every table that predates
        # PCDATA_UnsafePoint, which degrades the module status by
        # construction.  Claiming a complete parse here would be claiming
        # something the decoder cannot report.
        if statuses != ["partial"]:
            raise VerificationError(
                f"{context} a {release.pclntab_version} table always parses "
                "partially because it has no PCDATA_UnsafePoint to recover"
            )
    elif statuses != ["complete"]:
        raise VerificationError(
            f"{context} a {release.pclntab_version} table must parse completely"
        )

    version = _require_string(neverd, "expected_pclntab_version", context)
    if version != release.pclntab_version:
        raise VerificationError(
            f"{context}.expected_pclntab_version is {version!r}, Go "
            f"{variant.go_version} writes {release.pclntab_version!r}"
        )

    min_functions = _require_nonnegative_int(neverd, "min_go_functions", context)
    if min_functions < 1:
        raise VerificationError(f"{context}.min_go_functions must be positive")
    if min_functions > function_count:
        raise VerificationError(
            f"{context}.min_go_functions is {min_functions}, but the pclntab "
            f"only declares {function_count} functions"
        )

    min_defers = _require_nonnegative_int(neverd, "min_defer_sites", context)
    min_recovers = _require_nonnegative_int(neverd, "min_recover_sites", context)
    min_panics = _require_nonnegative_int(neverd, "min_panic_sites", context)
    min_open_coded = _require_nonnegative_int(
        neverd, "min_open_coded_defer_funcs", context
    )
    if min_defers < 1 or min_recovers < 1 or min_panics < 1:
        raise VerificationError(
            f"{context} every artifact in this corpus contains defer, recover, "
            "and panic sites, so none of their minimums may be zero"
        )
    if variant.optimization == "none":
        if min_open_coded != 0:
            raise VerificationError(
                f"{context} -N clears hasOpenDefers for every function, so no "
                "frame can carry open-coded defer info"
            )
    elif min_open_coded < 1:
        raise VerificationError(
            f"{context} an optimized build of the probe open-codes defers in "
            "at least one frame"
        )

    requires_moduledata = _require_bool(neverd, "requires_moduledata", context)
    # Before Go 1.18 a funcdata entry was a relocated pointer, so the decoder
    # needs no module structure to follow it.  From Go 1.18 the entries are
    # offsets from `moduledata.gofunc` and nothing resolves without it.
    expected_requires = release.pclntab_version in ("go1.18", "go1.20")
    if requires_moduledata != expected_requires:
        raise VerificationError(
            f"{context}.requires_moduledata must be {expected_requires} for a "
            f"{release.pclntab_version} table"
        )


def _validate_artifact(artifact: dict[str, Any], index: int, root: Path) -> tuple[str, int]:
    context = f"artifacts[{index}]"
    relative_text = _require_string(artifact, "path", context)
    relative = PurePosixPath(relative_text)
    if (
        relative.is_absolute()
        or relative.as_posix() != relative_text
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise VerificationError(f"{context}.path is not a normalized relative path")
    if relative.name.split("-", 1)[0] != ARTIFACT_NAME:
        raise VerificationError(f"{context}.path does not name the corpus probe")

    try:
        variant = variant_for_path(relative_text)
    except MatrixError as error:
        raise VerificationError(f"{context}: {error}") from error

    for key, expected in (
        ("goos", variant.goos),
        ("goarch", variant.goarch),
        ("go_version", variant.go_version),
        ("object_format", variant.target.object_format),
        ("buildmode", variant.buildmode),
        ("optimization", variant.optimization),
    ):
        actual = _require_string(artifact, key, context)
        if actual != expected:
            raise VerificationError(
                f"{context}.{key} is {actual!r}, but the artifact path says "
                f"{expected!r}"
            )
    if _require_bool(artifact, "cgo_enabled", context) != variant.cgo_enabled:
        raise VerificationError(f"{context}.cgo_enabled disagrees with the path")
    if _require_bool(artifact, "stripped", context) != variant.stripped:
        raise VerificationError(f"{context}.stripped disagrees with the path")

    _validate_build(
        _require_object(artifact.get("build"), f"{context}.build"),
        variant,
        f"{context}.build",
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
        raise VerificationError(f"cannot read artifact {relative_text}: {error}") from error
    if len(payload) != expected_size:
        raise VerificationError(f"{context} size mismatch")
    if hashlib.sha256(payload).hexdigest() != expected_hash:
        raise VerificationError(f"{context} SHA-256 mismatch")

    image = parse_object(payload, variant.target.object_format)
    function_count = _validate_evidence(
        artifact.get("evidence"),
        image=image,
        variant=variant,
        context=f"{context}.evidence",
    )
    _validate_neverd(
        artifact.get("neverd"),
        variant=variant,
        function_count=function_count,
        context=f"{context}.neverd",
    )
    return relative_text, len(payload)


@functools.lru_cache(maxsize=1)
def _schema_validator() -> Any:
    """Compile the published schema once, or report that it cannot be applied."""

    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return None
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    return validator_class(schema)


def validate_against_schema(manifest: dict[str, Any]) -> bool:
    """Check the manifest against the published schema when possible.

    Returns True when the schema was applied.  The structural checks above are
    the contract; this is a second, independent opinion that only runs where
    `jsonschema` is installed.
    """

    validator = _schema_validator()
    if validator is None:
        return False
    errors = sorted(validator.iter_errors(manifest), key=lambda error: error.path)
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise VerificationError(
            f"manifest fails the JSON Schema at {location}: {first.message} "
            f"({len(errors)} error(s) total)"
        )
    return True


def verify_manifest(path: Path, root: Path) -> VerificationResult:
    manifest = _load_manifest(path)
    _validate_manifest_identity(manifest)
    toolchains = _validate_producer(manifest)
    validate_against_schema(manifest)

    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    if not artifacts:
        raise VerificationError("manifest contains no artifacts")

    seen_paths: set[str] = set()
    used_versions: set[str] = set()
    total_bytes = 0
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        relative_path, size = _validate_artifact(artifact, index, root)
        if relative_path in seen_paths:
            raise VerificationError(f"duplicate artifact path: {relative_path}")
        seen_paths.add(relative_path)
        used_versions.add(str(artifact.get("go_version")))
        total_bytes += size
    missing_toolchains = sorted(used_versions - set(toolchains))
    if missing_toolchains:
        raise VerificationError(
            "producer.toolchains does not describe the toolchain(s) that built "
            f"{', '.join(missing_toolchains)}"
        )
    return VerificationResult(len(artifacts), total_bytes)


def verify_complete_matrix(path: Path) -> None:
    manifest = _load_manifest(path)
    _validate_manifest_identity(manifest)
    producer = _require_object(manifest.get("producer"), "producer")
    toolchains = _require_array(producer.get("toolchains"), "producer.toolchains")
    declared_versions = sorted(
        str(_require_object(entry, "producer.toolchains[]").get("go_version"))
        for entry in toolchains
    )
    if declared_versions != sorted(pinned_go_versions()):
        raise VerificationError(
            f"producer.toolchains lists {declared_versions}, the pinned set is "
            f"{sorted(pinned_go_versions())}"
        )

    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    paths: list[str] = []
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        paths.append(_require_string(artifact, "path", f"artifacts[{index}]"))
    if len(set(paths)) != len(paths):
        duplicates = sorted({item for item in paths if paths.count(item) > 1})
        raise VerificationError(f"duplicate artifact path(s): {duplicates}")

    expected = {variant.path for variant in expected_variants()}
    actual = set(paths)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise VerificationError(
            f"incomplete Go EH matrix; missing={missing}, extra={extra}"
        )


def _merge_producers(envelopes: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Union the toolchain records and require everything else to agree.

    Each cell only ever installs its own toolchain, so the fragments differ in
    exactly one field and must be identical in the rest.
    """

    merged: dict[str, Any] | None = None
    toolchains: dict[str, dict[str, Any]] = {}
    for envelope in envelopes:
        producer = _require_object(envelope.get("producer"), "producer")
        shared = {
            key: value for key, value in producer.items() if key != "toolchains"
        }
        if merged is None:
            merged = shared
        elif merged != shared:
            raise VerificationError(
                "manifest fragments disagree about the producer that made them"
            )
        for entry in _require_array(producer.get("toolchains"), "producer.toolchains"):
            record = _require_object(entry, "producer.toolchains[]")
            version = _require_string(record, "go_version", "producer.toolchains[]")
            existing = toolchains.get(version)
            if existing is not None and existing != record:
                raise VerificationError(
                    f"manifest fragments disagree about Go {version}"
                )
            toolchains[version] = record
    if merged is None:
        raise VerificationError("no manifest fragments were merged")
    merged["toolchains"] = [
        toolchains[version] for version in sorted(toolchains, key=_version_key)
    ]
    return merged


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as error:
        raise VerificationError(f"malformed Go version {version!r}") from error


def merge_manifests(
    fragment_paths: list[Path], output_path: Path, root: Path
) -> VerificationResult:
    if not fragment_paths:
        raise VerificationError("no manifest fragments were found")
    fragments: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for fragment_path in sorted(fragment_paths, key=lambda item: item.as_posix()):
        verify_manifest(fragment_path, root)
        fragment = _load_manifest(fragment_path)
        fragments.append(fragment)
        artifacts.extend(_require_array(fragment.get("artifacts"), "artifacts"))

    first = fragments[0]
    for fragment in fragments[1:]:
        if (
            fragment["schema_version"] != first["schema_version"]
            or fragment["corpus"] != first["corpus"]
        ):
            raise VerificationError("manifest fragments have inconsistent identities")

    artifacts.sort(key=lambda artifact: str(artifact.get("path", "")))
    merged = {
        "schema_version": first["schema_version"],
        "corpus": first["corpus"],
        "producer": _merge_producers(fragments),
        "artifacts": artifacts,
    }
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
    parser.add_argument(
        "--require-schema-validation",
        action="store_true",
        help="fail when jsonschema is not installed instead of skipping it",
    )
    args = parser.parse_args()
    if args.require_schema_validation and not validate_against_schema(
        _load_manifest(args.manifest)
    ):
        raise VerificationError(
            "jsonschema is not installed, so the manifest schema was not applied"
        )
    result = verify_manifest(args.manifest, args.root)
    if args.require_complete_matrix:
        verify_complete_matrix(args.manifest)
    print(
        f"verified {result.artifact_count} artifact(s), {result.total_bytes} byte(s)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
