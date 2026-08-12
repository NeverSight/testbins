# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Synthetic ELF, PE, and Mach-O images for the Go corpus verifier tests.

Fixtures are assembled byte by byte at run time rather than committed, because
a corpus repository that carries a binary nobody built in CI is exactly the
thing this producer exists to avoid.  Building them here also keeps the
malformed shapes reachable: a real toolchain will not emit a container with two
plausible `pclntab` headers in it, and that is one of the cases the verifier
has to reject.
"""

from __future__ import annotations

import struct
import unittest
from dataclasses import dataclass, field

PCLNTAB_GO12 = 0xFFFFFFFB
PCLNTAB_GO116 = 0xFFFFFFFA
PCLNTAB_GO118 = 0xFFFFFFF0
PCLNTAB_GO120 = 0xFFFFFFF1


def pclntab_header(
    magic: int = PCLNTAB_GO120,
    *,
    min_lc: int = 1,
    pointer_size: int = 8,
    function_count: int = 1500,
    pad: bytes = b"\0\0",
) -> bytes:
    """The eight-byte `runtime.pcHeader` prefix followed by `nfunc`.

    Every layout the four magics name starts this way, which is the whole
    reason a reader can identify the table before it knows which one it has.
    """

    count = struct.pack("<Q" if pointer_size == 8 else "<I", function_count)
    return struct.pack("<I", magic) + pad + bytes((min_lc, pointer_size)) + count


@dataclass
class SectionSpec:
    name: str
    body: bytes = b""
    virtual_address: int = 0
    #: Zero-filled sections such as `.bss` occupy no file range.
    file_backed: bool = True


@dataclass
class ImageSpec:
    sections: list[SectionSpec] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    #: Mach-O prefixes every symbol with an underscore.
    symbol_prefix: str = ""


def _align(value: int, alignment: int = 16) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _string_table(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\0")
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(blob)
        blob += name.encode("utf-8") + b"\0"
    return bytes(blob), offsets


#===========================================================================
# ELF
#===========================================================================

_SHT_NULL = 0
_SHT_PROGBITS = 1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_NOBITS = 8


def build_elf(spec: ImageSpec) -> bytes:
    names = [".shstrtab"] + [section.name for section in spec.sections]
    has_symbols = bool(spec.symbols)
    if has_symbols:
        names += [".symtab", ".strtab"]
    shstrtab, name_offsets = _string_table(names)
    symbol_strtab, symbol_offsets = _string_table(spec.symbols)

    entries: list[tuple[str, int, int, bytes, bool, int]] = [
        ("", _SHT_NULL, 0, b"", False, 0)
    ]
    for section in spec.sections:
        kind = _SHT_PROGBITS if section.file_backed else _SHT_NOBITS
        entries.append(
            (
                section.name,
                kind,
                section.virtual_address,
                section.body,
                section.file_backed,
                0,
            )
        )
    symbol_table_index = 0
    if has_symbols:
        symbol_blob = bytearray(b"\0" * 24)
        for name in spec.symbols:
            symbol_blob += struct.pack(
                "<IBBHQQ", symbol_offsets[name], 0x12, 0, 1, 0x1000, 16
            )
        symbol_table_index = len(entries)
        entries.append((".symtab", _SHT_SYMTAB, 0, bytes(symbol_blob), True, 0))
        entries.append((".strtab", _SHT_STRTAB, 0, symbol_strtab, True, 0))
    entries.append((".shstrtab", _SHT_STRTAB, 0, shstrtab, True, 0))

    payload = bytearray(b"\0" * 64)
    payload[0:4] = b"\x7fELF"
    payload[4] = 2
    payload[5] = 1
    payload[6] = 1
    payload[16:18] = struct.pack("<H", 2)
    payload[18:20] = struct.pack("<H", 0x3E)

    placed: list[tuple[str, int, int, int, int, int]] = []
    for name, kind, address, body, file_backed, _link in entries:
        if not body and kind in (_SHT_NULL,):
            placed.append((name, kind, address, 0, 0, 0))
            continue
        if not file_backed:
            placed.append((name, kind, address, 0, len(body), 0))
            continue
        payload += b"\0" * (_align(len(payload)) - len(payload))
        offset = len(payload)
        payload += body
        placed.append((name, kind, address, offset, len(body), 0))

    payload += b"\0" * (_align(len(payload)) - len(payload))
    section_offset = len(payload)
    for index, (name, kind, address, offset, size, _link) in enumerate(placed):
        link = 0
        if kind == _SHT_SYMTAB:
            link = symbol_table_index + 1
        payload += struct.pack(
            "<IIQQQQIIQQ",
            name_offsets.get(name, 0) if name else 0,
            kind,
            0,
            address,
            offset,
            size,
            link,
            0,
            1,
            24 if kind == _SHT_SYMTAB else 0,
        )

    struct.pack_into("<Q", payload, 0x28, section_offset)
    struct.pack_into("<HHH", payload, 0x3A, 64, len(placed), len(placed) - 1)
    return bytes(payload)


#===========================================================================
# PE
#===========================================================================


def build_pe(spec: ImageSpec) -> bytes:
    optional_size = 0xF0
    header_size = 0x40 + 24 + optional_size + 40 * len(spec.sections)
    body_start = _align(header_size, 512)

    payload = bytearray(b"\0" * body_start)
    payload[0:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x40)
    payload[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", payload, 0x40 + 24, 0x20B)

    placed: list[tuple[str, int, int, int, int]] = []
    for section in spec.sections:
        if not section.file_backed:
            placed.append((section.name, section.virtual_address, len(section.body), 0, 0))
            continue
        payload += b"\0" * (_align(len(payload), 512) - len(payload))
        offset = len(payload)
        payload += section.body
        placed.append(
            (
                section.name,
                section.virtual_address,
                len(section.body),
                offset,
                len(section.body),
            )
        )

    symbol_offset = 0
    symbol_count = 0
    if spec.symbols:
        payload += b"\0" * (_align(len(payload)) - len(payload))
        symbol_offset = len(payload)
        symbol_count = len(spec.symbols)
        strings = bytearray(b"\0\0\0\0")
        records = bytearray()
        for name in spec.symbols:
            if len(name) <= 8:
                records += name.encode("utf-8").ljust(8, b"\0")
            else:
                records += struct.pack("<II", 0, len(strings))
                strings += name.encode("utf-8") + b"\0"
            records += struct.pack("<IhHBB", 0x1000, 1, 0x20, 2, 0)
        struct.pack_into("<I", strings, 0, len(strings))
        payload += records + strings

    table = 0x40 + 24 + optional_size
    for index, (name, address, virtual_size, offset, size) in enumerate(placed):
        base = table + index * 40
        payload[base : base + 8] = name.encode("utf-8").ljust(8, b"\0")[:8]
        struct.pack_into("<IIII", payload, base + 8, virtual_size, address, size, offset)
    struct.pack_into(
        "<HHIIIHH",
        payload,
        0x40 + 4,
        0x8664,
        len(placed),
        0,
        symbol_offset,
        symbol_count,
        optional_size,
        0x0022,
    )
    return bytes(payload)


#===========================================================================
# Mach-O
#===========================================================================

_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x02


def build_macho(spec: ImageSpec) -> bytes:
    prefix = spec.symbol_prefix or "_"
    symbols = [f"{prefix}{name}" for name in spec.symbols]
    segment_size = 72 + 80 * len(spec.sections)
    symtab_size = 24 if symbols else 0
    command_count = 1 + (1 if symbols else 0)
    header_size = 32 + segment_size + symtab_size
    body_start = _align(header_size, 0x100)

    payload = bytearray(b"\0" * body_start)
    struct.pack_into("<IiiIIII", payload, 0, 0xFEEDFACF, 0x0100000C, 0, 2, command_count, segment_size + symtab_size, 0)

    placed: list[tuple[str, int, int, int]] = []
    for section in spec.sections:
        if not section.file_backed:
            placed.append((section.name, section.virtual_address, len(section.body), 0))
            continue
        payload += b"\0" * (_align(len(payload)) - len(payload))
        offset = len(payload)
        payload += section.body
        placed.append((section.name, section.virtual_address, len(section.body), offset))

    symbol_offset = 0
    string_offset = 0
    string_size = 0
    if symbols:
        payload += b"\0" * (_align(len(payload)) - len(payload))
        symbol_offset = len(payload)
        strings, offsets = _string_table(symbols)
        records = bytearray()
        for name in symbols:
            records += struct.pack("<IBBHQ", offsets[name], 0x0F, 1, 0, 0x1000)
        payload += records
        string_offset = len(payload)
        payload += strings
        string_size = len(strings)

    cursor = 32
    struct.pack_into("<II", payload, cursor, _LC_SEGMENT_64, segment_size)
    payload[cursor + 8 : cursor + 24] = b"__TEXT".ljust(16, b"\0")
    struct.pack_into("<I", payload, cursor + 64, len(placed))
    section_cursor = cursor + 72
    for name, address, size, offset in placed:
        payload[section_cursor : section_cursor + 16] = name.encode("utf-8").ljust(16, b"\0")[:16]
        payload[section_cursor + 16 : section_cursor + 32] = b"__TEXT".ljust(16, b"\0")
        struct.pack_into("<QQ", payload, section_cursor + 32, address, size)
        struct.pack_into("<I", payload, section_cursor + 48, offset)
        section_cursor += 80
    if symbols:
        symtab_cursor = cursor + segment_size
        struct.pack_into(
            "<IIIIII",
            payload,
            symtab_cursor,
            _LC_SYMTAB,
            symtab_size,
            symbol_offset,
            len(symbols),
            string_offset,
            string_size,
        )
    return bytes(payload)


BUILDERS = {"elf": build_elf, "pe": build_pe, "macho": build_macho}


class ObjectFixtureTests(unittest.TestCase):
    """The fixtures are only useful if they look like the real thing."""

    def test_every_builder_produces_its_own_magic(self) -> None:
        spec = ImageSpec(
            sections=[SectionSpec(".text", b"\x90" * 64, 0x1000)],
            symbols=["runtime.gopanic"],
        )
        self.assertEqual(build_elf(spec)[:4], b"\x7fELF")
        self.assertEqual(build_pe(spec)[:2], b"MZ")
        self.assertEqual(build_macho(spec)[:4], b"\xcf\xfa\xed\xfe")

    def test_pclntab_header_matches_the_documented_prefix(self) -> None:
        header = pclntab_header(PCLNTAB_GO116, min_lc=4, function_count=7)
        self.assertEqual(header[:4], struct.pack("<I", PCLNTAB_GO116))
        self.assertEqual(header[4:6], b"\0\0")
        self.assertEqual(header[6], 4)
        self.assertEqual(header[7], 8)
        self.assertEqual(struct.unpack_from("<Q", header, 8)[0], 7)


if __name__ == "__main__":
    unittest.main()
