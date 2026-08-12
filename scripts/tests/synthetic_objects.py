# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Hand-built ELF, PE, and Mach-O images for the producer's own tests.

The corpus itself is generated in CI and never committed from a developer's
machine, so the producer tests cannot rely on a real artifact being present.
They synthesize the smallest image each reader will accept instead, which also
makes it cheap to corrupt exactly one field and prove the reader notices.
"""

from __future__ import annotations

import struct

_ELF_MACHINES = {"x86_64": 0x3E, "aarch64": 0xB7}
_MACHO_CPU_TYPES = {"x86_64": 0x01000007, "aarch64": 0x0100000C}
_PE_MACHINES = {"x86_64": 0x8664, "aarch64": 0xAA64}

_SHT_PROGBITS = 1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4


def dwarf_frame_section() -> bytes:
    """A CIE, one FDE, and the zero terminator: the smallest valid chain."""

    cie_body = struct.pack("<I", 0) + b"\x01" + b"\x00" * 7
    fde_body = struct.pack("<I", 16) + b"\x00" * 8
    return b"".join(
        (
            struct.pack("<I", len(cie_body)),
            cie_body,
            struct.pack("<I", len(fde_body)),
            fde_body,
            struct.pack("<I", 0),
        )
    )


def compact_unwind_section(version: int = 1, index_count: int = 2) -> bytes:
    """A `__unwind_info` header with a first-level index and nothing else."""

    return struct.pack("<7I", version, 28, 0, 28, 0, 28, index_count) + b"\x00" * 32


def _string_table(names: list[str]) -> tuple[bytes, dict[str, int]]:
    table = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(table)
        table += name.encode("utf-8") + b"\x00"
    return bytes(table), offsets


def build_elf(
    *,
    architecture: str = "x86_64",
    symbols: tuple[str, ...] = (),
    sections: tuple[str, ...] = (".text", ".eh_frame", ".gcc_except_table"),
    eh_frame: bytes | None = None,
    trailing_bytes: bytes = b"",
) -> bytes:
    """Return a 64-bit little-endian ELF with the requested sections."""

    frame = dwarf_frame_section() if eh_frame is None else eh_frame
    contents: dict[str, bytes] = {}
    for name in sections:
        if name == ".eh_frame":
            contents[name] = frame
        elif name == ".text":
            contents[name] = b"\x90" * 16
        else:
            contents[name] = b"\x00" * 8

    symbol_names = list(symbols)
    string_table, string_offsets = _string_table(symbol_names)
    symbol_table = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
    for name in symbol_names:
        symbol_table += struct.pack(
            "<IBBHQQ", string_offsets[name], 0x12, 0, 1, 0x1000, 8
        )

    ordered = list(sections) + [".symtab", ".strtab", ".shstrtab"]
    section_names, name_offsets = _string_table(ordered)
    contents[".symtab"] = bytes(symbol_table)
    contents[".strtab"] = string_table
    contents[".shstrtab"] = section_names

    payload = bytearray(b"\x00" * 64)
    payload[0:4] = b"\x7fELF"
    payload[4] = 2
    payload[5] = 1
    payload[6] = 1
    offsets: dict[str, int] = {}
    for name in ordered:
        while len(payload) % 8:
            payload += b"\x00"
        offsets[name] = len(payload)
        payload += contents[name]

    while len(payload) % 8:
        payload += b"\x00"
    section_header_offset = len(payload)
    symtab_index = ordered.index(".symtab")
    strtab_index = ordered.index(".strtab")

    headers = bytearray(struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    for index, name in enumerate(ordered):
        if name == ".symtab":
            section_type, flags, link, entry_size = _SHT_SYMTAB, 0, strtab_index + 1, 24
        elif name in (".strtab", ".shstrtab"):
            section_type, flags, link, entry_size = _SHT_STRTAB, 0, 0, 0
        else:
            flags = _SHF_ALLOC | (_SHF_EXECINSTR if name == ".text" else 0)
            section_type, link, entry_size = _SHT_PROGBITS, 0, 0
        headers += struct.pack(
            "<IIQQQQIIQQ",
            name_offsets[name],
            section_type,
            flags,
            0x1000 + index * 0x1000,
            offsets[name],
            len(contents[name]),
            link,
            0,
            8,
            entry_size,
        )
    payload += headers
    payload += trailing_bytes

    struct.pack_into("<H", payload, 16, 2)
    struct.pack_into("<H", payload, 18, _ELF_MACHINES[architecture])
    struct.pack_into("<I", payload, 20, 1)
    struct.pack_into("<Q", payload, 40, section_header_offset)
    struct.pack_into("<H", payload, 52, 64)
    struct.pack_into("<HHH", payload, 58, 64, len(ordered) + 1, len(ordered))
    # The section-name table is the last entry, and the null header shifts
    # every index by one.
    struct.pack_into("<H", payload, 62, ordered.index(".shstrtab") + 1)
    assert symtab_index >= 0
    return bytes(payload)


def build_macho(
    *,
    architecture: str = "aarch64",
    symbols: tuple[str, ...] = (),
    sections: tuple[str, ...] = (
        "__text",
        "__eh_frame",
        "__gcc_except_tab",
        "__unwind_info",
    ),
    unwind_info: bytes | None = None,
    trailing_bytes: bytes = b"",
) -> bytes:
    """Return a 64-bit little-endian Mach-O with one segment and a symbol table."""

    contents: dict[str, bytes] = {}
    for name in sections:
        if name == "__unwind_info":
            contents[name] = (
                compact_unwind_section() if unwind_info is None else unwind_info
            )
        elif name == "__eh_frame":
            contents[name] = dwarf_frame_section()
        elif name == "__text":
            contents[name] = b"\x1f\x20\x03\xd5" * 4
        else:
            contents[name] = b"\x00" * 8

    # Mach-O symbol names carry a leading underscore, which is exactly the
    # normalization the reader has to undo.
    encoded_symbols = [f"_{name}" for name in symbols]
    string_table, string_offsets = _string_table(encoded_symbols)
    symbol_table = bytearray()
    for name in encoded_symbols:
        symbol_table += struct.pack("<IBBHQ", string_offsets[name], 0x0F, 1, 0, 0x1000)

    section_count = len(sections)
    segment_size = 72 + section_count * 80
    command_size = segment_size + 24
    body_offset = 32 + command_size
    while body_offset % 16:
        body_offset += 1

    body = bytearray()
    offsets: dict[str, int] = {}
    for name in sections:
        offsets[name] = body_offset + len(body)
        body += contents[name]
        while len(body) % 8:
            body += b"\x00"
    symbol_offset = body_offset + len(body)
    body += bytes(symbol_table)
    string_offset = body_offset + len(body)
    body += string_table

    payload = bytearray()
    payload += struct.pack(
        "<IIIIIII",
        0xFEEDFACF,
        _MACHO_CPU_TYPES[architecture],
        0,
        2,
        2,
        command_size,
        0,
    )
    payload += struct.pack("<I", 0)

    segment = bytearray()
    segment += struct.pack("<II", 0x19, segment_size)
    segment += b"__TEXT".ljust(16, b"\x00")
    segment += struct.pack(
        "<QQQQiiII", 0, 0x10000, 0, len(body), 7, 5, section_count, 0
    )
    for index, name in enumerate(sections):
        segment += name.encode("ascii").ljust(16, b"\x00")
        segment += b"__TEXT".ljust(16, b"\x00")
        flags = 0x80000400 if name == "__text" else 0
        segment += struct.pack(
            "<QQIIIIIIII",
            0x1000 + index * 0x1000,
            len(contents[name]),
            offsets[name],
            2,
            0,
            0,
            flags,
            0,
            0,
            0,
        )
    payload += segment
    payload += struct.pack(
        "<IIIIII",
        0x02,
        24,
        symbol_offset,
        len(encoded_symbols),
        string_offset,
        len(string_table),
    )
    payload += b"\x00" * (body_offset - len(payload))
    payload += body
    payload += trailing_bytes
    return bytes(payload)


def build_pe(
    *,
    architecture: str = "x86_64",
    exports: tuple[str, ...] = (),
    sections: tuple[str, ...] = (".text", ".pdata", ".rdata"),
    runtime_functions: tuple[tuple[int, int, int], ...] | None = None,
    trailing_bytes: bytes = b"",
) -> bytes:
    """Return a PE32+ image with a `.pdata` table and an optional export table."""

    section_layout = [
        (".text", 0x1000, 0x400, True, False),
        (".pdata", 0x2000, 0x600, False, False),
        (".rdata", 0x3000, 0x800, False, False),
        (".edata", 0x4000, 0xA00, False, False),
        (".data", 0x5000, 0xC00, False, True),
    ]
    chosen = [entry for entry in section_layout if entry[0] in sections]
    if exports and ".edata" not in sections:
        chosen.append(section_layout[3])

    payload = bytearray(b"\x00" * 0x1000)
    payload[0:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    pe = 0x80
    payload[pe : pe + 4] = b"PE\0\0"
    optional_size = 0xF0
    struct.pack_into(
        "<HHIIIHH",
        payload,
        pe + 4,
        _PE_MACHINES[architecture],
        len(chosen),
        0,
        0,
        0,
        optional_size,
        0x0022,
    )
    optional = pe + 24
    struct.pack_into("<H", payload, optional, 0x20B)
    struct.pack_into("<Q", payload, optional + 24, 0x140000000)
    struct.pack_into("<I", payload, optional + 60, 0x400)
    struct.pack_into("<I", payload, optional + 108, 16)
    directory = optional + 112

    entries = runtime_functions
    if entries is None:
        entries = ((0x1000, 0x1010, 0x3000),)
    struct.pack_into("<II", payload, directory + 3 * 8, 0x2000, len(entries) * 12)

    section_table = optional + optional_size
    for index, (name, rva, raw, executable, writable) in enumerate(chosen):
        offset = section_table + index * 40
        payload[offset : offset + 8] = name.encode("ascii").ljust(8, b"\x00")
        characteristics = 0x40000040
        if executable:
            characteristics = 0x60000020
        elif writable:
            characteristics = 0xC0000040
        struct.pack_into(
            "<IIIIIIHHI",
            payload,
            offset + 8,
            0x200,
            rva,
            0x200,
            raw,
            0,
            0,
            0,
            0,
            characteristics,
        )

    for index, (begin, end, unwind) in enumerate(entries):
        struct.pack_into("<III", payload, 0x600 + index * 12, begin, end, unwind)

    if exports:
        struct.pack_into("<II", payload, directory + 0 * 8, 0x4000, 40)
        export_offset = 0xA00
        name_array_rva = 0x4000 + 64
        struct.pack_into("<I", payload, export_offset + 24, len(exports))
        struct.pack_into("<I", payload, export_offset + 32, name_array_rva)
        cursor = export_offset + 64 + len(exports) * 4
        for index, name in enumerate(exports):
            struct.pack_into(
                "<I",
                payload,
                export_offset + 64 + index * 4,
                0x4000 + (cursor - export_offset),
            )
            encoded = name.encode("ascii") + b"\x00"
            payload[cursor : cursor + len(encoded)] = encoded
            cursor += len(encoded)

    payload += trailing_bytes
    return bytes(payload)
