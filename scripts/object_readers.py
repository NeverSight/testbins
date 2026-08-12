#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Minimal ELF, PE, and Mach-O readers for corpus verification.

The point of this module is independence: the verifier must not take the
producer's word for what is in a binary, and it must reach that conclusion
without a third-party dependency that could drift from what CI installs.

Only the structure the corpus asserts is decoded -- the section table, the
symbol table, and enough of each format's unwind metadata to prove it is real
and file-backed. Anything richer belongs in NeverD, which is the consumer these
binaries exist to test.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any


class ObjectFormatError(ValueError):
    """Raised when a binary cannot be decoded as the format it claims."""


# A corpus artifact is a small test program. These caps exist so that a
# corrupted or hostile header cannot turn verification into an unbounded loop.
_MAX_SECTIONS = 4096
_MAX_SYMBOLS = 1 << 20
_MAX_LOAD_COMMANDS = 4096
_MAX_UNWIND_ENTRIES = 1 << 20
_MAX_STRING_BYTES = 4096

# ARM EHABI index entries are two words: a PREL31 offset to the function and
# either an inline compact model, a PREL31 offset into `.ARM.extab`, or the
# `EXIDX_CANTUNWIND` marker.
_ARM_EXIDX_SECTION = ".ARM.exidx"
_ARM_EXIDX_ENTRY_SIZE = 8


@dataclass(frozen=True)
class ObjectSection:
    """One section, named as the object format names it."""

    name: str
    address: int
    size: int
    file_offset: int
    file_size: int
    executable: bool
    writable: bool
    # True when the section occupies no bytes in the file, as `.bss` does.
    virtual_only: bool


class ObjectImage:
    """Common surface the verifier uses, whatever the format underneath."""

    object_format = "unknown"

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.architecture = "unknown"
        self.sections: dict[str, ObjectSection] = {}
        self.symbols: set[str] = set()
        self.has_symbol_table = False

    def _unpack(self, fmt: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if offset < 0 or size > len(self._payload) - offset:
            raise ObjectFormatError("truncated object structure")
        return struct.unpack_from(fmt, self._payload, offset)

    def _slice(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or size > len(self._payload) - offset:
            raise ObjectFormatError("object range leaves the file")
        return self._payload[offset : offset + size]

    def _add_section(self, section: ObjectSection) -> None:
        # A duplicate name is legal in every one of these formats. The first
        # occurrence wins so that lookups stay deterministic.
        self.sections.setdefault(section.name, section)

    def contains_bytes(self, needle: bytes) -> bool:
        """True when the raw file contains \\p needle."""

        return needle in self._payload

    def section_bytes(self, name: str) -> bytes:
        section = self.sections.get(name)
        if section is None:
            raise ObjectFormatError(f"section {name} is absent")
        if section.virtual_only:
            raise ObjectFormatError(f"section {name} has no file-backed bytes")
        return self._slice(section.file_offset, section.file_size)

    def verify_unwind_tables(self) -> int:
        """Prove the image's unwind metadata is present and structurally sound.

        Returns a count of verified records so a caller can reject an image
        whose tables exist but describe nothing.
        """

        raise NotImplementedError

    def frame_record_counts(self) -> tuple[int, int]:
        """Return the (CIE, FDE) counts of the image's DWARF frame section.

        `verify_unwind_tables` only proves the chain is well formed, and a
        section holding one CIE and no frame descriptions satisfies that while
        describing no code at all. Splitting the two lets a caller require
        coverage rather than presence.
        """

        raise ObjectFormatError(
            f"{self.object_format} images have no DWARF frame section here"
        )

    def arm_exidx_entries(self) -> int:
        """Return the number of ARM EHABI index entries, or zero when absent.

        Only ELF can carry `.ARM.exidx`, so every other format answers zero
        rather than raising: absence is the expected answer, not an error.
        """

        return 0


# ===----------------------------------------------------------------------===#
# ELF
# ===----------------------------------------------------------------------===#


class ELFImage(ObjectImage):
    object_format = "elf"

    _MACHINES = {
        0x03: "x86",
        0x28: "arm",
        0x3E: "x86_64",
        0xB7: "aarch64",
    }

    _SHT_NOBITS = 8
    _SHT_SYMTAB = 2
    _SHT_DYNSYM = 11
    _SHF_WRITE = 0x1
    _SHF_EXECINSTR = 0x4

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self._is64 = False
        self._prefix = "<"
        self._parse()

    def _parse(self) -> None:
        if len(self._payload) < 64 or self._payload[:4] != b"\x7fELF":
            raise ObjectFormatError("artifact is not an ELF image")
        elf_class = self._payload[4]
        elf_data = self._payload[5]
        if elf_class not in (1, 2):
            raise ObjectFormatError("unsupported ELF class")
        if elf_data not in (1, 2):
            raise ObjectFormatError("unsupported ELF data encoding")
        self._is64 = elf_class == 2
        self._prefix = "<" if elf_data == 1 else ">"

        (machine,) = self._unpack(f"{self._prefix}H", 18)
        self.architecture = self._MACHINES.get(machine, "unknown")
        if self.architecture == "unknown":
            raise ObjectFormatError(f"unsupported ELF machine 0x{machine:04x}")

        if self._is64:
            (section_offset,) = self._unpack(f"{self._prefix}Q", 40)
            entry_size, count, string_index = self._unpack(f"{self._prefix}HHH", 58)
        else:
            (section_offset,) = self._unpack(f"{self._prefix}I", 32)
            entry_size, count, string_index = self._unpack(f"{self._prefix}HHH", 46)
        expected_entry_size = 64 if self._is64 else 40
        if entry_size != expected_entry_size:
            raise ObjectFormatError("unexpected ELF section header size")
        if not 1 <= count <= _MAX_SECTIONS:
            raise ObjectFormatError("invalid ELF section count")
        if string_index >= count:
            raise ObjectFormatError("ELF section name table index is out of range")

        headers = []
        for index in range(count):
            headers.append(
                self._read_section_header(section_offset + index * entry_size)
            )

        name_table = self._section_payload(headers[string_index])
        for header in headers:
            name = _read_c_string(name_table, header["name_offset"])
            if not name:
                continue
            self._add_section(
                ObjectSection(
                    name=name,
                    address=header["address"],
                    size=header["size"],
                    file_offset=header["offset"],
                    file_size=0
                    if header["type"] == self._SHT_NOBITS
                    else header["size"],
                    executable=bool(header["flags"] & self._SHF_EXECINSTR),
                    writable=bool(header["flags"] & self._SHF_WRITE),
                    virtual_only=header["type"] == self._SHT_NOBITS,
                )
            )

        self._parse_symbols(headers)

    def _read_section_header(self, offset: int) -> dict[str, int]:
        if self._is64:
            fields = self._unpack(f"{self._prefix}IIQQQQIIQQ", offset)
        else:
            fields = self._unpack(f"{self._prefix}IIIIIIIIII", offset)
        header = {
            "name_offset": int(fields[0]),
            "type": int(fields[1]),
            "flags": int(fields[2]),
            "address": int(fields[3]),
            "offset": int(fields[4]),
            "size": int(fields[5]),
            "link": int(fields[6]),
            "entry_size": int(fields[9]),
        }
        if header["type"] != self._SHT_NOBITS:
            # Touching the range proves it is inside the file before anything
            # tries to read through it.
            self._slice(header["offset"], header["size"])
        return header

    def _section_payload(self, header: dict[str, int]) -> bytes:
        if header["type"] == self._SHT_NOBITS:
            return b""
        return self._slice(header["offset"], header["size"])

    def _parse_symbols(self, headers: list[dict[str, int]]) -> None:
        entry_size = 24 if self._is64 else 16
        for header in headers:
            if header["type"] not in (self._SHT_SYMTAB, self._SHT_DYNSYM):
                continue
            if header["entry_size"] not in (0, entry_size):
                raise ObjectFormatError("unexpected ELF symbol entry size")
            if header["link"] >= len(headers):
                raise ObjectFormatError("ELF symbol table names a missing string table")
            strings = self._section_payload(headers[header["link"]])
            table = self._section_payload(header)
            count = len(table) // entry_size
            if count > _MAX_SYMBOLS:
                raise ObjectFormatError("ELF symbol table exceeds the decode budget")
            self.has_symbol_table = self.has_symbol_table or count > 0
            for index in range(count):
                (name_offset,) = struct.unpack_from(
                    f"{self._prefix}I", table, index * entry_size
                )
                name = _read_c_string(strings, int(name_offset))
                if name:
                    self.symbols.add(name)

    def verify_unwind_tables(self) -> int:
        payload = self.section_bytes(".eh_frame")
        if not payload:
            raise ObjectFormatError(".eh_frame is empty")
        return _walk_dwarf_frame_section(payload, self._prefix)

    def frame_record_counts(self) -> tuple[int, int]:
        return count_dwarf_frame_records(self.section_bytes(".eh_frame"), self._prefix)

    def arm_exidx_entries(self) -> int:
        if _ARM_EXIDX_SECTION not in self.sections:
            return 0
        payload = self.section_bytes(_ARM_EXIDX_SECTION)
        if len(payload) % _ARM_EXIDX_ENTRY_SIZE:
            raise ObjectFormatError(
                f"{_ARM_EXIDX_SECTION} is not a whole number of index entries"
            )
        return len(payload) // _ARM_EXIDX_ENTRY_SIZE


# ===----------------------------------------------------------------------===#
# Mach-O
# ===----------------------------------------------------------------------===#


class MachOImage(ObjectImage):
    object_format = "macho"

    _CPU_TYPES = {
        0x01000007: "x86_64",
        0x0100000C: "aarch64",
        0x00000007: "x86",
        0x0000000C: "arm",
    }

    _LC_SEGMENT = 0x01
    _LC_SEGMENT_64 = 0x19
    _LC_SYMTAB = 0x02
    _S_ATTR_PURE_INSTRUCTIONS = 0x80000000
    _S_ATTR_SOME_INSTRUCTIONS = 0x00000400
    _S_ZEROFILL = 0x1

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self._is64 = False
        self._parse()

    def _parse(self) -> None:
        if len(self._payload) < 28:
            raise ObjectFormatError("artifact is too small to be a Mach-O image")
        (magic,) = struct.unpack_from("<I", self._payload, 0)
        if magic in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
            raise ObjectFormatError(
                "universal Mach-O binaries are not part of this corpus"
            )
        if magic == 0xFEEDFACF:
            self._is64 = True
        elif magic == 0xFEEDFACE:
            self._is64 = False
        else:
            raise ObjectFormatError("artifact is not a little-endian Mach-O image")

        cpu_type, _cpu_subtype, _file_type, command_count, command_size = self._unpack(
            "<IIIII", 4
        )
        self.architecture = self._CPU_TYPES.get(cpu_type, "unknown")
        if self.architecture == "unknown":
            raise ObjectFormatError(f"unsupported Mach-O cputype 0x{cpu_type:08x}")
        if not 1 <= command_count <= _MAX_LOAD_COMMANDS:
            raise ObjectFormatError("invalid Mach-O load-command count")

        header_size = 32 if self._is64 else 28
        self._slice(header_size, command_size)
        offset = header_size
        end = header_size + command_size
        for _ in range(command_count):
            if offset + 8 > end:
                raise ObjectFormatError("Mach-O load commands leave their region")
            command, size = self._unpack("<II", offset)
            if size < 8 or offset + size > end:
                raise ObjectFormatError("Mach-O load command has an invalid size")
            if command in (self._LC_SEGMENT, self._LC_SEGMENT_64):
                self._parse_segment(offset, size)
            elif command == self._LC_SYMTAB:
                self._parse_symtab(offset, size)
            offset += size

    def _parse_segment(self, offset: int, size: int) -> None:
        if self._is64:
            if size < 72:
                raise ObjectFormatError("truncated Mach-O 64-bit segment command")
            segment_name = _decode_fixed_name(self._slice(offset + 8, 16))
            (section_count,) = self._unpack("<I", offset + 64)
            section_offset = offset + 72
            section_size = 80
        else:
            if size < 56:
                raise ObjectFormatError("truncated Mach-O 32-bit segment command")
            segment_name = _decode_fixed_name(self._slice(offset + 8, 16))
            (section_count,) = self._unpack("<I", offset + 48)
            section_offset = offset + 56
            section_size = 68
        if section_count > _MAX_SECTIONS:
            raise ObjectFormatError("Mach-O segment declares too many sections")
        if section_offset + section_count * section_size > offset + size:
            raise ObjectFormatError("Mach-O section headers leave their command")

        for index in range(section_count):
            base = section_offset + index * section_size
            name = _decode_fixed_name(self._slice(base, 16))
            if self._is64:
                address, section_bytes = self._unpack("<QQ", base + 32)
                (file_offset,) = self._unpack("<I", base + 48)
                (flags,) = self._unpack("<I", base + 64)
            else:
                address, section_bytes = self._unpack("<II", base + 32)
                (file_offset,) = self._unpack("<I", base + 40)
                (flags,) = self._unpack("<I", base + 56)
            zero_filled = (flags & 0xFF) == self._S_ZEROFILL
            file_size = 0 if zero_filled else int(section_bytes)
            if file_size:
                self._slice(int(file_offset), file_size)
            executable = bool(
                flags
                & (self._S_ATTR_PURE_INSTRUCTIONS | self._S_ATTR_SOME_INSTRUCTIONS)
            )
            section = ObjectSection(
                name=name,
                address=int(address),
                size=int(section_bytes),
                file_offset=int(file_offset),
                file_size=file_size,
                executable=executable,
                writable=segment_name not in ("__TEXT", "__LINKEDIT"),
                virtual_only=zero_filled,
            )
            self._add_section(section)
            # Two segments may carry the same section name, so the qualified
            # spelling is registered as well and stays unambiguous.
            self.sections.setdefault(f"{segment_name},{name}", section)

    def _parse_symtab(self, offset: int, size: int) -> None:
        if size < 24:
            raise ObjectFormatError("truncated Mach-O LC_SYMTAB")
        symbol_offset, symbol_count, string_offset, string_size = self._unpack(
            "<IIII", offset + 8
        )
        if symbol_count > _MAX_SYMBOLS:
            raise ObjectFormatError("Mach-O symbol table exceeds the decode budget")
        entry_size = 16 if self._is64 else 12
        table = self._slice(int(symbol_offset), int(symbol_count) * entry_size)
        strings = self._slice(int(string_offset), int(string_size))
        self.has_symbol_table = self.has_symbol_table or symbol_count > 0
        for index in range(int(symbol_count)):
            (name_offset,) = struct.unpack_from("<I", table, index * entry_size)
            name = _read_c_string(strings, int(name_offset))
            if not name:
                continue
            self.symbols.add(name)
            # Mach-O prefixes C symbols with an underscore. The manifest names
            # symbols the way the source does, so the bare spelling is what a
            # lookup has to find.
            if name.startswith("_"):
                self.symbols.add(name[1:])

    def verify_unwind_tables(self) -> int:
        payload = self.section_bytes("__unwind_info")
        if len(payload) < 4:
            raise ObjectFormatError("__unwind_info is truncated")
        (version,) = struct.unpack_from("<I", payload, 0)
        if version != 1:
            raise ObjectFormatError(f"unsupported __unwind_info version {version}")
        (index_count,) = struct.unpack_from("<I", payload, 24)
        if not 1 <= index_count <= _MAX_UNWIND_ENTRIES:
            raise ObjectFormatError("__unwind_info has no first-level index")
        frames = 0
        if "__eh_frame" in self.sections:
            frames = _walk_dwarf_frame_section(self.section_bytes("__eh_frame"), "<")
        return int(index_count) + frames

    def frame_record_counts(self) -> tuple[int, int]:
        return count_dwarf_frame_records(self.section_bytes("__eh_frame"), "<")


# ===----------------------------------------------------------------------===#
# PE
# ===----------------------------------------------------------------------===#


class PEImage(ObjectImage):
    object_format = "pe"

    _MACHINES = {
        0x014C: "x86",
        0x01C4: "arm",
        0x8664: "x86_64",
        0xAA64: "aarch64",
    }

    _EXPORT_DIRECTORY = 0
    _EXCEPTION_DIRECTORY = 3

    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self._directories: list[tuple[int, int]] = []
        self._size_of_headers = 0
        self._is_pe32_plus = False
        self._parse()

    def _parse(self) -> None:
        if len(self._payload) < 0x40 or self._payload[:2] != b"MZ":
            raise ObjectFormatError("artifact is not a DOS/PE image")
        (pe_offset,) = self._unpack("<I", 0x3C)
        if self._payload[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ObjectFormatError("invalid PE signature")

        (
            machine,
            section_count,
            _timestamp,
            symbol_offset,
            symbol_count,
            optional_size,
            _characteristics,
        ) = self._unpack("<HHIIIHH", pe_offset + 4)
        self.architecture = self._MACHINES.get(machine, "unknown")
        if self.architecture == "unknown":
            raise ObjectFormatError(f"unsupported PE machine 0x{machine:04x}")
        if not 1 <= section_count <= 96:
            raise ObjectFormatError("invalid PE section count")

        optional_offset = pe_offset + 24
        self._slice(optional_offset, optional_size)
        (magic,) = self._unpack("<H", optional_offset)
        if magic == 0x20B:
            self._is_pe32_plus = True
            directory_count_offset = optional_offset + 108
            directory_offset = optional_offset + 112
        elif magic == 0x10B:
            directory_count_offset = optional_offset + 92
            directory_offset = optional_offset + 96
        else:
            raise ObjectFormatError("unsupported PE optional-header magic")
        if self._is_pe32_plus != (self.architecture in ("x86_64", "aarch64")):
            raise ObjectFormatError("PE optional-header bitness disagrees with machine")

        (self._size_of_headers,) = self._unpack("<I", optional_offset + 60)
        (directory_count,) = self._unpack("<I", directory_count_offset)
        directory_count = min(int(directory_count), 16)
        if directory_offset + directory_count * 8 > optional_offset + optional_size:
            raise ObjectFormatError("PE data directories exceed the optional header")
        for index in range(directory_count):
            rva, size = self._unpack("<II", directory_offset + index * 8)
            self._directories.append((int(rva), int(size)))

        section_offset = optional_offset + optional_size
        self._slice(section_offset, section_count * 40)
        for index in range(section_count):
            offset = section_offset + index * 40
            raw_name = self._payload[offset : offset + 8].split(b"\0", 1)[0]
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError as error:
                raise ObjectFormatError("PE section name is not ASCII") from error
            virtual_size, virtual_address, raw_size, raw_offset = self._unpack(
                "<IIII", offset + 8
            )
            (characteristics,) = self._unpack("<I", offset + 36)
            if not name:
                raise ObjectFormatError("empty PE section name")
            if raw_size:
                self._slice(int(raw_offset), int(raw_size))
            self._add_section(
                ObjectSection(
                    name=name,
                    address=int(virtual_address),
                    size=int(virtual_size),
                    file_offset=int(raw_offset),
                    file_size=int(raw_size),
                    executable=bool(characteristics & 0x20000000),
                    writable=bool(characteristics & 0x80000000),
                    virtual_only=raw_size == 0,
                )
            )
        self._parse_coff_symbols(int(symbol_offset), int(symbol_count))
        self._parse_exports()

    def _parse_exports(self) -> None:
        """Read the export table, which is the only names a linked PE keeps.

        A Rust `cdylib` names every `#[unsafe(no_mangle)] pub extern` function
        here, so the shared-library artifacts have real symbol evidence even
        though the executables do not.
        """

        if self._EXPORT_DIRECTORY >= len(self._directories):
            return
        rva, size = self._directories[self._EXPORT_DIRECTORY]
        if not rva or size < 40:
            return
        offset = self._rva_to_offset(rva, 40)
        (name_count,) = self._unpack("<I", offset + 24)
        (name_array_rva,) = self._unpack("<I", offset + 32)
        if not name_count or not name_array_rva:
            return
        if name_count > _MAX_SYMBOLS:
            raise ObjectFormatError("PE export table exceeds the decode budget")
        array_offset = self._rva_to_offset(name_array_rva, int(name_count) * 4)
        self.has_symbol_table = True
        for index in range(int(name_count)):
            (name_rva,) = self._unpack("<I", array_offset + index * 4)
            name_offset = self._rva_to_offset(int(name_rva), 1)
            end = self._payload.find(
                b"\0",
                name_offset,
                min(len(self._payload), name_offset + _MAX_STRING_BYTES),
            )
            if end == -1:
                raise ObjectFormatError("unterminated PE export name")
            self.symbols.add(self._payload[name_offset:end].decode("ascii", "replace"))

    def _parse_coff_symbols(self, symbol_offset: int, symbol_count: int) -> None:
        # A linked Rust image normally carries no COFF symbol table -- the
        # names live in the PDB -- so its absence is expected rather than an
        # error. When one is present it is read, because it is free evidence.
        if not symbol_offset or not symbol_count:
            return
        if symbol_count > _MAX_SYMBOLS:
            raise ObjectFormatError("PE symbol table exceeds the decode budget")
        table = self._slice(symbol_offset, symbol_count * 18)
        strings_offset = symbol_offset + symbol_count * 18
        (strings_size,) = self._unpack("<I", strings_offset)
        if strings_size < 4:
            raise ObjectFormatError("PE string table is truncated")
        strings = self._slice(strings_offset, int(strings_size))
        self.has_symbol_table = True
        index = 0
        while index < symbol_count:
            record = table[index * 18 : index * 18 + 18]
            if record[:4] == b"\0\0\0\0":
                (long_offset,) = struct.unpack_from("<I", record, 4)
                name = _read_c_string(strings, int(long_offset))
            else:
                name = record[:8].split(b"\0", 1)[0].decode("ascii", "replace")
            if name:
                self.symbols.add(name)
            index += 1 + record[17]

    def _section_for_rva(self, rva: int, size: int) -> ObjectSection | None:
        for section in self.sections.values():
            if rva < section.address:
                continue
            delta = rva - section.address
            if delta <= section.file_size and size <= section.file_size - delta:
                return section
        return None

    def _rva_to_offset(self, rva: int, size: int) -> int:
        if rva < 0 or size < 0:
            raise ObjectFormatError("negative PE range")
        if rva < self._size_of_headers:
            self._slice(rva, size)
            return rva
        section = self._section_for_rva(rva, size)
        if section is None:
            raise ObjectFormatError(f"RVA 0x{rva:x} is not file-backed")
        return section.file_offset + (rva - section.address)

    def verify_unwind_tables(self) -> int:
        if self._EXCEPTION_DIRECTORY >= len(self._directories):
            raise ObjectFormatError("PE exception directory is absent")
        rva, size = self._directories[self._EXCEPTION_DIRECTORY]
        if not rva or not size:
            raise ObjectFormatError("PE exception directory is absent")
        if self.architecture != "x86_64":
            raise ObjectFormatError(
                f"{self.architecture} PE unwind records are outside this corpus"
            )
        entry_size = 12
        if size % entry_size:
            raise ObjectFormatError("misaligned x64 runtime-function table")
        count = size // entry_size
        if not 1 <= count <= _MAX_UNWIND_ENTRIES:
            raise ObjectFormatError("invalid x64 runtime-function count")
        offset = self._rva_to_offset(rva, size)
        verified = 0
        for index in range(count):
            begin, end, unwind_rva = self._unpack("<III", offset + index * entry_size)
            if begin == end == unwind_rva == 0:
                continue
            if begin >= end:
                raise ObjectFormatError("x64 runtime-function code range is invalid")
            code = self._section_for_rva(begin, end - begin)
            if code is None or not code.executable:
                raise ObjectFormatError(
                    "x64 runtime-function code range is not executable"
                )
            unwind = self._section_for_rva(unwind_rva, 4)
            if unwind is None or unwind.executable:
                raise ObjectFormatError(
                    "x64 unwind RVA is not backed by non-executable data"
                )
            verified += 1
        if not verified:
            raise ObjectFormatError("x64 runtime-function table is empty")
        return verified

    def frame_record_counts(self) -> tuple[int, int]:
        return count_dwarf_frame_records(self.section_bytes(".eh_frame"), "<")


# ===----------------------------------------------------------------------===#
# Shared helpers
# ===----------------------------------------------------------------------===#


def _read_c_string(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\0", offset, min(len(table), offset + _MAX_STRING_BYTES))
    if end == -1:
        raise ObjectFormatError("unterminated string-table entry")
    return table[offset:end].decode("utf-8", "replace")


def _decode_fixed_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def count_dwarf_frame_records(payload: bytes, prefix: str = "<") -> tuple[int, int]:
    """Walk a `.eh_frame`/`__eh_frame` section and count its CIEs and FDEs.

    Only each entry's length and identifier are decoded. That is enough to
    prove the section holds a well-formed chain of records rather than
    arbitrary bytes, and to tell a section that describes code from one that
    holds nothing but a common information entry, without duplicating the frame
    decoder NeverD already has.
    """

    offset = 0
    entries = 0
    cies = 0
    while offset + 4 <= len(payload):
        (length,) = struct.unpack_from(f"{prefix}I", payload, offset)
        header = 4
        if length == 0xFFFFFFFF:
            if offset + 12 > len(payload):
                raise ObjectFormatError("truncated 64-bit DWARF frame length")
            (length,) = struct.unpack_from(f"{prefix}Q", payload, offset + 4)
            header = 12
        if length == 0:
            # A zero-length record terminates the section.
            break
        if length > len(payload) - offset - header:
            raise ObjectFormatError("DWARF frame record leaves its section")
        if length < 4:
            raise ObjectFormatError("DWARF frame record is too small to hold an id")
        (identifier,) = struct.unpack_from(f"{prefix}I", payload, offset + header)
        if identifier == 0:
            if length < 5:
                raise ObjectFormatError("CIE is too small to hold a version")
            (version,) = struct.unpack_from("B", payload, offset + header + 4)
            if version not in (1, 3, 4):
                raise ObjectFormatError(f"unsupported CIE version {version}")
            cies += 1
        entries += 1
        if entries > _MAX_UNWIND_ENTRIES:
            raise ObjectFormatError("DWARF frame section exceeds the decode budget")
        offset += header + length
    if not entries:
        raise ObjectFormatError("DWARF frame section holds no records")
    return cies, entries - cies


def _walk_dwarf_frame_section(payload: bytes, prefix: str) -> int:
    """Return the total number of records in a DWARF frame section."""

    cies, fdes = count_dwarf_frame_records(payload, prefix)
    return cies + fdes


def load_object(payload: bytes) -> ObjectImage:
    """Decode \\p payload as whichever of the three formats it declares."""

    if payload[:4] == b"\x7fELF":
        return ELFImage(payload)
    if payload[:2] == b"MZ":
        return PEImage(payload)
    if len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] in (
        0xFEEDFACE,
        0xFEEDFACF,
        0xCAFEBABE,
        0xBEBAFECA,
        0xCAFEBABF,
        0xBFBAFECA,
    ):
        return MachOImage(payload)
    raise ObjectFormatError("artifact is not an ELF, PE, or Mach-O image")
