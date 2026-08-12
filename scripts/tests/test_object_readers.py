# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import struct
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import synthetic_objects  # noqa: E402
from object_readers import ObjectFormatError, load_object  # noqa: E402


class ELFReaderTests(unittest.TestCase):
    def test_reads_sections_symbols_and_frames(self) -> None:
        payload = synthetic_objects.build_elf(
            architecture="aarch64",
            symbols=("rust_eh_personality", "rust_eh_drop_across_panic"),
        )

        image = load_object(payload)

        self.assertEqual(image.object_format, "elf")
        self.assertEqual(image.architecture, "aarch64")
        self.assertLessEqual(
            {".text", ".eh_frame", ".gcc_except_table", ".symtab"},
            set(image.sections),
        )
        self.assertTrue(image.has_symbol_table)
        self.assertIn("rust_eh_personality", image.symbols)
        self.assertIn("rust_eh_drop_across_panic", image.symbols)
        self.assertEqual(image.verify_unwind_tables(), 2)

    def test_rejects_frame_record_that_leaves_its_section(self) -> None:
        payload = synthetic_objects.build_elf(
            eh_frame=struct.pack("<I", 0xFFFF) + b"\x00" * 12
        )

        image = load_object(payload)

        with self.assertRaisesRegex(ObjectFormatError, "leaves its section"):
            image.verify_unwind_tables()

    def test_rejects_unsupported_cie_version(self) -> None:
        cie_body = struct.pack("<I", 0) + b"\x09" + b"\x00" * 7
        payload = synthetic_objects.build_elf(
            eh_frame=struct.pack("<I", len(cie_body)) + cie_body + struct.pack("<I", 0)
        )

        image = load_object(payload)

        with self.assertRaisesRegex(ObjectFormatError, "CIE version"):
            image.verify_unwind_tables()

    def test_rejects_missing_eh_frame(self) -> None:
        payload = synthetic_objects.build_elf(sections=(".text",))

        image = load_object(payload)

        self.assertNotIn(".eh_frame", image.sections)
        with self.assertRaisesRegex(ObjectFormatError, "absent"):
            image.verify_unwind_tables()

    def test_rejects_unsupported_machine(self) -> None:
        payload = bytearray(synthetic_objects.build_elf())
        struct.pack_into("<H", payload, 18, 0x1234)

        with self.assertRaisesRegex(ObjectFormatError, "machine"):
            load_object(bytes(payload))


class ARMEHABIReaderTests(unittest.TestCase):
    """32-bit ARM replaces the DWARF chain with an index section."""

    def _arm_image(self, entry_count: int = 12, **overrides: bytes):
        section_overrides = {
            ".ARM.exidx": synthetic_objects.arm_exidx_section(entry_count)
        }
        section_overrides.update(overrides)
        return load_object(
            synthetic_objects.build_elf(
                architecture="arm",
                elf_class=32,
                sections=(".text", ".ARM.exidx", ".ARM.extab"),
                symbols=("__gxx_personality_v0", "cxx_eh_probe_quiet_sum"),
                section_overrides=section_overrides,
            )
        )

    def test_reads_a_thirty_two_bit_image(self) -> None:
        image = self._arm_image()

        self.assertEqual(image.object_format, "elf")
        self.assertEqual(image.architecture, "arm")
        self.assertLessEqual({".text", ".ARM.exidx", ".ARM.extab"}, set(image.sections))
        self.assertTrue(image.has_symbol_table)
        self.assertIn("__gxx_personality_v0", image.symbols)

    def test_counts_index_entries(self) -> None:
        self.assertEqual(self._arm_image(entry_count=12).arm_exidx_entries(), 12)
        self.assertEqual(self._arm_image(entry_count=1).arm_exidx_entries(), 1)

    def test_rejects_an_index_that_is_not_whole_entries(self) -> None:
        image = self._arm_image(**{".ARM.exidx": b"\x00" * 12})

        with self.assertRaisesRegex(ObjectFormatError, "whole number of index"):
            image.arm_exidx_entries()

    def test_reports_no_index_when_the_section_is_absent(self) -> None:
        for payload in (
            synthetic_objects.build_elf(),
            synthetic_objects.build_macho(),
            synthetic_objects.build_pe(),
        ):
            image = load_object(payload)
            with self.subTest(object_format=image.object_format):
                self.assertEqual(image.arm_exidx_entries(), 0)


class FrameRecordCountTests(unittest.TestCase):
    def test_separates_common_information_entries_from_descriptions(self) -> None:
        image = load_object(synthetic_objects.build_elf())

        self.assertEqual(image.frame_record_counts(), (1, 1))

    def test_notices_a_section_that_describes_no_function(self) -> None:
        image = load_object(
            synthetic_objects.build_elf(
                eh_frame=synthetic_objects.dwarf_frame_section_without_descriptions()
            )
        )

        cies, descriptions = image.frame_record_counts()
        self.assertEqual(cies, 1)
        self.assertEqual(descriptions, 0)
        # The chain is still well formed, which is exactly why presence and
        # coverage have to be asked separately.
        self.assertEqual(image.verify_unwind_tables(), 1)

    def test_reports_an_absent_frame_section(self) -> None:
        image = load_object(synthetic_objects.build_elf(sections=(".text",)))

        with self.assertRaisesRegex(ObjectFormatError, "absent"):
            image.frame_record_counts()


class MachOReaderTests(unittest.TestCase):
    def test_reads_sections_symbols_and_compact_unwind(self) -> None:
        payload = synthetic_objects.build_macho(
            architecture="x86_64",
            symbols=("rust_eh_personality", "rust_eh_dylib_drop_log"),
        )

        image = load_object(payload)

        self.assertEqual(image.object_format, "macho")
        self.assertEqual(image.architecture, "x86_64")
        self.assertLessEqual(
            {"__text", "__eh_frame", "__gcc_except_tab", "__unwind_info"},
            set(image.sections),
        )
        self.assertIn("__TEXT,__text", image.sections)
        self.assertGreaterEqual(image.verify_unwind_tables(), 2)

    def test_strips_the_leading_underscore_from_symbol_names(self) -> None:
        payload = synthetic_objects.build_macho(symbols=("rust_eh_c_leaf_nounwind",))

        image = load_object(payload)

        self.assertIn("rust_eh_c_leaf_nounwind", image.symbols)
        self.assertIn("_rust_eh_c_leaf_nounwind", image.symbols)

    def test_rejects_unsupported_compact_unwind_version(self) -> None:
        payload = synthetic_objects.build_macho(
            unwind_info=synthetic_objects.compact_unwind_section(version=2)
        )

        image = load_object(payload)

        with self.assertRaisesRegex(ObjectFormatError, "__unwind_info version"):
            image.verify_unwind_tables()

    def test_rejects_compact_unwind_without_a_first_level_index(self) -> None:
        payload = synthetic_objects.build_macho(
            unwind_info=synthetic_objects.compact_unwind_section(index_count=0)
        )

        image = load_object(payload)

        with self.assertRaisesRegex(ObjectFormatError, "first-level index"):
            image.verify_unwind_tables()

    def test_rejects_universal_binaries(self) -> None:
        payload = struct.pack(">I", 0xCAFEBABE) + b"\x00" * 64

        with self.assertRaisesRegex(ObjectFormatError, "universal"):
            load_object(payload)


class PEReaderTests(unittest.TestCase):
    def test_reads_sections_and_runtime_functions(self) -> None:
        payload = synthetic_objects.build_pe()

        image = load_object(payload)

        self.assertEqual(image.object_format, "pe")
        self.assertEqual(image.architecture, "x86_64")
        self.assertLessEqual({".text", ".pdata", ".rdata"}, set(image.sections))
        self.assertEqual(image.verify_unwind_tables(), 1)

    def test_reads_export_names_from_a_shared_library(self) -> None:
        payload = synthetic_objects.build_pe(
            exports=("rust_eh_dylib_c_leaf_nounwind", "rust_eh_dylib_drop_log")
        )

        image = load_object(payload)

        self.assertTrue(image.has_symbol_table)
        self.assertIn("rust_eh_dylib_c_leaf_nounwind", image.symbols)
        self.assertIn("rust_eh_dylib_drop_log", image.symbols)

    def test_reports_no_symbol_names_for_an_executable(self) -> None:
        image = load_object(synthetic_objects.build_pe())

        self.assertFalse(image.has_symbol_table)
        self.assertEqual(image.symbols, set())

    def test_reads_the_coff_symbol_table_a_mingw_link_keeps(self) -> None:
        payload = synthetic_objects.build_pe(
            sections=(".text", ".pdata", ".xdata"),
            symbols=("__gxx_personality_seh0", "main", "__cxa_throw"),
        )

        image = load_object(payload)

        self.assertTrue(image.has_symbol_table)
        self.assertLessEqual({".pdata", ".xdata"}, set(image.sections))
        # Short names live in the record; longer ones in the string table.
        self.assertLessEqual(
            {"__gxx_personality_seh0", "main", "__cxa_throw"}, image.symbols
        )
        self.assertEqual(image.verify_unwind_tables(), 1)

    def test_rejects_runtime_function_outside_executable_code(self) -> None:
        payload = synthetic_objects.build_pe(
            runtime_functions=((0x3000, 0x3010, 0x3000),)
        )

        image = load_object(payload)

        with self.assertRaisesRegex(ObjectFormatError, "not executable"):
            image.verify_unwind_tables()

    def test_rejects_inverted_runtime_function_range(self) -> None:
        payload = synthetic_objects.build_pe(
            runtime_functions=((0x1010, 0x1000, 0x3000),)
        )

        image = load_object(payload)

        with self.assertRaisesRegex(ObjectFormatError, "code range is invalid"):
            image.verify_unwind_tables()


class FormatDispatchTests(unittest.TestCase):
    def test_dispatches_on_the_magic_number(self) -> None:
        cases = (
            (synthetic_objects.build_elf(), "elf"),
            (synthetic_objects.build_macho(), "macho"),
            (synthetic_objects.build_pe(), "pe"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(load_object(payload).object_format, expected)

    def test_rejects_an_unrecognized_file(self) -> None:
        with self.assertRaisesRegex(ObjectFormatError, "not an ELF, PE, or Mach-O"):
            load_object(b"not an object file at all")

    def test_finds_raw_strings_in_the_image(self) -> None:
        image = load_object(
            synthetic_objects.build_pe(trailing_bytes=b"rust_panic\x00")
        )

        self.assertTrue(image.contains_bytes(b"rust_panic"))
        self.assertFalse(image.contains_bytes(b"cxx_panic"))


if __name__ == "__main__":
    unittest.main()
