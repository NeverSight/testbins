# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""The Ada/D probes keep the exception shapes the manifest floors depend on."""

from __future__ import annotations

import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = SCRIPTS_ROOT.parent
SOURCE_ROOT = REPOSITORY_ROOT / "sources" / "ada-d-eh"

ADA = SOURCE_ROOT / "ada_eh_probe.adb"
D = SOURCE_ROOT / "d_eh_probe.d"


class SourceInventoryTests(unittest.TestCase):
    def test_the_corpus_is_two_probes_and_no_build_system(self) -> None:
        names = sorted(path.name for path in SOURCE_ROOT.iterdir())

        self.assertEqual(names, ["ada_eh_probe.adb", "d_eh_probe.d"])
        self.assertTrue(ADA.is_file())
        self.assertTrue(D.is_file())

    def test_sources_carry_no_local_path_or_account_name(self) -> None:
        for path in (ADA, D):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("/Users/", text)
                self.assertNotIn("/home/", text)
                self.assertNotIn("C:\\", text)


class AdaProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = ADA.read_text(encoding="utf-8")

    def test_prints_the_shared_pass_marker_on_the_success_path(self) -> None:
        self.assertIn('Put_Line ("ada-d-eh probe passed")', self.text)
        self.assertIn("Result + Integer (Cleanup_Count) = 44", self.text)

    def test_raises_and_catches_three_named_exceptions(self) -> None:
        for name in ("Constraint_Error", "Decode_Error", "Secondary_Error"):
            with self.subTest(name=name):
                self.assertIn(f"raise {name}", self.text)
                self.assertIn(f"when {name} =>", self.text)
        self.assertIn("when others =>", self.text)

    def test_keeps_the_string_identities_the_verifier_searches_for(self) -> None:
        for message in ('"constraint"', '"decode"', '"secondary"'):
            self.assertIn(message, self.text)


class DProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = D.read_text(encoding="utf-8")

    def test_prints_the_shared_pass_marker_on_the_success_path(self) -> None:
        self.assertIn('puts("ada-d-eh probe passed")', self.text)
        self.assertIn("result + cleanupCount != 44", self.text)

    def test_throws_and_catches_three_class_exceptions_plus_cleanup(self) -> None:
        for name in ("ConstraintDecodeError", "DecodeError", "SecondaryError"):
            with self.subTest(name=name):
                self.assertIn(f"class {name} : Exception", self.text)
                self.assertIn(f"throw new {name}", self.text)
                self.assertIn(f"catch ({name})", self.text)
        self.assertIn("catch (Throwable)", self.text)
        self.assertIn("scope (exit)", self.text)

    def test_keeps_the_string_identities_the_verifier_searches_for(self) -> None:
        for message in ('"constraint"', '"decode"', '"secondary"'):
            self.assertIn(message, self.text)


if __name__ == "__main__":
    unittest.main()
