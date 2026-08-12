# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import re
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import rust_matrix  # noqa: E402

REPOSITORY_ROOT = SCRIPTS_ROOT.parent
SOURCE_ROOT = REPOSITORY_ROOT / "sources/rust-eh"

_EXPORT_RE = re.compile(r"^\s*pub\s+(?:extern\s+\"[^\"]+\"\s+)?fn\s+([A-Za-z0-9_]+)")
_USE_RE = re.compile(r"^\s*use\s+([A-Za-z0-9_]+)")
_STANDARD_ROOTS = frozenset({"std", "core", "alloc", "crate", "self", "super"})


def _exported_probes(text: str) -> dict[str, set[str]]:
    """Return each `#[unsafe(no_mangle)]` function and the attributes above it."""

    probes: dict[str, set[str]] = {}
    attributes: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#["):
            attributes.add(stripped)
            continue
        match = _EXPORT_RE.match(line)
        if match:
            if "#[unsafe(no_mangle)]" in attributes:
                probes[match.group(1)] = set(attributes)
            attributes = set()
            continue
        if stripped and not stripped.startswith("//"):
            attributes = set()
    return probes


class ProbeInventoryTests(unittest.TestCase):
    def test_every_crate_source_exists_where_the_matrix_says(self) -> None:
        for crate_name in rust_matrix.crate_names():
            with self.subTest(crate=crate_name):
                path = REPOSITORY_ROOT / rust_matrix.crate_source(crate_name)
                self.assertTrue(path.is_file(), path)

    def test_declared_probe_symbols_match_the_sources(self) -> None:
        for crate_name in rust_matrix.crate_names():
            with self.subTest(crate=crate_name):
                path = REPOSITORY_ROOT / rust_matrix.crate_source(crate_name)
                exported = _exported_probes(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    sorted(exported), sorted(rust_matrix.probe_symbols(crate_name))
                )

    def test_every_probe_survives_optimization(self) -> None:
        for crate_name in rust_matrix.crate_names():
            path = REPOSITORY_ROOT / rust_matrix.crate_source(crate_name)
            for name, attributes in _exported_probes(
                path.read_text(encoding="utf-8")
            ).items():
                with self.subTest(crate=crate_name, probe=name):
                    self.assertIn("#[inline(never)]", attributes)

    def test_the_c_abi_boundaries_cover_both_unwind_conventions(self) -> None:
        for crate_name in rust_matrix.crate_names():
            with self.subTest(crate=crate_name):
                text = (
                    REPOSITORY_ROOT / rust_matrix.crate_source(crate_name)
                ).read_text(encoding="utf-8")
                self.assertIn('pub extern "C-unwind" fn', text)
                self.assertIn('pub extern "C" fn', text)

    def test_the_executable_probe_exercises_every_panic_family(self) -> None:
        text = (REPOSITORY_ROOT / rust_matrix.crate_source("rust_eh_probe")).read_text(
            encoding="utf-8"
        )

        self.assertIn("catch_unwind", text)
        self.assertIn("panic!", text)
        self.assertIn(".unwrap()", text)
        self.assertIn("impl Drop for", text)
        self.assertIn("black_box", text)

    def test_the_executable_probe_never_panics_under_abort(self) -> None:
        text = (REPOSITORY_ROOT / rust_matrix.crate_source("rust_eh_probe")).read_text(
            encoding="utf-8"
        )

        self.assertIn('#[cfg(panic = "unwind")]', text)
        self.assertIn('#[cfg(not(panic = "unwind"))]', text)

    def test_the_probes_have_no_crates_io_dependencies(self) -> None:
        for path in sorted(SOURCE_ROOT.glob("*.rs")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(source=path.name):
                self.assertNotIn("extern crate", text)
                for line in text.splitlines():
                    match = _USE_RE.match(line)
                    if match:
                        self.assertIn(match.group(1), _STANDARD_ROOTS, line)

    def test_no_cargo_manifest_reintroduces_a_registry(self) -> None:
        self.assertEqual(list(SOURCE_ROOT.rglob("Cargo.toml")), [])


class ToolchainFileTests(unittest.TestCase):
    def test_the_toolchain_is_pinned_to_one_release(self) -> None:
        text = (REPOSITORY_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")

        match = re.search(r'^\s*channel\s*=\s*"([^"]+)"', text, re.MULTILINE)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertRegex(match.group(1), r"^[0-9]+\.[0-9]+\.[0-9]+$")

        settings = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        for moving_channel in ("stable", "beta", "nightly"):
            self.assertNotIn(moving_channel, settings)


if __name__ == "__main__":
    unittest.main()
