# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""The Go probe keeps the properties the manifest contract is written against.

`sources/go-eh/cmd/eh_probe` is the only thing in this product line that decides
what metadata ends up in the corpus.  If a helper loses its `//go:noinline`, or
the nine-defer function drops to eight, the artifacts still build and still
verify -- they just stop containing the thing they were added for.  These tests
watch the properties the manifest floors depend on.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
MODULE_ROOT = REPOSITORY_ROOT / "sources/go-eh"
PROBE = MODULE_ROOT / "cmd/eh_probe/main.go"

#: `cmd/compile/internal/walk.maxOpenDefers`.  A function with more defers than
#: this cannot open-code them, because the frame records active defers in a
#: single byte.
MAX_OPEN_DEFERS = 8


def _source() -> str:
    return PROBE.read_text(encoding="utf-8")


def _function_bodies(text: str) -> dict[str, str]:
    """Split the file into top-level function bodies by brace depth."""

    bodies: dict[str, str] = {}
    for match in re.finditer(r"^func ([A-Za-z_][A-Za-z0-9_]*)\(", text, re.MULTILINE):
        name = match.group(1)
        # `interface{}` and `struct{}` appear in signatures, so the body's
        # opening brace is the first one that is not immediately closed.
        cursor = match.start()
        while True:
            cursor = text.index("{", cursor)
            if text[cursor + 1] != "}":
                break
            cursor += 2
        depth = 0
        for index in range(cursor, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    bodies[name] = text[cursor : index + 1]
                    break
    return bodies


class GoModuleTests(unittest.TestCase):
    def test_module_is_self_contained(self) -> None:
        go_mod = (MODULE_ROOT / "go.mod").read_text(encoding="utf-8")
        self.assertIn("module neversight.dev/goeh", go_mod)
        self.assertNotIn("require", go_mod)
        self.assertFalse((MODULE_ROOT / "go.sum").exists())
        directive = re.search(r"^go ([0-9]+\.[0-9]+)$", go_mod, re.MULTILINE)
        self.assertIsNotNone(directive)
        self.assertEqual(directive.group(1), "1.15")

    def test_only_the_standard_library_is_imported(self) -> None:
        for path in MODULE_ROOT.rglob("*.go"):
            text = path.read_text(encoding="utf-8")
            block = re.search(r"^import \(\n(.*?)^\)", text, re.MULTILINE | re.DOTALL)
            imports = []
            if block:
                imports = re.findall(r'"([^"]+)"', block.group(1))
            imports += re.findall(r'^import "([^"]+)"', text, re.MULTILINE)
            for name in imports:
                with self.subTest(path=path.name, imported=name):
                    self.assertNotIn(".", name.split("/")[0])

    def test_no_build_constraints_a_legacy_toolchain_would_silently_ignore(
        self,
    ) -> None:
        """`//go:build` arrived in Go 1.17 and is a comment to anything older.

        A constraint the oldest pinned toolchain does not understand would not
        fail the build, it would change which files that toolchain compiles.
        """

        for path in MODULE_ROOT.rglob("*.go"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIsNone(re.search(r"^//go:build", text, re.MULTILINE))
                self.assertIsNone(re.search(r"^// \+build", text, re.MULTILINE))

    def test_sources_carry_no_local_path_or_account_name(self) -> None:
        for path in MODULE_ROOT.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=path.name):
                self.assertNotIn("/Users/", text)
                self.assertNotIn("/home/", text)
                self.assertNotIn("C:\\", text)


class GoProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _source()
        cls.bodies = _function_bodies(cls.text)

    def test_every_helper_resists_inlining(self) -> None:
        """An inlined helper stops being a frame, and a frame is the unit here."""

        exempt = {"main"}
        declarations = re.findall(
            r"(?:^//go:noinline\n)?^func ([A-Za-z_][A-Za-z0-9_]*)\(",
            self.text,
            re.MULTILINE,
        )
        annotated = set(
            re.findall(r"^//go:noinline\nfunc ([A-Za-z_][A-Za-z0-9_]*)\(", self.text, re.MULTILINE)
        )
        for name in declarations:
            if name in exempt:
                continue
            with self.subTest(function=name):
                self.assertIn(name, annotated)

    def test_a_recover_sits_in_the_frame_that_deferred_it(self) -> None:
        body = self.bodies["recoverInPlace"]
        self.assertIn("defer func()", body)
        self.assertIn("recover()", body)
        self.assertIn("panic(", body)

    def test_a_deferred_closure_rewrites_a_named_result(self) -> None:
        self.assertRegex(self.text, r"func namedResultRewrite\(seed int\) \(result int\)")
        body = self.bodies["namedResultRewrite"]
        self.assertIn("result *= 3", body)
        self.assertNotIn("panic(", body)

    def test_open_coded_defers_stay_under_the_compiler_threshold(self) -> None:
        body = self.bodies["openCodedDefers"]
        count = len(re.findall(r"\bdefer\b", body))
        self.assertGreater(count, 1)
        self.assertLessEqual(count, MAX_OPEN_DEFERS)
        self.assertNotIn("for ", body)

    def test_one_function_defers_past_the_threshold_and_one_defers_in_a_loop(
        self,
    ) -> None:
        """The two ways walkStmt disqualifies open coding, one function each."""

        over = self.bodies["heapDefersOverThreshold"]
        self.assertGreater(len(re.findall(r"\bdefer\b", over)), MAX_OPEN_DEFERS)
        self.assertNotIn("for ", over)

        loop = self.bodies["heapDefersInLoop"]
        self.assertIn("for i := 0;", loop)
        self.assertIn("defer func(", loop)

    def test_a_panic_crosses_several_frames_before_it_is_recovered(self) -> None:
        self.assertIn("panic(", self.bodies["deepest"])
        self.assertIn("deepest(boom)", self.bodies["middle"])
        self.assertIn("middle(boom)", self.bodies["outer"])
        caught = self.bodies["catchDeep"]
        self.assertIn("recover()", caught)
        self.assertIn("outer(boom)", caught)
        self.assertNotIn("recover()", self.bodies["middle"])

    def test_a_second_panic_is_raised_while_the_first_unwinds(self) -> None:
        body = self.bodies["panicDuringDefer"]
        self.assertEqual(len(re.findall(r"\bpanic\(", body)), 2)
        self.assertIn("recover()", body)

    def test_every_runtime_generated_panic_has_its_own_frame(self) -> None:
        expected = {
            "nilMapWrite": "m[key] = 1",
            "nilPointerDeref": "consume(*p)",
            "sliceBounds": "values[index]",
            "sliceExprBounds": "values[:high]",
            "divideByZero": "7 / divisor",
            "typeAssertion": "value.(int)",
        }
        for name, fragment in expected.items():
            with self.subTest(function=name):
                body = self.bodies[name]
                self.assertIn(fragment, body)
                self.assertIn("recover()", body)

    def test_a_goroutine_recovers_its_own_panic(self) -> None:
        body = self.bodies["goroutinePanic"]
        self.assertIn("go func()", body)
        self.assertIn("panic(", body)
        self.assertIn("recover()", body)
        self.assertIn("wait.Wait()", body)

    def test_goexit_runs_a_deferred_call_with_no_panic_active(self) -> None:
        body = self.bodies["goexitWithDefer"]
        self.assertIn("runtime.Goexit()", body)
        self.assertIn("defer func()", body)
        self.assertNotIn("panic(", body)

    def test_results_reach_a_package_level_sink(self) -> None:
        self.assertIn("var Sink int64", self.text)
        self.assertIn("var Flags uint64", self.text)
        self.assertIn("Sink += int64(v)", self.text)

    def test_the_probe_asserts_its_own_behaviour_before_exiting(self) -> None:
        """Running the artifact is the only proof the metadata drove an unwind."""

        run = self.bodies["run"]
        flags = {int(value) for value in re.findall(r"\bflag\((\d+),", run)}
        self.assertEqual(flags, set(range(len(flags))))
        mask = (1 << len(flags)) - 1
        self.assertIn(f"Flags != {hex(mask).upper().replace('0X', '0x')}", self.text)
        self.assertIn("os.Exit(1)", self.bodies["main"])

    def test_the_probe_avoids_the_packages_that_would_double_its_size(self) -> None:
        """`fmt` alone costs roughly 600 KiB in every one of these artifacts."""

        self.assertNotIn('"fmt"', self.text)
        self.assertNotIn('"strconv"', self.text)
        self.assertIn("println(", self.text)


if __name__ == "__main__":
    unittest.main()
