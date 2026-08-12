# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import json
import sys
import unittest
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import json_schema_check  # noqa: E402

SCHEMA_ROOT = SCRIPTS_ROOT.parent / "schema"


class SchemaKeywordCoverageTests(unittest.TestCase):
    """A partial validator that ignores a keyword silently is worse than none."""

    def test_rejects_a_keyword_it_cannot_enforce(self) -> None:
        with self.assertRaisesRegex(json_schema_check.SchemaError, "unsupported"):
            json_schema_check.check_schema({"multipleOf": 3})

    def test_rejects_an_unresolvable_reference(self) -> None:
        with self.assertRaisesRegex(json_schema_check.SchemaError, "resolve"):
            json_schema_check.validate({}, {"$ref": "#/$defs/missing"})

    def test_rejects_a_non_local_reference(self) -> None:
        with self.assertRaisesRegex(json_schema_check.SchemaError, "local"):
            json_schema_check.check_schema({"$ref": "https://example.invalid/s.json"})

    def test_accepts_every_shipped_schema(self) -> None:
        schemas = sorted(SCHEMA_ROOT.glob("*.schema.json"))
        self.assertTrue(schemas, "no manifest schemas were found")
        for path in schemas:
            with self.subTest(schema=path.name):
                json_schema_check.check_schema(
                    json.loads(path.read_text(encoding="utf-8"))
                )


class ValidationTests(unittest.TestCase):
    def test_distinguishes_booleans_from_integers(self) -> None:
        json_schema_check.validate(1, {"type": "integer"})
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate(True, {"type": "integer"})
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate(1, {"const": True})

    def test_enforces_additional_properties_false(self) -> None:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"kept": {"type": "string"}},
        }

        json_schema_check.validate({"kept": "yes"}, schema)
        with self.assertRaisesRegex(
            json_schema_check.ValidationError, "'extra' is not allowed"
        ):
            json_schema_check.validate({"kept": "yes", "extra": 1}, schema)

    def test_enforces_required_properties(self) -> None:
        with self.assertRaisesRegex(json_schema_check.ValidationError, "missing"):
            json_schema_check.validate({}, {"required": ["path"]})

    def test_enforces_contains_over_arrays(self) -> None:
        schema = {"type": "array", "contains": {"const": ".eh_frame"}}

        json_schema_check.validate([".text", ".eh_frame"], schema)
        with self.assertRaisesRegex(json_schema_check.ValidationError, "contains"):
            json_schema_check.validate([".text"], schema)

    def test_enforces_unique_items_on_unhashable_values(self) -> None:
        schema = {"type": "array", "uniqueItems": True}

        json_schema_check.validate([{"a": 1}, {"a": 2}], schema)
        with self.assertRaisesRegex(json_schema_check.ValidationError, "unique"):
            json_schema_check.validate([{"a": 1}, {"a": 1}], schema)

    def test_applies_if_then_else_branches(self) -> None:
        schema = {
            "if": {"required": ["kind"], "properties": {"kind": {"const": "abort"}}},
            "then": {"properties": {"pads": {"const": 0}}},
            "else": {"properties": {"pads": {"minimum": 1}}},
        }

        json_schema_check.validate({"kind": "abort", "pads": 0}, schema)
        json_schema_check.validate({"kind": "unwind", "pads": 4}, schema)
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate({"kind": "abort", "pads": 4}, schema)
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate({"kind": "unwind", "pads": 0}, schema)

    def test_resolves_local_references_including_nested_ones(self) -> None:
        schema = {
            "type": "array",
            "items": {"$ref": "#/$defs/name"},
            "$defs": {"name": {"type": "string", "minLength": 1}},
        }

        json_schema_check.validate(["rust_eh_personality"], schema)
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate([""], schema)

    def test_reports_the_path_of_the_failing_value(self) -> None:
        schema = {
            "properties": {
                "artifacts": {"items": {"properties": {"size": {"minimum": 1}}}}
            }
        }

        with self.assertRaisesRegex(
            json_schema_check.ValidationError, r"/artifacts/1/size"
        ):
            json_schema_check.validate(
                {"artifacts": [{"size": 4}, {"size": 0}]}, schema
            )

    def test_enforces_patterns_and_enums(self) -> None:
        json_schema_check.validate("o2", {"enum": ["o0", "o2"]})
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate("o1", {"enum": ["o0", "o2"]})
        json_schema_check.validate("0" * 64, {"pattern": "^[0-9a-f]{64}$"})
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate("nope", {"pattern": "^[0-9a-f]{64}$"})

    def test_not_and_all_of_compose(self) -> None:
        schema = {
            "allOf": [{"type": "string"}, {"not": {"const": "forbidden"}}],
        }

        json_schema_check.validate("allowed", schema)
        with self.assertRaises(json_schema_check.ValidationError):
            json_schema_check.validate("forbidden", schema)


if __name__ == "__main__":
    unittest.main()
