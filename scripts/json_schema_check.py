#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""A small JSON Schema 2020-12 validator for the corpus manifests.

The corpus producer must not depend on anything CI has to install, so this
implements the subset of the specification the manifest schemas actually use
instead of pulling in `jsonschema`.

The dangerous failure mode for a partial validator is silence: an unimplemented
keyword that is skipped turns a strict schema into a permissive one without
anybody noticing. `check_schema` therefore rejects any keyword this module does
not implement, so a schema can only ever be validated in full or not at all.
"""

from __future__ import annotations

import json
import re
from typing import Any


class SchemaError(ValueError):
    """Raised when a schema uses something this validator does not implement."""


class ValidationError(ValueError):
    """Raised when an instance does not satisfy its schema."""


# Keywords that carry documentation or identity and constrain nothing.
_ANNOTATIONS = frozenset(
    {"$schema", "$id", "$comment", "title", "description", "default", "examples"}
)

_APPLICATOR_SCHEMA = frozenset(
    {"items", "contains", "not", "if", "then", "else", "propertyNames"}
)
_APPLICATOR_SCHEMA_LIST = frozenset({"allOf", "anyOf", "oneOf"})
_APPLICATOR_SCHEMA_MAP = frozenset({"properties", "$defs"})
_ASSERTIONS = frozenset(
    {
        "type",
        "const",
        "enum",
        "required",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "minProperties",
        "maxProperties",
        "$ref",
    }
)
_SUPPORTED = (
    _ANNOTATIONS
    | _APPLICATOR_SCHEMA
    | _APPLICATOR_SCHEMA_LIST
    | _APPLICATOR_SCHEMA_MAP
    | _ASSERTIONS
    | {"additionalProperties"}
)

_TYPE_NAMES = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)

_MAX_REF_DEPTH = 64


def check_schema(schema: Any, path: str = "#") -> None:
    """Reject a schema this validator cannot enforce in full."""

    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"{path}: a schema must be an object or a boolean")
    for keyword, value in schema.items():
        location = f"{path}/{keyword}"
        if keyword not in _SUPPORTED:
            raise SchemaError(f"{location}: unsupported schema keyword {keyword!r}")
        if keyword in _ANNOTATIONS:
            continue
        if keyword in _APPLICATOR_SCHEMA:
            check_schema(value, location)
        elif keyword == "additionalProperties":
            check_schema(value, location)
        elif keyword in _APPLICATOR_SCHEMA_LIST:
            if not isinstance(value, list) or not value:
                raise SchemaError(f"{location}: expected a non-empty list of schemas")
            for index, entry in enumerate(value):
                check_schema(entry, f"{location}/{index}")
        elif keyword in _APPLICATOR_SCHEMA_MAP:
            if not isinstance(value, dict):
                raise SchemaError(f"{location}: expected an object of schemas")
            for name, entry in value.items():
                check_schema(entry, f"{location}/{name}")
        else:
            _check_assertion(keyword, value, location)


def _check_assertion(keyword: str, value: Any, location: str) -> None:
    if keyword == "type":
        names = value if isinstance(value, list) else [value]
        for name in names:
            if name not in _TYPE_NAMES:
                raise SchemaError(f"{location}: unknown type {name!r}")
    elif keyword == "enum":
        if not isinstance(value, list) or not value:
            raise SchemaError(f"{location}: expected a non-empty list")
    elif keyword == "required":
        if not isinstance(value, list) or any(
            not isinstance(entry, str) for entry in value
        ):
            raise SchemaError(f"{location}: expected a list of property names")
    elif keyword == "pattern":
        if not isinstance(value, str):
            raise SchemaError(f"{location}: expected a regular expression")
        try:
            re.compile(value)
        except re.error as error:
            raise SchemaError(f"{location}: invalid pattern: {error}") from error
    elif keyword == "$ref":
        if not isinstance(value, str) or not value.startswith("#/"):
            raise SchemaError(f"{location}: only local '#/' references are supported")
    elif keyword == "uniqueItems":
        if not isinstance(value, bool):
            raise SchemaError(f"{location}: expected a boolean")
    elif keyword in (
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minProperties",
        "maxProperties",
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise SchemaError(f"{location}: expected a non-negative integer")
    elif keyword in ("minimum", "maximum"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SchemaError(f"{location}: expected a number")


def validate(instance: Any, schema: Any) -> None:
    """Validate \\p instance against \\p schema, raising on the first failure."""

    check_schema(schema)
    _validate(instance, schema, schema, "", 0)


def _validate(instance: Any, schema: Any, root: Any, path: str, depth: int) -> None:
    if depth > _MAX_REF_DEPTH:
        raise SchemaError("schema reference chain is too deep")
    if schema is True or schema == {}:
        return
    if schema is False:
        raise ValidationError(f"{_display(path)}: no value is allowed here")

    if "$ref" in schema:
        _validate(instance, _resolve(root, schema["$ref"]), root, path, depth + 1)

    for keyword, value in schema.items():
        if keyword in _ANNOTATIONS or keyword in ("$ref", "$defs", "then", "else"):
            continue
        _apply(keyword, value, instance, schema, root, path, depth)


def _apply(
    keyword: str,
    value: Any,
    instance: Any,
    schema: Any,
    root: Any,
    path: str,
    depth: int,
) -> None:
    if keyword == "type":
        names = value if isinstance(value, list) else [value]
        if not any(_matches_type(instance, name) for name in names):
            raise ValidationError(
                f"{_display(path)}: expected {'/'.join(names)}, found {_kind(instance)}"
            )
    elif keyword == "const":
        if not _json_equal(instance, value):
            raise ValidationError(
                f"{_display(path)}: expected {value!r}, found {instance!r}"
            )
    elif keyword == "enum":
        if not any(_json_equal(instance, entry) for entry in value):
            raise ValidationError(
                f"{_display(path)}: {instance!r} is not one of {value!r}"
            )
    elif keyword == "required":
        if isinstance(instance, dict):
            missing = [name for name in value if name not in instance]
            if missing:
                raise ValidationError(
                    f"{_display(path)}: missing required propert(y/ies) "
                    f"{', '.join(sorted(missing))}"
                )
    elif keyword == "properties":
        if isinstance(instance, dict):
            for name, subschema in value.items():
                if name in instance:
                    _validate(instance[name], subschema, root, f"{path}/{name}", depth)
    elif keyword == "additionalProperties":
        if isinstance(instance, dict):
            declared = set(schema.get("properties", {}))
            for name in instance:
                if name in declared:
                    continue
                if value is False:
                    raise ValidationError(
                        f"{_display(path)}: property {name!r} is not allowed"
                    )
                _validate(instance[name], value, root, f"{path}/{name}", depth)
    elif keyword == "items":
        if isinstance(instance, list):
            for index, entry in enumerate(instance):
                _validate(entry, value, root, f"{path}/{index}", depth)
    elif keyword == "contains":
        if isinstance(instance, list):
            for entry in instance:
                try:
                    _validate(entry, value, root, path, depth)
                except ValidationError:
                    continue
                break
            else:
                raise ValidationError(
                    f"{_display(path)}: no element satisfies the 'contains' schema"
                )
    elif keyword == "minItems":
        if isinstance(instance, list) and len(instance) < value:
            raise ValidationError(
                f"{_display(path)}: expected at least {value} item(s)"
            )
    elif keyword == "maxItems":
        if isinstance(instance, list) and len(instance) > value:
            raise ValidationError(f"{_display(path)}: expected at most {value} item(s)")
    elif keyword == "uniqueItems":
        if value and isinstance(instance, list):
            seen = [_canonical(entry) for entry in instance]
            if len(set(seen)) != len(seen):
                raise ValidationError(f"{_display(path)}: items must be unique")
    elif keyword == "minLength":
        if isinstance(instance, str) and len(instance) < value:
            raise ValidationError(
                f"{_display(path)}: expected at least {value} character(s)"
            )
    elif keyword == "maxLength":
        if isinstance(instance, str) and len(instance) > value:
            raise ValidationError(
                f"{_display(path)}: expected at most {value} character(s)"
            )
    elif keyword == "pattern":
        if isinstance(instance, str) and re.search(value, instance) is None:
            raise ValidationError(
                f"{_display(path)}: {instance!r} does not match /{value}/"
            )
    elif keyword == "minimum":
        if _is_number(instance) and instance < value:
            raise ValidationError(f"{_display(path)}: must be at least {value}")
    elif keyword == "maximum":
        if _is_number(instance) and instance > value:
            raise ValidationError(f"{_display(path)}: must be at most {value}")
    elif keyword == "minProperties":
        if isinstance(instance, dict) and len(instance) < value:
            raise ValidationError(
                f"{_display(path)}: expected at least {value} propert(y/ies)"
            )
    elif keyword == "maxProperties":
        if isinstance(instance, dict) and len(instance) > value:
            raise ValidationError(
                f"{_display(path)}: expected at most {value} propert(y/ies)"
            )
    elif keyword == "propertyNames":
        if isinstance(instance, dict):
            for name in instance:
                _validate(name, value, root, f"{path}/{name}", depth)
    elif keyword == "allOf":
        for subschema in value:
            _validate(instance, subschema, root, path, depth)
    elif keyword == "anyOf":
        for subschema in value:
            try:
                _validate(instance, subschema, root, path, depth)
            except ValidationError:
                continue
            return
        raise ValidationError(f"{_display(path)}: no 'anyOf' branch matched")
    elif keyword == "oneOf":
        matched = 0
        for subschema in value:
            try:
                _validate(instance, subschema, root, path, depth)
            except ValidationError:
                continue
            matched += 1
        if matched != 1:
            raise ValidationError(
                f"{_display(path)}: expected exactly one 'oneOf' branch, {matched} matched"
            )
    elif keyword == "not":
        try:
            _validate(instance, value, root, path, depth)
        except ValidationError:
            return
        raise ValidationError(f"{_display(path)}: the 'not' schema must not match")
    elif keyword == "if":
        try:
            _validate(instance, value, root, path, depth)
        except ValidationError:
            branch = schema.get("else")
        else:
            branch = schema.get("then")
        if branch is not None:
            _validate(instance, branch, root, path, depth)


def _resolve(root: Any, reference: str) -> Any:
    node = root
    for token in reference[2:].split("/"):
        if not token:
            continue
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            raise SchemaError(f"cannot resolve reference {reference}")
        node = node[token]
    return node


def _matches_type(instance: Any, name: str) -> bool:
    if name == "object":
        return isinstance(instance, dict)
    if name == "array":
        return isinstance(instance, list)
    if name == "string":
        return isinstance(instance, str)
    if name == "boolean":
        return isinstance(instance, bool)
    if name == "null":
        return instance is None
    if name == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if name == "number":
        return _is_number(instance)
    return False


def _is_number(instance: Any) -> bool:
    return isinstance(instance, (int, float)) and not isinstance(instance, bool)


def _json_equal(left: Any, right: Any) -> bool:
    # JSON has one number type, but Python distinguishes True from 1, and a
    # const of 1 must not be satisfied by true.
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)


def _kind(instance: Any) -> str:
    for name in ("null", "boolean", "integer", "number", "string", "array", "object"):
        if _matches_type(instance, name):
            return name
    return "unknown"


def _display(path: str) -> str:
    return path or "<root>"
