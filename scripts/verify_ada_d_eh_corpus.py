#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Validate Ada/D EH manifests against their matrix and binary evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import ada_d_eh_matrix as matrix
import json_schema_check
from object_readers import ObjectFormatError, load_object


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schema/ada-d-eh-manifest.schema.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,2}$")
PREFIX_MAP = "-ffile-prefix-map="
PREFIX_MAP_SUFFIX = "=/testbins"


class VerificationError(ValueError):
    """Raised when a manifest or artifact breaks the corpus contract."""


@dataclass(frozen=True)
class VerificationResult:
    artifact_count: int
    total_bytes: int


def require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context} must be an object")
    return value


def require_array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{context} must be an array")
    return value


def require_string(container: dict[str, Any], key: str, context: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{context}.{key} must be a non-empty string")
    return value


def load_json(path: Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {context} {path}: {error}") from error


def validate_schema(manifest: dict[str, Any]) -> None:
    schema = load_json(SCHEMA_PATH, "schema")
    try:
        json_schema_check.validate(manifest, schema)
    except (json_schema_check.SchemaError, json_schema_check.ValidationError) as error:
        raise VerificationError(f"manifest schema validation failed: {error}") from error


def validate_producer(
    manifest: dict[str, Any],
) -> tuple[str, dict[str, dict[str, Any]]]:
    producer = require_object(manifest.get("producer"), "producer")
    revision = require_string(producer, "repository_revision", "producer")
    if not REVISION_RE.fullmatch(revision):
        raise VerificationError("producer.repository_revision must be a full SHA")

    records = require_array(producer.get("toolchains"), "producer.toolchains")
    if not records:
        raise VerificationError("producer.toolchains must not be empty")
    by_cell: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(records):
        context = f"producer.toolchains[{index}]"
        record = require_object(raw, context)
        key = require_string(record, "cell", context)
        if key in by_cell:
            raise VerificationError(f"duplicate toolchain record for {key}")
        try:
            cell = matrix.validate_cell(
                require_string(record, "toolchain", context),
                require_string(record, "target", context),
            )
        except matrix.MatrixError as error:
            raise VerificationError(f"{context}: {error}") from error
        if key != cell.key:
            raise VerificationError(f"{context}.cell must be {cell.key!r}")
        expected = matrix.toolchain_contract(cell)
        declared = {name: record.get(name) for name in expected}
        if declared != expected:
            raise VerificationError(f"{context} disagrees with the build matrix")
        version = require_string(record, "version", context)
        if not VERSION_RE.fullmatch(version) or not version.startswith(
            cell.version_prefix
        ):
            raise VerificationError(
                f"{context}.version {version!r} violates pin "
                f"{cell.version_prefix!r}"
            )
        require_string(record, "version_string", context)
        by_cell[key] = record
    return revision, by_cell


def resolve_artifact(
    artifact: dict[str, Any], context: str
) -> tuple[matrix.MatrixCell, matrix.Variant]:
    try:
        cell = matrix.validate_cell(
            require_string(artifact, "toolchain", context),
            require_string(artifact, "target", context),
        )
        variant = matrix.validate_variant(
            require_string(artifact, "optimization", context)
        )
    except matrix.MatrixError as error:
        raise VerificationError(f"{context}: {error}") from error

    expected_axes = {
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "source_language": cell.language,
        "execution": cell.execution(),
        "exception_model": "itanium-dwarf",
    }
    for key, expected in expected_axes.items():
        if require_string(artifact, key, context) != expected:
            raise VerificationError(f"{context}.{key} must be {expected!r}")
    expected_path = cell.artifact_path(variant)
    if require_string(artifact, "path", context) != expected_path:
        raise VerificationError(f"{context}.path must be {expected_path!r}")
    return cell, variant


def checkout_prefix(
    build: dict[str, Any], cell: matrix.MatrixCell, context: str
) -> str:
    declared_prefix = require_string(build, "checkout_prefix", context)
    if len(declared_prefix) < 4:
        raise VerificationError(f"{context}.checkout_prefix is implausibly short")
    flags = require_array(build.get("compiler_flags"), f"{context}.compiler_flags")
    if any(not isinstance(flag, str) or not flag for flag in flags):
        raise VerificationError(f"{context}.compiler_flags contains an invalid flag")
    maps = [flag for flag in flags if flag.startswith(PREFIX_MAP)]
    if cell.toolchain in {"gnat", "gdc"}:
        if len(maps) != 1 or not maps[0].endswith(PREFIX_MAP_SUFFIX):
            raise VerificationError(f"{context} must remap one checkout prefix")
        mapped_prefix = maps[0][len(PREFIX_MAP) : -len(PREFIX_MAP_SUFFIX)]
        if mapped_prefix != declared_prefix:
            raise VerificationError(f"{context}.checkout_prefix disagrees with remap")
        return declared_prefix
    if maps:
        raise VerificationError(f"{context} declares an unsupported prefix map")
    return declared_prefix


def validate_build(
    artifact: dict[str, Any],
    cell: matrix.MatrixCell,
    variant: matrix.Variant,
    context: str,
) -> str:
    build = require_object(artifact.get("build"), f"{context}.build")
    prefix = checkout_prefix(build, cell, f"{context}.build")
    expected = matrix.build_contract(cell, variant, prefix)
    declared = {name: build.get(name) for name in expected}
    if declared != expected:
        differences = sorted(
            name for name in expected if declared.get(name) != expected[name]
        )
        raise VerificationError(
            f"{context}.build disagrees on: {', '.join(differences)}"
        )
    for key, expected_value in (
        ("runner_os", cell.runner_os),
        ("runner_arch", cell.runner_arch),
    ):
        if require_string(build, key, f"{context}.build") != expected_value:
            raise VerificationError(
                f"{context}.build.{key} must be {expected_value!r}"
            )
    require_string(build, "runner_image", f"{context}.build")
    return prefix


def resolve_file(root: Path, path_text: str, context: str) -> Path:
    pure = PurePosixPath(path_text)
    if pure.is_absolute() or ".." in pure.parts:
        raise VerificationError(f"{context}.path escapes the corpus root")
    path = root.joinpath(*pure.parts)
    if not path.is_file():
        raise VerificationError(f"{context} artifact is missing: {path_text}")
    return path


def validate_binary(
    payload: bytes,
    artifact: dict[str, Any],
    cell: matrix.MatrixCell,
    checkout: str,
    context: str,
) -> None:
    try:
        image = load_object(payload)
    except ObjectFormatError as error:
        raise VerificationError(f"{context}: {error}") from error
    if image.object_format != cell.object_format:
        raise VerificationError(f"{context} is not {cell.object_format}")
    if image.architecture != cell.architecture:
        raise VerificationError(
            f"{context} is {image.architecture}, expected {cell.architecture}"
        )

    evidence = require_object(artifact.get("evidence"), f"{context}.evidence")
    if evidence != matrix.evidence_contract(cell):
        raise VerificationError(f"{context}.evidence disagrees with the matrix")
    for section in evidence["required_sections"]:
        if section not in image.sections:
            raise VerificationError(f"{context} is missing section {section}")
        if image.sections[section].file_size == 0:
            raise VerificationError(f"{context} section {section} is empty")
    for symbol in evidence["required_symbols"]:
        if symbol not in image.symbols:
            raise VerificationError(f"{context} is missing symbol {symbol}")
    for text in evidence["required_strings"]:
        if not image.contains_bytes(text.encode("utf-8")):
            raise VerificationError(f"{context} is missing string {text!r}")
    if checkout and image.contains_bytes(checkout.encode("utf-8")):
        raise VerificationError(f"{context} leaks its checkout path")

    try:
        records = image.verify_unwind_tables()
        _cies, fdes = image.frame_record_counts()
    except ObjectFormatError as error:
        raise VerificationError(f"{context}: malformed unwind data: {error}") from error
    if records < 1 or fdes < 1:
        raise VerificationError(f"{context} has no file-backed unwind records")


def validate_artifact(
    artifact: dict[str, Any],
    root: Path,
    context: str,
) -> tuple[str, str, int]:
    cell, variant = resolve_artifact(artifact, context)
    checkout = validate_build(artifact, cell, variant, context)
    if artifact.get("evidence") != matrix.evidence_contract(cell):
        raise VerificationError(f"{context}.evidence disagrees with the matrix")
    if artifact.get("neverd") != matrix.neverd_contract(cell):
        raise VerificationError(f"{context}.neverd disagrees with the matrix")

    path_text = require_string(artifact, "path", context)
    path = resolve_file(root, path_text, context)
    payload = path.read_bytes()
    size = artifact.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size != len(payload):
        raise VerificationError(f"{context} size mismatch")
    digest = require_string(artifact, "sha256", context)
    if not SHA256_RE.fullmatch(digest):
        raise VerificationError(f"{context}.sha256 is invalid")
    if hashlib.sha256(payload).hexdigest() != digest:
        raise VerificationError(f"{context} SHA-256 mismatch")
    validate_binary(payload, artifact, cell, checkout, context)
    return path_text, cell.key, len(payload)


def verify_manifest(manifest_path: Path, root: Path) -> VerificationResult:
    manifest = require_object(load_json(manifest_path, "manifest"), "manifest")
    validate_schema(manifest)
    if manifest.get("schema_version") != 1 or manifest.get("corpus") != matrix.CORPUS_NAME:
        raise VerificationError("unsupported Ada/D EH manifest identity")
    _revision, toolchains = validate_producer(manifest)

    artifacts = require_array(manifest.get("artifacts"), "artifacts")
    if not artifacts:
        raise VerificationError("artifacts must not be empty")
    paths: list[str] = []
    used_cells: set[str] = set()
    total_bytes = 0
    for index, raw in enumerate(artifacts):
        context = f"artifacts[{index}]"
        artifact = require_object(raw, context)
        path, cell_key, size = validate_artifact(artifact, root, context)
        paths.append(path)
        used_cells.add(cell_key)
        total_bytes += size
        version = require_string(artifact, "toolchain_version", context)
        if cell_key not in toolchains or version != toolchains[cell_key]["version"]:
            raise VerificationError(f"{context} has no matching producer toolchain")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise VerificationError("artifact paths must be sorted and unique")
    if set(toolchains) != used_cells:
        raise VerificationError("producer toolchains must exactly match artifact cells")
    return VerificationResult(len(artifacts), total_bytes)


def verify_complete_matrix(manifest_path: Path) -> None:
    manifest = require_object(load_json(manifest_path, "manifest"), "manifest")
    paths = tuple(entry["path"] for entry in manifest["artifacts"])
    if paths != matrix.expected_artifact_paths():
        raise VerificationError("manifest does not contain the complete Ada/D EH matrix")
    cells = {record["cell"] for record in manifest["producer"]["toolchains"]}
    expected = {cell.key for cell in matrix.expected_cells()}
    if cells != expected:
        raise VerificationError("producer does not contain every Ada/D EH cell")


def merge_manifests(
    fragment_paths: list[Path], output: Path, root: Path
) -> VerificationResult:
    if not fragment_paths:
        raise VerificationError("no Ada/D EH fragments were provided")
    revisions: set[str] = set()
    toolchains: dict[str, dict[str, Any]] = {}
    artifacts: list[dict[str, Any]] = []
    for path in fragment_paths:
        verify_manifest(path, root)
        fragment = require_object(load_json(path, "fragment"), "fragment")
        revision, records = validate_producer(fragment)
        revisions.add(revision)
        for key, record in records.items():
            if key in toolchains:
                raise VerificationError(f"duplicate fragment for cell {key}")
            toolchains[key] = record
        artifacts.extend(fragment["artifacts"])
    if len(revisions) != 1:
        raise VerificationError("fragments were produced from different revisions")

    manifest = {
        "schema_version": 1,
        "corpus": matrix.CORPUS_NAME,
        "producer": {
            "repository_revision": revisions.pop(),
            "toolchains": [toolchains[key] for key in sorted(toolchains)],
        },
        "artifacts": sorted(artifacts, key=lambda entry: entry["path"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return verify_manifest(output, root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--require-complete-matrix", action="store_true")
    args = parser.parse_args()
    result = verify_manifest(args.manifest, args.root)
    if args.require_complete_matrix:
        verify_complete_matrix(args.manifest)
    print(
        f"verified {result.artifact_count} Ada/D EH artifact(s), "
        f"{result.total_bytes} byte(s)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
