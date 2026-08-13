#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Validate the Objective-C exception corpus and its manifest.

The manifest is schema-checked, every axis and contract is recomputed from
`objc_matrix.py`, and every structural claim is then derived again from the
Mach-O bytes through `object_readers.py`. Producer statements about binary
contents are never accepted as evidence on their own.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import json_schema_check
import objc_matrix as matrix
from object_readers import ObjectFormatError, ObjectImage, load_object


class VerificationError(ValueError):
    """Raised when the corpus contract or an artifact is invalid."""


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schema/objc-eh-manifest.schema.json"
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REVISION_RE = re.compile(r"[0-9a-f]{40}")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_APPLE_CLANG_BANNER_RE = re.compile(
    r"^Apple clang version ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)"
)
_FILE_PREFIX_MAP = "-ffile-prefix-map="
_REMAP_SUFFIX = "=/testbins"
_MIN_REMAPPED_PREFIX = 4


@dataclass(frozen=True)
class VerificationResult:
    artifact_count: int
    total_bytes: int


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context} must be an object")
    return value


def _require_array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{context} must be an array")
    return value


def _require_string(container: dict[str, Any], key: str, context: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{context}.{key} must be a non-empty string")
    return value


def _require_bool(container: dict[str, Any], key: str, context: str) -> bool:
    value = container.get(key)
    if not isinstance(value, bool):
        raise VerificationError(f"{context}.{key} must be a boolean")
    return value


def _load_json(path: Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {context} {path}: {error}") from error


def _load_manifest(path: Path) -> dict[str, Any]:
    return _require_object(_load_json(path, "manifest"), "manifest")


def validate_against_schema(manifest: dict[str, Any], schema_path: Path) -> None:
    schema = _load_json(schema_path, "schema")
    try:
        json_schema_check.validate(manifest, schema)
    except json_schema_check.SchemaError as error:
        raise VerificationError(f"manifest schema is unusable: {error}") from error
    except json_schema_check.ValidationError as error:
        raise VerificationError(
            f"manifest does not match its schema: {error}"
        ) from error


def _validate_manifest_identity(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 1:
        raise VerificationError("unsupported manifest schema_version")
    if manifest.get("corpus") != matrix.CORPUS_NAME:
        raise VerificationError("unsupported corpus identity")


def _validate_producer(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Validate the producer envelope and key toolchains by matrix cell."""

    producer = _require_object(manifest.get("producer"), "producer")
    revision = _require_string(producer, "repository_revision", "producer")
    if not _REVISION_RE.fullmatch(revision):
        raise VerificationError("producer.repository_revision must be a full SHA")

    records = _require_array(producer.get("toolchains"), "producer.toolchains")
    if not records:
        raise VerificationError("producer.toolchains must not be empty")
    by_cell: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(records):
        context = f"producer.toolchains[{index}]"
        record = _require_object(raw, context)
        key = _require_string(record, "cell", context)
        if key in by_cell:
            raise VerificationError(f"duplicate producer toolchain for cell {key}")
        runtime = _require_string(record, "runtime", context)
        target = _require_string(record, "target", context)
        try:
            cell = matrix.validate_cell(runtime, target)
        except matrix.MatrixError as error:
            raise VerificationError(f"{context}: {error}") from error
        if cell.key != key:
            raise VerificationError(
                f"{context}.cell is {key!r} but runtime and target resolve to "
                f"{cell.key!r}"
            )
        expected = matrix.toolchain_contract(cell)
        declared = {name: record.get(name) for name in expected}
        if declared != expected:
            differences = sorted(
                name for name in expected if declared[name] != expected[name]
            )
            raise VerificationError(
                f"{context} disagrees with the matrix on: {', '.join(differences)}"
            )
        version = _require_string(record, "version", context)
        if not _VERSION_RE.fullmatch(version):
            raise VerificationError(
                f"{context}.version is not an exact three-part release"
            )
        if not version.startswith(cell.version_prefix):
            raise VerificationError(
                f"{context} built with {version!r}, but the matrix pins "
                f"{cell.version_prefix!r} for {cell.key}"
            )
        version_string = _require_string(record, "version_string", context)
        banner_match = _APPLE_CLANG_BANNER_RE.match(version_string)
        if banner_match is None or banner_match.group(1) != version:
            raise VerificationError(
                f"{context}.version_string does not identify Apple clang {version}"
            )
        by_cell[key] = record
    return by_cell


def _resolve(
    artifact: dict[str, Any], context: str
) -> tuple[matrix.MatrixCell, matrix.Variant]:
    """Recover the cell and variant, then check every adjacent axis."""

    runtime = _require_string(artifact, "runtime", context)
    target = _require_string(artifact, "target", context)
    program = _require_string(artifact, "program", context)
    optimization = _require_string(artifact, "optimization", context)
    stripped = _require_bool(artifact, "stripped", context)
    try:
        cell = matrix.validate_cell(runtime, target)
        variant = matrix.validate_variant(program, optimization, stripped)
    except matrix.MatrixError as error:
        raise VerificationError(f"{context}: {error}") from error

    for key, expected in (
        ("architecture", cell.architecture),
        ("object_format", cell.object_format),
        ("arc", variant.arc),
        ("exceptions", variant.exceptions),
        ("execution", cell.execution(variant)),
    ):
        if _require_string(artifact, key, context) != expected:
            raise VerificationError(
                f"{context}.{key} must be {expected!r} for {cell.key}/{variant.key}"
            )
    expected_path = cell.artifact_path(variant)
    if _require_string(artifact, "path", context) != expected_path:
        raise VerificationError(
            f"{context}.path disagrees with the build axes; expected {expected_path}"
        )
    return cell, variant


def _validate_build(
    artifact: dict[str, Any],
    cell: matrix.MatrixCell,
    variant: matrix.Variant,
    context: str,
) -> str:
    """Check the exact invocation and return the remapped checkout prefix."""

    build = _require_object(artifact.get("build"), f"{context}.build")
    flags = _require_array(
        build.get("compiler_flags"), f"{context}.build.compiler_flags"
    )
    if any(not isinstance(flag, str) or not flag for flag in flags):
        raise VerificationError(
            f"{context}.build.compiler_flags must be non-empty strings"
        )
    mapped = [flag for flag in flags if flag.startswith(_FILE_PREFIX_MAP)]
    if len(mapped) != 1:
        raise VerificationError(
            f"{context}.build.compiler_flags must pass exactly one "
            f"{_FILE_PREFIX_MAP}"
        )
    mapping = mapped[0][len(_FILE_PREFIX_MAP) :]
    if not mapping.endswith(_REMAP_SUFFIX):
        raise VerificationError(
            f"{context}.build.compiler_flags: {_FILE_PREFIX_MAP} must map onto "
            f"{_REMAP_SUFFIX[1:]!r}"
        )
    prefix = mapping[: -len(_REMAP_SUFFIX)]
    if len(prefix) < _MIN_REMAPPED_PREFIX:
        raise VerificationError(
            f"{context}.build.compiler_flags: remapped prefix {prefix!r} is too "
            "short to be a checkout path"
        )

    expected = matrix.build_contract(cell, variant, prefix)
    declared = {name: build.get(name) for name in expected}
    if declared != expected:
        differences = sorted(
            name for name in expected if declared[name] != expected[name]
        )
        raise VerificationError(
            f"{context}.build disagrees with the matrix on: {', '.join(differences)}"
        )
    for key, expected_value in (
        ("runner_os", cell.runner_os),
        ("runner_arch", cell.runner_arch),
    ):
        if _require_string(build, key, f"{context}.build") != expected_value:
            raise VerificationError(
                f"{context}.build.{key} must be {expected_value!r} for {cell.key}"
            )
    _require_string(build, "runner_image", f"{context}.build")
    return prefix


def _validate_contract_block(
    artifact: dict[str, Any],
    key: str,
    expected: dict[str, object],
    context: str,
) -> dict[str, Any]:
    block = _require_object(artifact.get(key), f"{context}.{key}")
    if block != expected:
        differences = sorted(
            name
            for name in set(block) | set(expected)
            if block.get(name) != expected.get(name)
        )
        raise VerificationError(
            f"{context}.{key} disagrees with the matrix contract on: "
            f"{', '.join(differences)}"
        )
    return block


def _validate_image(
    image: ObjectImage,
    artifact: dict[str, Any],
    cell: matrix.MatrixCell,
    remapped_prefix: str,
    context: str,
) -> None:
    if image.object_format != cell.object_format:
        raise VerificationError(
            f"{context} is a {image.object_format} image, manifest says "
            f"{cell.object_format}"
        )
    if image.architecture != cell.architecture:
        raise VerificationError(
            f"{context} is {image.architecture}, manifest says {cell.architecture}"
        )

    evidence = _require_object(artifact.get("evidence"), f"{context}.evidence")
    missing = [
        name for name in evidence["required_sections"] if name not in image.sections
    ]
    if missing:
        raise VerificationError(
            f"{context} required section(s) missing: {', '.join(sorted(missing))}"
        )
    unwanted = [
        name for name in evidence["forbidden_sections"] if name in image.sections
    ]
    if unwanted:
        raise VerificationError(
            f"{context} forbidden section(s) present: {', '.join(sorted(unwanted))}"
        )

    if evidence["symbol_names_expected"] and not image.has_symbol_table:
        raise VerificationError(f"{context} has no readable symbol names")
    absent = [
        name for name in evidence["required_symbols"] if name not in image.symbols
    ]
    if absent:
        raise VerificationError(
            f"{context} required symbol(s) missing: {', '.join(sorted(absent))}"
        )
    present = [name for name in evidence["forbidden_symbols"] if name in image.symbols]
    if present:
        raise VerificationError(
            f"{context} forbidden symbol(s) present: {', '.join(sorted(present))}"
        )
    for text in evidence["required_strings"]:
        if not image.contains_bytes(text.encode("ascii")):
            raise VerificationError(f"{context} does not contain the string {text!r}")

    if evidence["require_unwind_tables"]:
        try:
            records = image.verify_unwind_tables()
        except ObjectFormatError as error:
            raise VerificationError(
                f"{context} unwind tables are invalid: {error}"
            ) from error
        if records < 1:
            raise VerificationError(f"{context} unwind tables describe nothing")

    has_eh_frame = "__eh_frame" in image.sections
    if evidence["eh_frame_present"]:
        if not has_eh_frame:
            raise VerificationError(f"{context} required __eh_frame is absent")
        try:
            _cies, frame_descriptions = image.frame_record_counts()
        except ObjectFormatError as error:
            raise VerificationError(
                f"{context} has no readable DWARF frame section: {error}"
            ) from error
        if frame_descriptions < 1:
            raise VerificationError(
                f"{context} has a DWARF frame section that describes no function"
            )
    elif has_eh_frame:
        raise VerificationError(
            f"{context} carries __eh_frame although the matrix requires compact "
            "unwind only"
        )

    if image.contains_bytes(remapped_prefix.encode("utf-8")):
        raise VerificationError(
            f"{context} leaks the build path {remapped_prefix!r} despite "
            "-ffile-prefix-map"
        )


def _validate_artifact(
    artifact: dict[str, Any],
    index: int,
    root: Path,
    toolchains: dict[str, dict[str, Any]],
) -> tuple[str, int]:
    context = f"artifacts[{index}]"
    cell, variant = _resolve(artifact, context)
    remapped_prefix = _validate_build(artifact, cell, variant, context)
    _validate_contract_block(
        artifact, "evidence", matrix.evidence_contract(cell, variant), context
    )
    _validate_contract_block(
        artifact, "neverd", matrix.neverd_contract(cell, variant), context
    )

    version = _require_string(artifact, "toolchain_version", context)
    if not _VERSION_RE.fullmatch(version) or not version.startswith(
        cell.version_prefix
    ):
        raise VerificationError(
            f"{context}.toolchain_version {version!r} is not the {cell.key} pin "
            f"{cell.version_prefix!r}"
        )
    producer = toolchains.get(cell.key)
    if producer is None:
        raise VerificationError(
            f"{context} names a cell producer.toolchains does not describe"
        )
    if producer.get("version") != version:
        raise VerificationError(
            f"{context}.toolchain_version disagrees with producer.toolchains"
        )

    relative_text = str(artifact["path"])
    relative = PurePosixPath(relative_text)
    if relative.is_absolute() or any(
        part in ("", ".", "..") for part in relative.parts
    ):
        raise VerificationError(f"{context}.path is not a normalized relative path")
    expected_hash = _require_string(artifact, "sha256", context)
    if not _SHA256_RE.fullmatch(expected_hash):
        raise VerificationError(f"{context}.sha256 is not a lowercase SHA-256")
    expected_size = artifact.get("size")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size < 1
    ):
        raise VerificationError(f"{context}.size must be a positive integer")

    root_resolved = root.resolve()
    artifact_path = (root / Path(*relative.parts)).resolve()
    try:
        artifact_path.relative_to(root_resolved)
    except ValueError as error:
        raise VerificationError(f"{context}.path escapes the corpus root") from error
    try:
        payload = artifact_path.read_bytes()
    except OSError as error:
        raise VerificationError(
            f"cannot read artifact {relative_text}: {error}"
        ) from error
    if len(payload) != expected_size:
        raise VerificationError(
            f"{context} size mismatch: file is {len(payload)}, manifest says "
            f"{expected_size}"
        )
    if hashlib.sha256(payload).hexdigest() != expected_hash:
        raise VerificationError(f"{context} SHA-256 mismatch")

    try:
        image = load_object(payload)
    except ObjectFormatError as error:
        raise VerificationError(f"{context} cannot be decoded: {error}") from error
    _validate_image(image, artifact, cell, remapped_prefix, context)
    return relative_text, len(payload)


def verify_manifest(
    path: Path, root: Path, schema_path: Path | None = None
) -> VerificationResult:
    manifest = _load_manifest(path)
    _validate_manifest_identity(manifest)
    validate_against_schema(manifest, schema_path or _SCHEMA_PATH)
    toolchains = _validate_producer(manifest)

    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    if not artifacts:
        raise VerificationError("manifest contains no artifacts")
    seen_paths: set[str] = set()
    total_bytes = 0
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        relative_path, size = _validate_artifact(artifact, index, root, toolchains)
        if relative_path in seen_paths:
            raise VerificationError(f"duplicate artifact path: {relative_path}")
        seen_paths.add(relative_path)
        total_bytes += size
    return VerificationResult(len(artifacts), total_bytes)


def verify_complete_matrix(path: Path) -> None:
    manifest = _load_manifest(path)
    _validate_manifest_identity(manifest)
    producer = _require_object(manifest.get("producer"), "producer")
    declared_cells = sorted(
        str(_require_object(entry, "producer.toolchains[]").get("cell"))
        for entry in _require_array(producer.get("toolchains"), "producer.toolchains")
    )
    expected_cells = sorted(cell.key for cell in matrix.expected_cells())
    if declared_cells != expected_cells:
        raise VerificationError(
            f"producer.toolchains lists {declared_cells}, the matrix has "
            f"{expected_cells}"
        )

    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    paths: list[str] = []
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        paths.append(_require_string(artifact, "path", f"artifacts[{index}]"))
    if len(set(paths)) != len(paths):
        duplicate = sorted({name for name in paths if paths.count(name) > 1})
        raise VerificationError(f"duplicate artifact path(s): {', '.join(duplicate)}")

    expected_paths = set(matrix.expected_artifact_paths())
    actual = set(paths)
    if actual != expected_paths:
        missing = sorted(expected_paths - actual)
        extra = sorted(actual - expected_paths)
        raise VerificationError(
            f"incomplete objc-eh matrix; missing={missing}, extra={extra}"
        )


def _merge_producers(fragments: list[dict[str, Any]]) -> dict[str, Any]:
    """Union cell toolchains while requiring shared producer facts to agree."""

    shared: dict[str, Any] | None = None
    toolchains: dict[str, dict[str, Any]] = {}
    for fragment in fragments:
        producer = _require_object(fragment.get("producer"), "producer")
        rest = {key: value for key, value in producer.items() if key != "toolchains"}
        if shared is None:
            shared = rest
        elif shared != rest:
            raise VerificationError(
                "manifest fragments disagree about the producer that made them"
            )
        for entry in _require_array(producer.get("toolchains"), "producer.toolchains"):
            record = _require_object(entry, "producer.toolchains[]")
            key = _require_string(record, "cell", "producer.toolchains[]")
            existing = toolchains.get(key)
            if existing is not None and existing != record:
                raise VerificationError(
                    f"manifest fragments disagree about the {key} toolchain"
                )
            toolchains[key] = record
    assert shared is not None
    merged = dict(shared)
    merged["toolchains"] = [toolchains[key] for key in sorted(toolchains)]
    return merged


def merge_manifests(
    fragment_paths: list[Path], output_path: Path, root: Path
) -> VerificationResult:
    if not fragment_paths:
        raise VerificationError("no manifest fragments were found")
    fragments: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for fragment_path in sorted(fragment_paths, key=lambda item: item.as_posix()):
        verify_manifest(fragment_path, root)
        fragment = _load_manifest(fragment_path)
        fragments.append(fragment)
        artifacts.extend(_require_array(fragment.get("artifacts"), "artifacts"))

    first = fragments[0]
    for fragment in fragments[1:]:
        if (
            fragment["schema_version"] != first["schema_version"]
            or fragment["corpus"] != first["corpus"]
        ):
            raise VerificationError("manifest fragments have inconsistent identities")
    merged = {
        "schema_version": first["schema_version"],
        "corpus": first["corpus"],
        "producer": _merge_producers(fragments),
        "artifacts": sorted(artifacts, key=lambda entry: str(entry.get("path", ""))),
    }
    _write_json(output_path, merged)
    return verify_manifest(output_path, root)


def _write_json(output_path: Path, payload: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
        Path(temporary_name).replace(output_path)
    except BaseException:
        try:
            Path(temporary_name).unlink()
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=_SCHEMA_PATH)
    parser.add_argument("--require-complete-matrix", action="store_true")
    args = parser.parse_args()
    result = verify_manifest(args.manifest, args.root, args.schema)
    if args.require_complete_matrix:
        verify_complete_matrix(args.manifest)
    print(f"verified {result.artifact_count} artifact(s), {result.total_bytes} byte(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
