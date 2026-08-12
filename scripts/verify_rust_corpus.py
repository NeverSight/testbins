#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Validate the Rust unwinding and panic corpus and its manifest.

Three checks run against every artifact, and they are deliberately independent
of one another:

1. the manifest validates against `schema/rust-eh-manifest.schema.json`;
2. every declared axis, path, flag, and contract is recomputed from
   `rust_matrix.py` and must match exactly, so the manifest cannot drift from
   the matrix that produced it;
3. the binary is parsed from its own headers and must actually contain the
   sections, symbols, strings, and unwind records the manifest claims.

The producer is only trusted for the bytes on disk.
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
import rust_matrix
from object_readers import ObjectFormatError, ObjectImage, load_object


class VerificationError(ValueError):
    """Raised when the corpus contract or an artifact is invalid."""


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schema/rust-eh-manifest.schema.json"
)
_TOOLCHAIN_PATH = Path(__file__).resolve().parents[1] / "rust-toolchain.toml"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CHANNEL_RE = re.compile(r'^\s*channel\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_EXACT_RELEASE_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_REMAP_SUFFIX = "=/testbins"
# A remapped prefix shorter than this is too generic to search for safely.
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


def _load_json(path: Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {context} {path}: {error}") from error


def _load_manifest(path: Path) -> dict[str, Any]:
    return _require_object(_load_json(path, "manifest"), "manifest")


def pinned_toolchain_channel() -> str:
    """Return the exact release `rust-toolchain.toml` pins."""

    try:
        text = _TOOLCHAIN_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise VerificationError(f"cannot read {_TOOLCHAIN_PATH}: {error}") from error
    match = _CHANNEL_RE.search(text)
    if not match:
        raise VerificationError("rust-toolchain.toml declares no channel")
    channel = match.group(1)
    if not _EXACT_RELEASE_RE.fullmatch(channel):
        raise VerificationError(
            f"rust-toolchain.toml must pin an exact release, found {channel!r}"
        )
    return channel


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


def _validate_producer(manifest: dict[str, Any]) -> None:
    producer = _require_object(manifest.get("producer"), "producer")
    rustc = _require_object(producer.get("rustc"), "producer.rustc")
    release = _require_string(rustc, "release", "producer.rustc")
    channel = _require_string(producer, "toolchain_channel", "producer")
    if channel != release:
        raise VerificationError(
            f"producer.toolchain_channel {channel!r} disagrees with the rustc "
            f"release {release!r} that produced the corpus"
        )
    pinned = pinned_toolchain_channel()
    if channel != pinned:
        raise VerificationError(
            f"corpus was built with {channel!r} but rust-toolchain.toml pins {pinned!r}"
        )


def _validate_axes(artifact: dict[str, Any], context: str) -> rust_matrix.MatrixCell:
    target = _require_string(artifact, "target_triple", context)
    panic_strategy = _require_string(artifact, "panic_strategy", context)
    optimization = _require_string(artifact, "optimization", context)
    try:
        cell = rust_matrix.validate_cell(target, panic_strategy, optimization)
    except ValueError as error:
        raise VerificationError(f"{context}: {error}") from error

    crate_name = _require_string(artifact, "crate_name", context)
    try:
        expected_crate_type = rust_matrix.crate_type(crate_name)
    except ValueError as error:
        raise VerificationError(f"{context}: {error}") from error
    if _require_string(artifact, "crate_type", context) != expected_crate_type:
        raise VerificationError(f"{context}.crate_type disagrees with crate_name")
    if _require_string(artifact, "architecture", context) != cell.architecture:
        raise VerificationError(f"{context}.architecture disagrees with target_triple")
    if _require_string(artifact, "object_format", context) != cell.object_format:
        raise VerificationError(f"{context}.object_format disagrees with target_triple")
    expected_execution = cell.execution(crate_name)
    if _require_string(artifact, "execution", context) != expected_execution:
        raise VerificationError(
            f"{context}.execution must be {expected_execution!r} for "
            f"{cell.target}/{expected_crate_type}"
        )
    expected_path = cell.artifact_path(crate_name)
    if _require_string(artifact, "path", context) != expected_path:
        raise VerificationError(
            f"{context}.path disagrees with the build axes; expected {expected_path}"
        )
    return cell


def _validate_build(
    artifact: dict[str, Any], cell: rust_matrix.MatrixCell, context: str
) -> str:
    """Check the recorded rustc invocation and return the remapped prefix."""

    build = _require_object(artifact.get("build"), f"{context}.build")
    if _require_string(build, "edition", f"{context}.build") != rust_matrix.edition():
        raise VerificationError(f"{context}.build.edition is not the pinned edition")
    if _require_string(build, "linker", f"{context}.build") != cell.linker:
        raise VerificationError(
            f"{context}.build.linker must be {cell.linker!r} for {cell.target}"
        )
    for key, expected_value in (
        ("rustc_host", cell.rustc_host),
        ("runner_os", cell.runner_os),
        ("runner_arch", cell.runner_arch),
    ):
        if _require_string(build, key, f"{context}.build") != expected_value:
            raise VerificationError(
                f"{context}.build.{key} must be {expected_value!r} for {cell.target}"
            )
    _require_string(build, "runner_image", f"{context}.build")
    flags = _require_array(build.get("rustc_flags"), f"{context}.build.rustc_flags")
    if any(not isinstance(flag, str) or not flag for flag in flags):
        raise VerificationError(
            f"{context}.build.rustc_flags must be non-empty strings"
        )
    if "--remap-path-prefix" not in flags:
        raise VerificationError(
            f"{context}.build.rustc_flags omit --remap-path-prefix, so the build "
            "path is not proven to be absent from the image"
        )
    index = flags.index("--remap-path-prefix")
    if index + 1 >= len(flags):
        raise VerificationError(
            f"{context}.build.rustc_flags: --remap-path-prefix has no value"
        )
    mapping = flags[index + 1]
    if not mapping.endswith(_REMAP_SUFFIX):
        raise VerificationError(
            f"{context}.build.rustc_flags: --remap-path-prefix must map onto "
            f"{_REMAP_SUFFIX[1:]!r}"
        )
    prefix = mapping[: -len(_REMAP_SUFFIX)]
    if len(prefix) < _MIN_REMAPPED_PREFIX:
        raise VerificationError(
            f"{context}.build.rustc_flags: remapped prefix {prefix!r} is too short "
            "to be a checkout path"
        )
    crate_name = str(artifact["crate_name"])
    expected = rust_matrix.rustc_flags(cell, crate_name, prefix)
    if list(flags) != expected:
        raise VerificationError(
            f"{context}.build.rustc_flags are not the flags the matrix defines; "
            f"expected {expected}"
        )
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
    cell: rust_matrix.MatrixCell,
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

    # The whole point of --remap-path-prefix is that the checkout path does not
    # reach a published binary. Nothing else proves it actually worked.
    if image.contains_bytes(remapped_prefix.encode("utf-8")):
        raise VerificationError(
            f"{context} leaks the build path {remapped_prefix!r} despite "
            "--remap-path-prefix"
        )


def _validate_artifact(
    artifact: dict[str, Any], index: int, root: Path
) -> tuple[str, int]:
    context = f"artifacts[{index}]"
    cell = _validate_axes(artifact, context)
    crate_name = str(artifact["crate_name"])
    remapped_prefix = _validate_build(artifact, cell, context)
    _validate_contract_block(
        artifact, "evidence", rust_matrix.evidence_contract(cell, crate_name), context
    )
    _validate_contract_block(
        artifact, "neverd", rust_matrix.neverd_contract(cell, crate_name), context
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
            f"{context} size mismatch: file is {len(payload)}, manifest says {expected_size}"
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
    validate_against_schema(manifest, schema_path or _SCHEMA_PATH)
    _validate_producer(manifest)

    artifacts = _require_array(manifest.get("artifacts"), "artifacts")
    if not artifacts:
        raise VerificationError("manifest contains no artifacts")
    seen_paths: set[str] = set()
    total_bytes = 0
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        relative_path, size = _validate_artifact(artifact, index, root)
        if relative_path in seen_paths:
            raise VerificationError(f"duplicate artifact path: {relative_path}")
        seen_paths.add(relative_path)
        total_bytes += size
    return VerificationResult(len(artifacts), total_bytes)


def verify_complete_matrix(path: Path) -> None:
    manifest = _load_manifest(path)
    if manifest.get("corpus") != "rust-eh":
        raise VerificationError("unsupported corpus identity")
    artifacts = _require_array(manifest.get("artifacts"), "artifacts")

    crates_by_cell: dict[str, set[str]] = {}
    paths: set[str] = set()
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_object(raw_artifact, f"artifacts[{index}]")
        try:
            key = rust_matrix.artifact_cell_key(artifact)
        except ValueError as error:
            raise VerificationError(str(error)) from error
        crate_name = _require_string(artifact, "crate_name", f"artifacts[{index}]")
        path_text = _require_string(artifact, "path", f"artifacts[{index}]")
        if path_text in paths:
            raise VerificationError(f"duplicate artifact path: {path_text}")
        paths.add(path_text)
        crates = crates_by_cell.setdefault(key, set())
        if crate_name in crates:
            raise VerificationError(f"duplicate crate {crate_name!r} in cell {key}")
        crates.add(crate_name)

    expected_by_cell = {
        cell.key: set(cell.artifact_names) for cell in rust_matrix.expected_cells()
    }
    if set(crates_by_cell) != set(expected_by_cell):
        missing = sorted(set(expected_by_cell) - set(crates_by_cell))
        extra = sorted(set(crates_by_cell) - set(expected_by_cell))
        raise VerificationError(
            f"incomplete rust-eh matrix; missing={missing}, extra={extra}"
        )
    for key, crates in crates_by_cell.items():
        expected = expected_by_cell[key]
        if crates != expected:
            raise VerificationError(
                f"matrix cell {key} crate set differs: "
                f"missing={sorted(expected - crates)}, extra={sorted(crates - expected)}"
            )
    expected_count = sum(len(names) for names in expected_by_cell.values())
    if len(artifacts) != expected_count:
        raise VerificationError(
            f"matrix contains {len(artifacts)} artifacts, expected {expected_count}"
        )


def merge_manifests(
    fragment_paths: list[Path], output_path: Path, root: Path
) -> VerificationResult:
    if not fragment_paths:
        raise VerificationError("no manifest fragments were found")
    envelopes: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for fragment_path in sorted(fragment_paths, key=lambda item: item.as_posix()):
        verify_manifest(fragment_path, root)
        fragment = _load_manifest(fragment_path)
        envelopes.append(
            {
                "schema_version": fragment["schema_version"],
                "corpus": fragment["corpus"],
                "producer": fragment["producer"],
            }
        )
        artifacts.extend(_require_array(fragment.get("artifacts"), "artifacts"))

    # Every cell pins the same compiler, so the envelope has to be identical
    # across fragments. Anything that legitimately differs between the three
    # runner operating systems lives on the artifact instead.
    first = envelopes[0]
    for envelope in envelopes[1:]:
        if envelope != first:
            raise VerificationError("manifest fragments have inconsistent envelopes")

    merged = dict(first)
    merged["artifacts"] = sorted(
        artifacts, key=lambda entry: str(entry.get("path", ""))
    )
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
