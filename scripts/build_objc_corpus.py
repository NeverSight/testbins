#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Build and validate one cell of the Objective-C exception corpus.

One cell is one (runtime, target) pair. It produces all six variants plus a
manifest fragment describing them. The fragment is verified before the script
exits, so a cell that cannot prove its own output never reaches assembly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import objc_matrix as matrix
from verify_objc_corpus import VerificationError, verify_manifest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_APPLE_CLANG_BANNER_RE = re.compile(
    r"^Apple clang version ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)"
)
_RUN_TIMEOUT_SECONDS = 300


class BuildError(RuntimeError):
    """Raised when a cell cannot be built or does not behave as declared."""


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | None = None,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    print(f"> {printable}", flush=True)
    environment = None
    if extra_environment:
        environment = {**os.environ, **extra_environment}
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildError(f"{printable}: {error}") from error
    if completed.stdout:
        print(completed.stdout.rstrip(), flush=True)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise BuildError(f"{printable} exited with {completed.returncode}")
    return completed


def read_toolchain_identity(cell: matrix.MatrixCell) -> dict[str, str]:
    """Read Apple's exact clang release and its traceable banner."""

    if shutil.which(cell.driver) is None:
        raise BuildError(f"{cell.driver!r} is not on PATH")
    version = _run([cell.driver, "-dumpversion"], cwd=_REPOSITORY_ROOT).stdout.strip()
    if not _VERSION_RE.fullmatch(version):
        raise BuildError(
            f"{cell.driver} -dumpversion reported {version!r}, "
            "which is not an exact three-part release"
        )
    if not version.startswith(cell.version_prefix):
        raise BuildError(
            f"{cell.driver} is {version}, but the matrix pins "
            f"{cell.version_prefix!r} for {cell.key}"
        )

    banner = _run([cell.driver, "--version"], cwd=_REPOSITORY_ROOT).stdout
    version_string = banner.splitlines()[0].strip() if banner else ""
    match = _APPLE_CLANG_BANNER_RE.match(version_string)
    if match is None:
        raise BuildError(
            f"{cell.driver} --version did not identify Apple clang: {version_string!r}"
        )
    if match.group(1) != version:
        raise BuildError(
            f"{cell.driver} -dumpversion reported {version}, but its banner reports "
            f"{match.group(1)}"
        )
    return {"version": version, "version_string": version_string}


def repository_revision() -> str:
    revision = os.environ.get("GITHUB_SHA", "")
    if not _REVISION_RE.fullmatch(revision):
        completed = _run(["git", "-C", str(_REPOSITORY_ROOT), "rev-parse", "HEAD"])
        revision = completed.stdout.strip()
    if not _REVISION_RE.fullmatch(revision):
        raise BuildError("cannot determine the producer repository revision")
    return revision


def runner_image() -> str:
    image_os = os.environ.get("ImageOS", "")
    image_version = os.environ.get("ImageVersion", "")
    if image_os and image_version:
        return f"{image_os}-{image_version}"
    if image_os:
        return image_os
    return f"local-{platform.system().lower()}-{platform.machine().lower()}"


def build_artifact(
    cell: matrix.MatrixCell, variant: matrix.Variant, output_root: Path
) -> Path:
    """Compile, link, and optionally strip one Objective-C executable."""

    directory = output_root / cell.relative_directory(variant)
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / cell.artifact_filename(variant)
    flags = matrix.compiler_flags(cell, variant, str(_REPOSITORY_ROOT))
    command = [cell.driver, *flags, "-o", str(output), variant.source]
    _run(
        command,
        cwd=_REPOSITORY_ROOT,
        extra_environment=matrix.build_environment(),
    )
    if not output.is_file():
        raise BuildError(f"{cell.driver} produced no file at {output}")

    if variant.stripped:
        if shutil.which(cell.strip_tool) is None:
            raise BuildError(f"{cell.strip_tool!r} is not on PATH")
        _run([cell.strip_tool, str(output)], cwd=_REPOSITORY_ROOT)
    return output


def run_probe(cell: matrix.MatrixCell, executable: Path) -> None:
    """Run a native executable and require its self-test marker."""

    try:
        completed = subprocess.run(
            [str(executable)],
            cwd=str(executable.parent),
            check=False,
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildError(f"{executable.name}: {error}") from error
    if completed.stdout:
        print(completed.stdout.rstrip(), flush=True)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise BuildError(
            f"{executable.name} exited with {completed.returncode} on {cell.target}"
        )
    if matrix.PROBE_PASS_MARKER not in completed.stdout:
        raise BuildError(f"{executable.name} did not report a passing run")


def artifact_record(
    cell: matrix.MatrixCell,
    variant: matrix.Variant,
    path: Path,
    output_root: Path,
    version: str,
    image: str,
) -> dict[str, object]:
    payload = path.read_bytes()
    build = matrix.build_contract(cell, variant, str(_REPOSITORY_ROOT))
    build.update(
        {
            "runner_image": image,
            "runner_os": cell.runner_os,
            "runner_arch": cell.runner_arch,
        }
    )
    return {
        "path": path.relative_to(output_root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "runtime": cell.runtime,
        "toolchain_version": version,
        "target": cell.target,
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "program": variant.program,
        "arc": variant.arc,
        "exceptions": variant.exceptions,
        "optimization": variant.optimization,
        "stripped": variant.stripped,
        "execution": cell.execution(variant),
        "build": build,
        "evidence": matrix.evidence_contract(cell, variant),
        "neverd": matrix.neverd_contract(cell, variant),
    }


def _write_json(output_path: Path, payload: dict[str, object]) -> None:
    """Atomically replace a JSON file, never leaving a partial fragment."""

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


def build_cell(cell: matrix.MatrixCell, output_root: Path) -> Path:
    identity = read_toolchain_identity(cell)
    image = runner_image()
    built: list[tuple[matrix.Variant, Path]] = []
    for variant in cell.variants:
        path = build_artifact(cell, variant, output_root)
        if cell.native:
            run_probe(cell, path)
        built.append((variant, path))

    artifacts = [
        artifact_record(cell, variant, path, output_root, identity["version"], image)
        for variant, path in built
    ]
    artifacts.sort(key=lambda entry: str(entry["path"]))
    fragment: dict[str, object] = {
        "schema_version": 1,
        "corpus": matrix.CORPUS_NAME,
        "producer": {
            "repository_revision": repository_revision(),
            "toolchains": [
                {
                    **matrix.toolchain_contract(cell),
                    "version": identity["version"],
                    "version_string": identity["version_string"],
                }
            ],
        },
        "artifacts": artifacts,
    }
    fragment_path = output_root / "fragments" / f"{cell.key}.json"
    _write_json(fragment_path, fragment)
    return fragment_path


def describe(cell: matrix.MatrixCell) -> dict[str, object]:
    return {
        "cell_name": cell.key,
        "runtime": cell.runtime,
        "target": cell.target,
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "runner_os": cell.runner_os,
        "runner_arch": cell.runner_arch,
        "runs_on": cell.runs_on,
        "native": cell.native,
        "driver": cell.driver,
        "strip_tool": cell.strip_tool,
        "version_prefix": cell.version_prefix,
        "apt_packages": list(cell.apt_packages),
        "xcode_path": cell.xcode_path,
        "artifacts": [
            {
                "program": variant.program,
                "runtime": cell.runtime,
                "arc": variant.arc,
                "exceptions": variant.exceptions,
                "optimization": variant.optimization,
                "stripped": variant.stripped,
                "execution": cell.execution(variant),
                "path": cell.artifact_path(variant),
                "source": variant.source,
                "build": matrix.build_contract(cell, variant, "/checkout"),
                "evidence": matrix.evidence_contract(cell, variant),
                "neverd": matrix.neverd_contract(cell, variant),
            }
            for variant in cell.variants
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--describe-only",
        action="store_true",
        help="print the cell's resolved configuration and build nothing",
    )
    args = parser.parse_args()

    try:
        cell = matrix.validate_cell(args.runtime, args.target)
    except matrix.MatrixError as error:
        raise SystemExit(f"error: {error}") from error

    if args.describe_only:
        print(json.dumps(describe(cell), sort_keys=True))
        return 0

    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    fragment_path = build_cell(cell, output_root)
    result = verify_manifest(fragment_path, output_root)
    print(
        f"built and verified cell {cell.key}: {result.artifact_count} artifact(s), "
        f"{result.total_bytes} byte(s)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, VerificationError) as error:
        raise SystemExit(f"error: {error}") from error
