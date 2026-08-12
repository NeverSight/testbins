#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Build and validate one cell of the C++ Itanium exception corpus.

One cell is one (toolchain, target) pair, and it produces all eight variants
plus a manifest fragment describing them.  The fragment is verified before the
script exits, so a cell that cannot prove its own output never reaches the
assembly step.

The script is the same on both runner operating systems: everything
platform-specific is a property of the cell in `cxx_itanium_matrix.py`, not a
branch here.
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
from pathlib import Path

import cxx_itanium_matrix as matrix
from verify_cxx_itanium_corpus import VerificationError, verify_manifest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
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
    """Read the compiler's own version and check it against the cell's pin.

    GCC reports a three-part release only for `-dumpfullversion`; clang has no
    such option and answers `-dumpversion` with the full release.  Both are
    cross-checked against the first line of `--version`, which is what a human
    reading the manifest will recognize.
    """

    for driver in (cell.cxx_driver, cell.c_driver):
        if shutil.which(driver) is None:
            packages = " ".join(cell.apt_packages) or "the cell's toolchain"
            raise BuildError(f"{driver!r} is not on PATH; install {packages}")

    option = "-dumpfullversion" if cell.toolchain == "gcc" else "-dumpversion"
    version = _run([cell.cxx_driver, option], cwd=_REPOSITORY_ROOT).stdout.strip()
    if not _VERSION_RE.fullmatch(version):
        raise BuildError(
            f"{cell.cxx_driver} {option} reported {version!r}, not an x.y.z release"
        )
    if not version.startswith(cell.version_prefix):
        raise BuildError(
            f"{cell.cxx_driver} is {version}, but the matrix pins "
            f"{cell.version_prefix!r} for {cell.key}"
        )
    c_version = _run([cell.c_driver, option], cwd=_REPOSITORY_ROOT).stdout.strip()
    if c_version != version:
        raise BuildError(
            f"{cell.c_driver} is {c_version} but {cell.cxx_driver} is {version}; "
            "one cell must be one compiler"
        )
    banner = _run([cell.cxx_driver, "--version"], cwd=_REPOSITORY_ROOT).stdout
    version_string = banner.splitlines()[0].strip() if banner else ""
    if not version_string:
        raise BuildError(f"{cell.cxx_driver} --version printed nothing")
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
    """Compile, link, and -- where the variant says so -- strip one artifact."""

    directory = output_root / cell.relative_directory(variant)
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / cell.artifact_filename(variant)

    inputs = [variant.source]
    for dependency in matrix.linked_artifacts(cell, variant):
        resolved = output_root / dependency
        if not resolved.is_file():
            raise BuildError(
                f"{variant.key} links {dependency}, which this cell has not built"
            )
        inputs.append(str(resolved))

    flags = matrix.compiler_flags(cell, variant, str(_REPOSITORY_ROOT))
    command = [cell.driver(variant), *flags, "-o", str(output), *inputs]
    _run(
        command,
        cwd=_REPOSITORY_ROOT,
        extra_environment=matrix.build_environment(),
    )
    if not output.is_file():
        raise BuildError(f"{cell.driver(variant)} produced no file at {output}")

    if variant.stripped:
        # `ld64` has no equivalent of GNU `ld -s`, so every target strips the
        # same way: after the link, with the target's own strip.
        if shutil.which(cell.strip_tool) is None:
            raise BuildError(f"{cell.strip_tool!r} is not on PATH")
        _run([cell.strip_tool, str(output)], cwd=_REPOSITORY_ROOT)
    return output


def run_probe(cell: matrix.MatrixCell, executable: Path) -> None:
    """Run an executable probe, which is also the corpus's own runtime test."""

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
        "toolchain": cell.toolchain,
        "toolchain_version": version,
        "target": cell.target,
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "program": variant.program,
        "artifact_kind": variant.artifact_kind,
        "source_language": variant.source_language,
        "exceptions": variant.exceptions,
        "optimization": variant.optimization,
        "stripped": variant.stripped,
        "execution": cell.execution(variant),
        "build": build,
        "evidence": matrix.evidence_contract(cell, variant),
        "neverd": matrix.neverd_contract(cell, variant),
    }


def _build_order(cell: matrix.MatrixCell) -> list[matrix.Variant]:
    """Shared objects first, because an executable may link one."""

    return sorted(
        cell.variants,
        key=lambda variant: (variant.artifact_kind != "shared", variant.key),
    )


def build_cell(cell: matrix.MatrixCell, output_root: Path) -> Path:
    identity = read_toolchain_identity(cell)
    image = runner_image()

    built: list[tuple[matrix.Variant, Path]] = []
    for variant in _build_order(cell):
        built.append((variant, build_artifact(cell, variant, output_root)))
    # Running happens after every artifact exists, because the C probe loads
    # the shared library from the directory beside its own.
    for variant, path in built:
        if cell.execution(variant) == "passed":
            run_probe(cell, path)

    artifacts = [
        artifact_record(cell, variant, path, output_root, identity["version"], image)
        for variant, path in built
    ]
    artifacts.sort(key=lambda entry: str(entry["path"]))

    fragment = {
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
    fragment_root = output_root / "fragments"
    fragment_root.mkdir(parents=True, exist_ok=True)
    fragment_path = fragment_root / f"{cell.key}.json"
    with fragment_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(fragment, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return fragment_path


def describe(cell: matrix.MatrixCell) -> dict[str, object]:
    return {
        "cell_name": cell.key,
        "toolchain": cell.toolchain,
        "target": cell.target,
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "gnu_triple": cell.gnu_triple,
        "runner_os": cell.runner_os,
        "runner_arch": cell.runner_arch,
        "runs_on": cell.runs_on,
        "native": cell.native,
        "cxx_driver": cell.cxx_driver,
        "c_driver": cell.c_driver,
        "strip_tool": cell.strip_tool,
        "version_prefix": cell.version_prefix,
        "apt_packages": list(cell.apt_packages),
        "xcode_path": cell.xcode_path,
        "artifacts": [
            {
                "program": variant.program,
                "artifact_kind": variant.artifact_kind,
                "source_language": variant.source_language,
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
            for variant in _build_order(cell)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--describe-only",
        action="store_true",
        help="print the cell's resolved configuration and build nothing",
    )
    args = parser.parse_args()

    try:
        cell = matrix.validate_cell(args.toolchain, args.target)
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
