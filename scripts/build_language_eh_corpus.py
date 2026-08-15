#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Build, execute when native, and validate one Ada/D EH corpus cell."""

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

import ada_d_eh_matrix as matrix
from verify_ada_d_eh_corpus import VerificationError, verify_manifest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"\b(?:v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b")
RUN_TIMEOUT_SECONDS = 300


class BuildError(RuntimeError):
    """Raised when a cell cannot prove its declared output."""


def run(
    command: list[str],
    *,
    cwd: Path = REPOSITORY_ROOT,
    environment: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"> {' '.join(command)}", flush=True)
    merged_environment = {**os.environ, **(environment or {})}
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=merged_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildError(f"{command[0]}: {error}") from error
    if completed.stdout:
        print(completed.stdout.rstrip(), flush=True)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise BuildError(f"{command[0]} exited with {completed.returncode}")
    return completed


def read_toolchain_identity(cell: matrix.MatrixCell) -> dict[str, str]:
    compiler = shutil.which(cell.compiler)
    if compiler is None:
        raise BuildError(f"{cell.compiler!r} is not on PATH")
    banner = run([compiler, "--version"]).stdout
    first_line = banner.splitlines()[0].strip() if banner else ""
    match = VERSION_RE.search(first_line)
    if not first_line or match is None:
        raise BuildError(f"{cell.compiler} reported no parseable version")
    version = match.group(1)
    if not version.startswith(cell.version_prefix):
        raise BuildError(
            f"{cell.compiler} is {version}, matrix pins {cell.version_prefix!r}"
        )
    return {
        "version": version,
        "version_string": first_line,
        "resolved_compiler": compiler,
    }


def repository_revision() -> str:
    revision = os.environ.get("GITHUB_SHA", "")
    if not REVISION_RE.fullmatch(revision):
        revision = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    if not REVISION_RE.fullmatch(revision):
        raise BuildError("cannot determine producer repository revision")
    return revision


def runner_image() -> str:
    image_os = os.environ.get("ImageOS", "")
    image_version = os.environ.get("ImageVersion", "")
    if image_os and image_version:
        return f"{image_os}-{image_version}"
    return f"local-{platform.system().lower()}-{platform.machine().lower()}"


def build_artifact(
    cell: matrix.MatrixCell,
    variant: matrix.Variant,
    output_root: Path,
    compiler: str,
) -> Path:
    output = output_root / cell.artifact_path(variant)
    output.parent.mkdir(parents=True, exist_ok=True)
    source = REPOSITORY_ROOT / cell.source_path
    flags = list(matrix.compiler_flags(cell, variant, str(REPOSITORY_ROOT)))
    environment = dict(matrix.BUILD_ENVIRONMENT)

    if cell.toolchain == "gnat":
        with tempfile.TemporaryDirectory(prefix="ada-eh-") as temporary:
            command = [compiler, *flags, str(source), "-o", str(output)]
            run(command, cwd=Path(temporary), environment=environment)
    elif cell.toolchain == "gdc":
        command = [compiler, *flags, cell.source_path, "-o", str(output)]
        run(command, environment=environment)
    else:
        command = [compiler, *flags, cell.source_path, f"-of={output}"]
        run(command, environment=environment)

    if not output.is_file():
        raise BuildError(f"{cell.compiler} produced no file at {output}")
    output.chmod(0o755)
    return output


def run_probe(executable: Path) -> None:
    completed = run(
        [str(executable)],
        cwd=executable.parent,
        environment=dict(matrix.BUILD_ENVIRONMENT),
        timeout=RUN_TIMEOUT_SECONDS,
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
    build = matrix.build_contract(cell, variant, str(REPOSITORY_ROOT))
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
        "source_language": cell.language,
        "optimization": variant.optimization,
        "execution": cell.execution(),
        "exception_model": "itanium-dwarf",
        "build": build,
        "evidence": matrix.evidence_contract(cell),
        "neverd": matrix.neverd_contract(cell),
    }


def describe(cell: matrix.MatrixCell) -> dict[str, object]:
    return {
        "cell_name": cell.key,
        "toolchain": cell.toolchain,
        "target": cell.target,
        "runs_on": cell.runs_on,
        "compiler": cell.compiler,
        "apt_packages": list(cell.apt_packages),
        "dlang_compiler": cell.dlang_compiler,
        "artifacts": [
            {
                "path": cell.artifact_path(variant),
                "optimization": variant.optimization,
                "execution": cell.execution(),
                "source": cell.source_path,
                "build": matrix.build_contract(cell, variant, "/checkout"),
                "evidence": matrix.evidence_contract(cell),
                "neverd": matrix.neverd_contract(cell),
            }
            for variant in cell.variants
        ],
    }


def build_cell(cell: matrix.MatrixCell, output_root: Path) -> Path:
    identity = read_toolchain_identity(cell)
    image = runner_image()
    records = []
    for variant in cell.variants:
        path = build_artifact(
            cell,
            variant,
            output_root,
            identity["resolved_compiler"],
        )
        if cell.native:
            run_probe(path)
        records.append(
            artifact_record(
                cell,
                variant,
                path,
                output_root,
                identity["version"],
                image,
            )
        )

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
        "artifacts": sorted(records, key=lambda entry: str(entry["path"])),
    }
    fragment_root = output_root / "fragments"
    fragment_root.mkdir(parents=True, exist_ok=True)
    fragment_path = fragment_root / f"{cell.key}.json"
    fragment_path.write_text(
        json.dumps(fragment, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    verify_manifest(fragment_path, output_root)
    return fragment_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--describe-only", action="store_true")
    args = parser.parse_args()
    cell = matrix.validate_cell(args.toolchain, args.target)
    if args.describe_only:
        print(json.dumps(describe(cell), indent=2, sort_keys=True))
        return 0
    if args.output_root is None:
        parser.error("--output-root is required unless --describe-only is set")
    fragment = build_cell(cell, args.output_root.resolve())
    print(f"validated {cell.key}: {fragment}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, VerificationError, matrix.MatrixError) as error:
        raise SystemExit(f"error: {error}") from error
