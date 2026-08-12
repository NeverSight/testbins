#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Build and validate one cell of the Rust exception corpus.

One cell is one (target, panic strategy, optimization) triple, and it produces
both crates plus a manifest fragment describing them. The fragment is verified
before the script exits, so a cell that cannot prove its own output never
reaches the assembly step.

The script is the same on all three runner operating systems: everything
platform-specific is a property of the target in `rust_matrix.py`, not a branch
here.
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

import rust_matrix
from verify_rust_corpus import VerificationError, verify_manifest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_RUN_TIMEOUT_SECONDS = 300


class BuildError(RuntimeError):
    """Raised when a cell cannot be built or does not behave as declared."""


def _run(
    command: list[str], *, cwd: Path | None = None, timeout: int | None = None
) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    print(f"> {printable}", flush=True)
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
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


def read_rustc_identity() -> dict[str, str]:
    """Parse `rustc -vV` into the fields the manifest records."""

    completed = _run(["rustc", "-vV"], cwd=_REPOSITORY_ROOT)
    fields: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    try:
        identity = {
            "release": fields["release"],
            "commit_hash": fields["commit-hash"],
            "commit_date": fields["commit-date"],
            "llvm_version": fields["LLVM version"],
        }
        host = fields["host"]
    except KeyError as error:
        raise BuildError(f"rustc -vV did not report {error}") from error
    if not re.fullmatch(r"[0-9a-f]{40}", identity["commit_hash"]):
        raise BuildError(
            "rustc -vV reported no commit hash; the corpus needs a traceable build"
        )
    return {**identity, "host": host}


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


def install_target(cell: rust_matrix.MatrixCell) -> None:
    """Add the cell's standard library, resolved against the pinned channel."""

    _run(["rustup", "target", "add", cell.target], cwd=_REPOSITORY_ROOT)


def require_cross_linker(cell: rust_matrix.MatrixCell) -> None:
    if cell.linker == "rustc-default":
        return
    if shutil.which(cell.linker) is None:
        packages = " ".join(cell.apt_packages) or "the target's cross toolchain"
        raise BuildError(
            f"the cross linker {cell.linker!r} is not on PATH; install {packages}"
        )


def build_artifact(
    cell: rust_matrix.MatrixCell, crate_name: str, output_root: Path
) -> Path:
    directory = output_root / cell.relative_directory(crate_name)
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / cell.artifact_filename(crate_name)
    flags = rust_matrix.rustc_flags(cell, crate_name, str(_REPOSITORY_ROOT))
    command = (
        ["rustc"] + flags + ["-o", str(output), rust_matrix.crate_source(crate_name)]
    )
    _run(command, cwd=_REPOSITORY_ROOT)
    if not output.is_file():
        raise BuildError(f"rustc produced no file at {output}")
    return output


def run_probe(cell: rust_matrix.MatrixCell, executable: Path) -> None:
    """Run the executable probe, which is also the corpus's own runtime test."""

    completed = subprocess.run(
        [str(executable)],
        cwd=str(executable.parent),
        check=False,
        capture_output=True,
        text=True,
        timeout=_RUN_TIMEOUT_SECONDS,
    )
    if completed.stdout:
        print(completed.stdout.rstrip(), flush=True)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise BuildError(
            f"{executable.name} exited with {completed.returncode} on {cell.target}"
        )
    if "rust-eh probe passed" not in completed.stdout:
        raise BuildError(f"{executable.name} did not report a passing run")


def artifact_record(
    cell: rust_matrix.MatrixCell,
    crate_name: str,
    path: Path,
    output_root: Path,
    rustc_host: str,
    image: str,
) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": path.relative_to(output_root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "architecture": cell.architecture,
        "object_format": cell.object_format,
        "target_triple": cell.target,
        "crate_name": crate_name,
        "crate_type": rust_matrix.crate_type(crate_name),
        "panic_strategy": cell.panic_strategy,
        "optimization": cell.optimization,
        "execution": cell.execution(crate_name),
        "build": {
            "edition": rust_matrix.edition(),
            "linker": cell.linker,
            "rustc_flags": rust_matrix.rustc_flags(
                cell, crate_name, str(_REPOSITORY_ROOT)
            ),
            "rustc_host": rustc_host,
            "runner_image": image,
            "runner_os": cell.runner_os,
            "runner_arch": cell.runner_arch,
        },
        "evidence": rust_matrix.evidence_contract(cell, crate_name),
        "neverd": rust_matrix.neverd_contract(cell, crate_name),
    }


def build_cell(cell: rust_matrix.MatrixCell, output_root: Path) -> Path:
    install_target(cell)
    require_cross_linker(cell)
    identity = read_rustc_identity()
    if identity["host"] != cell.rustc_host:
        raise BuildError(
            f"this runner's rustc host is {identity['host']!r}, but the matrix "
            f"places {cell.target} on a {cell.rustc_host!r} runner"
        )

    image = runner_image()
    artifacts: list[dict[str, object]] = []
    for crate_name in cell.artifact_names:
        path = build_artifact(cell, crate_name, output_root)
        if cell.execution(crate_name) == "passed":
            run_probe(cell, path)
        artifacts.append(
            artifact_record(
                cell, crate_name, path, output_root, identity["host"], image
            )
        )

    fragment = {
        "schema_version": 1,
        "corpus": "rust-eh",
        "producer": {
            "rustc": {
                "release": identity["release"],
                "commit_hash": identity["commit_hash"],
                "commit_date": identity["commit_date"],
                "llvm_version": identity["llvm_version"],
            },
            "toolchain_channel": identity["release"],
            "repository_revision": repository_revision(),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--panic-strategy", required=True, choices=("unwind", "abort"))
    parser.add_argument("--optimization", required=True, choices=("o0", "o2"))
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--describe-only",
        action="store_true",
        help="print the cell's resolved configuration and build nothing",
    )
    args = parser.parse_args()

    try:
        cell = rust_matrix.validate_cell(
            args.target, args.panic_strategy, args.optimization
        )
    except ValueError as error:
        raise SystemExit(f"error: {error}") from error

    if args.describe_only:
        print(
            json.dumps(
                {
                    "cell_name": cell.key,
                    "target": cell.target,
                    "architecture": cell.architecture,
                    "object_format": cell.object_format,
                    "runner_os": cell.runner_os,
                    "runner_arch": cell.runner_arch,
                    "runs_on": cell.runs_on,
                    "rustc_host": cell.rustc_host,
                    "native": cell.native,
                    "linker": cell.linker,
                    "apt_packages": list(cell.apt_packages),
                    "artifacts": [
                        {
                            "crate_name": crate_name,
                            "crate_type": rust_matrix.crate_type(crate_name),
                            "execution": cell.execution(crate_name),
                            "path": cell.artifact_path(crate_name),
                            "rustc_flags": rust_matrix.rustc_flags(
                                cell, crate_name, "/checkout"
                            ),
                            "evidence": rust_matrix.evidence_contract(cell, crate_name),
                            "neverd": rust_matrix.neverd_contract(cell, crate_name),
                        }
                        for crate_name in cell.artifact_names
                    ],
                },
                sort_keys=True,
            )
        )
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
