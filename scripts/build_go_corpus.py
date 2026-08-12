#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Build one Go corpus cell: every artifact a single pinned toolchain owns.

A cell is a toolchain rather than a target because Go cross-compiles cleanly
with `CGO_ENABLED=0`, so one ubuntu x64 host with one installed release can
produce the ELF, PE, and Mach-O artifacts for that release.  Doing it that way
also removes the only thing that could make the images differ for reasons the
manifest does not record: they all come out of the same toolchain on the same
machine in the same run.

The manifest fragment this writes is not a description of what the builder
intended.  Every structural field in it is read back out of the linked image by
`verify_go_corpus`, and the fragment is then re-verified before the cell is
considered built.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from go_matrix import (
    MODULE_PACKAGE,
    MatrixError,
    Variant,
    release_for,
    variants_for_version,
)
from verify_go_corpus import (
    VerificationError,
    locate_pclntab,
    parse_object,
    verify_manifest,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_MODULE_ROOT = _REPOSITORY_ROOT / "sources/go-eh"
_MODULE_PATH = "neversight.dev/goeh"

_GO_ENV_KEYS = (
    "GOAMD64",
    "GOARM64",
    "GOEXPERIMENT",
    "GOFLAGS",
    "GOHOSTARCH",
    "GOHOSTOS",
    "GOTOOLCHAIN",
    "GOVERSION",
)

#: Floors for the counts NeverD is expected to recover.  They are deliberately
#: far below what `sources/go-eh/cmd/eh_probe` produces -- the probe alone has
#: eleven recover sites and ten heap-defer sites before the runtime is linked
#: in -- because the point is to catch a decoder that recovered nothing, not to
#: pin a number that shifts with every Go release.
_MIN_GO_FUNCTIONS = 800
_MIN_DEFER_SITES = 5
_MIN_RECOVER_SITES = 8
_MIN_PANIC_SITES = 20
#: `eh_probe` compiles thirteen frames with FUNCDATA_OpenCodedDeferInfo at
#: default optimization; the runtime adds many more.
_MIN_OPEN_CODED_DEFER_FUNCS = 12

class BuildError(RuntimeError):
    """Raised when a cell cannot be produced as specified."""


def _run(
    command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None
) -> str:
    printable = " ".join(command)
    print(f"> {printable}", flush=True)
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr, flush=True)
    if result.returncode != 0:
        raise BuildError(f"{printable} failed with exit code {result.returncode}")
    return result.stdout


def _base_environment() -> dict[str, str]:
    """A minimal environment so nothing the runner exports reaches the build."""

    environment: dict[str, str] = {}
    for key in ("PATH", "HOME", "TMPDIR", "GOROOT", "GOPATH", "GOCACHE", "GOMODCACHE"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment["GOFLAGS"] = ""
    environment["GO111MODULE"] = "on"
    environment["GOPROXY"] = "off"
    # Pinned here as well as in the per-artifact build environment so that the
    # `go env` this records and the `go build` it describes cannot disagree,
    # and so that no toolchain switch can substitute a release the manifest
    # does not name.  Releases older than Go 1.21 ignore both variables.
    environment["GOTOOLCHAIN"] = "local"
    environment["GOWORK"] = "off"
    return environment


def _go_binary() -> str:
    binary = shutil.which("go")
    if binary is None:
        raise BuildError("go is not on PATH")
    return binary


def _module_go_directive() -> str:
    text = (_MODULE_ROOT / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"^go ([0-9]+\.[0-9]+)$", text, re.MULTILINE)
    if match is None:
        raise BuildError("sources/go-eh/go.mod has no plain major.minor go directive")
    return match.group(1)


def _toolchain_record(go: str, version: str) -> dict[str, object]:
    """Capture the toolchain identity exactly as the toolchain reports it."""

    environment = _base_environment()
    version_string = _run([go, "version"], env=environment).strip()
    if f"go{version} " not in f"{version_string} ":
        raise BuildError(
            f"the toolchain on PATH reports {version_string!r}, but this cell "
            f"builds Go {version}"
        )
    values = _run([go, "env", *_GO_ENV_KEYS], env=environment).splitlines()
    if len(values) != len(_GO_ENV_KEYS):
        raise BuildError("go env did not report one line per requested variable")
    return {
        "go_version": version,
        "go_version_string": version_string,
        "go_env": {
            key: value.strip() for key, value in zip(_GO_ENV_KEYS, values, strict=True)
        },
    }


def _repository_revision() -> str:
    revision = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        revision = _run(
            ["git", "-C", str(_REPOSITORY_ROOT), "rev-parse", "HEAD"]
        ).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise BuildError("cannot determine the producer repository revision")
    return revision.lower()


def _runner_image() -> str:
    image_os = os.environ.get("ImageOS", "")
    image_version = os.environ.get("ImageVersion", "")
    if image_os and image_version:
        return f"{image_os}-{image_version}"
    return image_os or "ubuntu-24.04"


def _expected_required_sections(variant: Variant) -> list[str]:
    object_format = variant.target.object_format
    if object_format == "elf":
        return sorted((variant.elf_pclntab_section, ".noptrdata", ".text"))
    if object_format == "macho":
        return sorted(("__gopclntab", "__noptrdata", "__text"))
    return sorted((".rdata", ".data", ".text"))


def _pclntab_location(variant: Variant) -> tuple[str, bool]:
    object_format = variant.target.object_format
    if object_format == "elf":
        return variant.elf_pclntab_section, True
    if object_format == "macho":
        return "__gopclntab", True
    return ".rdata", False


def _build_one(go: str, variant: Variant, output_root: Path) -> Path:
    destination = output_root / Path(*variant.path.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    environment = _base_environment()
    environment.update(variant.build_env())
    _run(
        [go, "build", *variant.build_flags(), "-o", str(destination), MODULE_PACKAGE],
        env=environment,
        cwd=_MODULE_ROOT,
    )
    if not destination.is_file():
        raise BuildError(f"go build produced no file at {destination}")
    return destination


def _execute(variant: Variant, path: Path) -> None:
    """Run the artifact when the build host can, because the probe self-checks.

    `eh_probe` exits non-zero unless every panic it raises was recovered where
    it expected, so running it is the difference between a corpus of images
    that link and a corpus of images whose runtime metadata actually drove a
    real unwind.
    """

    os.chmod(path, 0o755)
    result = subprocess.run(
        [str(path)], capture_output=True, text=True, check=False, timeout=120
    )
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.stderr:
        print(result.stderr.rstrip(), flush=True)
    if result.returncode != 0:
        raise BuildError(
            f"{variant.key} exited with code {result.returncode}; the probe's "
            "own defer/recover assertions did not hold"
        )


def _artifact_record(variant: Variant, path: Path, output_root: Path) -> dict[str, object]:
    payload = path.read_bytes()
    image = parse_object(payload, variant.target.object_format)
    section_name, at_section_start = _pclntab_location(variant)
    header = locate_pclntab(image, section_name, at_section_start)

    release = variant.release
    optimized = variant.optimization == "default"
    return {
        "path": path.relative_to(output_root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "goos": variant.goos,
        "goarch": variant.goarch,
        "go_version": variant.go_version,
        "object_format": variant.target.object_format,
        "buildmode": variant.buildmode,
        "cgo_enabled": variant.cgo_enabled,
        "stripped": variant.stripped,
        "optimization": variant.optimization,
        "build": {
            "package": MODULE_PACKAGE,
            "flags": variant.build_flags(),
            "env": variant.build_env(),
            "execution": variant.execution,
        },
        "evidence": {
            "required_sections": _expected_required_sections(variant),
            "pclntab_section": section_name,
            "pclntab_at_section_start": at_section_start,
            "pclntab_magic": header.magic,
            "pclntab_min_lc": header.min_lc,
            "pclntab_ptr_size": header.pointer_size,
            "pclntab_function_count": header.function_count,
            "symbol_table": image.symbol_table_kind(),
            "gofunc_symbol": image.gofunc_symbol(),
            "native_unwind_sections": image.native_unwind_sections(),
        },
        "neverd": {
            "validation_level": (
                "table-only" if release.pclntab_version == "go1.2" else "runtime-graph"
            ),
            "allowed_parse_status": (
                ["complete"] if release.has_unsafe_point_table else ["partial"]
            ),
            "expected_pclntab_version": release.pclntab_version,
            "min_go_functions": _MIN_GO_FUNCTIONS,
            "min_defer_sites": _MIN_DEFER_SITES,
            "min_recover_sites": _MIN_RECOVER_SITES,
            "min_panic_sites": _MIN_PANIC_SITES,
            "min_open_coded_defer_funcs": (
                _MIN_OPEN_CODED_DEFER_FUNCS if optimized else 0
            ),
            "requires_moduledata": release.pclntab_version in ("go1.18", "go1.20"),
        },
    }


def build_cell(
    go_version: str, output_root: Path, *, execute: bool = True
) -> Path:
    release = release_for(go_version)
    variants = variants_for_version(release.version)
    if not variants:
        raise BuildError(f"Go {release.version} owns no corpus artifacts")

    go = _go_binary()
    toolchain = _toolchain_record(go, release.version)
    output_root.mkdir(parents=True, exist_ok=True)

    artifacts: list[dict[str, object]] = []
    for variant in variants:
        path = _build_one(go, variant, output_root)
        if execute and variant.executable_here:
            _execute(variant, path)
        artifacts.append(_artifact_record(variant, path, output_root))

    fragment = {
        "schema_version": 1,
        "corpus": "go-eh",
        "producer": {
            "repository_revision": _repository_revision(),
            "runner_image": _runner_image(),
            "runner_os": "linux",
            "runner_arch": "x64",
            "module_path": _MODULE_PATH,
            "module_go_directive": _module_go_directive(),
            "package": MODULE_PACKAGE,
            "toolchains": [toolchain],
        },
        "artifacts": artifacts,
    }
    fragment_root = output_root / "fragments"
    fragment_root.mkdir(parents=True, exist_ok=True)
    fragment_path = fragment_root / f"{release.label}.json"
    fragment_path.write_text(
        json.dumps(fragment, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = verify_manifest(fragment_path, output_root)
    print(
        f"built and verified cell {release.label}: {result.artifact_count} "
        f"artifact(s), {result.total_bytes} byte(s)"
    )
    return fragment_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--no-execute",
        action="store_true",
        help="skip running the host-native artifacts",
    )
    parser.add_argument(
        "--validate-configuration-only",
        action="store_true",
        help="print the cell plan as JSON without invoking the toolchain",
    )
    args = parser.parse_args()

    release = release_for(args.go_version)
    variants = variants_for_version(release.version)
    if args.validate_configuration_only:
        print(
            json.dumps(
                {
                    "cell_name": release.label,
                    "go_version": release.version,
                    "pclntab_version": release.pclntab_version,
                    "pclntab_magic": release.pclntab_magic,
                    "artifact_count": len(variants),
                    "artifacts": [
                        {
                            "key": variant.key,
                            "path": variant.path,
                            "flags": variant.build_flags(),
                            "env": variant.build_env(),
                            "execution": variant.execution,
                            "required_sections": _expected_required_sections(variant),
                            "pclntab_section": _pclntab_location(variant)[0],
                        }
                        for variant in variants
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    build_cell(release.version, args.output_root, execute=not args.no_execute)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, MatrixError, VerificationError) as error:
        raise SystemExit(f"error: {error}") from error
