#!/usr/bin/env python3
# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

"""Merge validated Ada/D EH fragments into one canonical manifest."""

from __future__ import annotations

import argparse
from pathlib import Path

from verify_ada_d_eh_corpus import (
    VerificationError,
    merge_manifests,
    verify_complete_matrix,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--fragments", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-complete-matrix", action="store_true")
    args = parser.parse_args()

    fragments = sorted(args.fragments.glob("*.json"))
    result = merge_manifests(fragments, args.output, args.root)
    if args.require_complete_matrix:
        verify_complete_matrix(args.output)
    print(
        f"merged {len(fragments)} fragment(s): "
        f"{result.artifact_count} artifact(s), {result.total_bytes} byte(s)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
