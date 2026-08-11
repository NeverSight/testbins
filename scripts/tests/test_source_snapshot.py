# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

import hashlib
import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[2]
SNAPSHOT_ROOT = REPOSITORY_ROOT / "sources/windows-seh-tests"


class SourceSnapshotTests(unittest.TestCase):
    def test_third_party_license_copy_matches_snapshot(self) -> None:
        license_copy = REPOSITORY_ROOT / "LICENSES/windows-seh-tests-MIT.txt"
        self.assertEqual(
            license_copy.read_text(encoding="utf-8"),
            (SNAPSHOT_ROOT / "LICENSE").read_text(encoding="utf-8"),
        )

    def test_snapshot_matches_pinned_file_manifest(self) -> None:
        metadata_path = SNAPSHOT_ROOT / "UPSTREAM.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["schema_version"], 1)
        self.assertEqual(
            metadata["revision"], "2e8b7bb654d9aebf03f28801c4b1400489ba6a0c"
        )
        self.assertEqual(metadata["license"], "MIT")

        declared = metadata["files"]
        actual = {
            path.relative_to(SNAPSHOT_ROOT).as_posix()
            for path in SNAPSHOT_ROOT.rglob("*")
            if path.is_file() and path.name != "UPSTREAM.json"
        }
        self.assertEqual(set(declared), actual)
        for relative_path, expected_hash in declared.items():
            payload = (SNAPSHOT_ROOT / relative_path).read_bytes()
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(),
                expected_hash,
                relative_path,
            )


if __name__ == "__main__":
    unittest.main()
