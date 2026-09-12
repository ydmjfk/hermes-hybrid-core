#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-001 ~ SEC-004: Path Traversal & Sandbox Escape Test Matrix
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hermes_core.path_sanitizer import (
    PathSanitizer,
    PathSanitizerError,
    PathTraversalError,
    SensitivePathBlockedError
)


class TestPathTraversalSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.sanitizer = PathSanitizer(workspace_root=self.workspace)
        (self.workspace / "allowed.txt").write_text("safe content", encoding="utf-8")
        (self.workspace / "sub_dir").mkdir(exist_ok=True)
        (self.workspace / "sub_dir" / "file.txt").write_text("sub content", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sec_001_path_traversal(self):
        """SEC-001: Standard Path Traversal Blocked"""
        with self.assertRaises((PathTraversalError, PathSanitizerError)):
            self.sanitizer.sanitize_path("../../etc/passwd")

        with self.assertRaises((PathTraversalError, PathSanitizerError)):
            self.sanitizer.sanitize_path("sub_dir/../../secret.txt")

    def test_sec_002_url_encoded_traversal(self):
        """SEC-002: URL Encoded Traversal Blocked"""
        with self.assertRaises((PathTraversalError, PathSanitizerError)):
            self.sanitizer.sanitize_path("%2e%2e/secret.txt")

        with self.assertRaises((PathTraversalError, PathSanitizerError)):
            self.sanitizer.sanitize_path("%2e%2e%2f%2e%2e%2fetc/passwd")

    def test_sec_003_unicode_traversal(self):
        """SEC-003: Unicode Normalized Traversal Blocked"""
        # Full-width periods: \uff0e\uff0e/
        fullwidth_traversal = "\uff0e\uff0e/secret.txt"
        with self.assertRaises((PathTraversalError, PathSanitizerError)):
            self.sanitizer.sanitize_path(fullwidth_traversal)

    def test_sec_004_symlink_escape(self):
        """SEC-004: Symlink Escape Outside Workspace Blocked"""
        outside_file = Path(tempfile.gettempdir()) / f"outside_secret_{os.getpid()}.txt"
        outside_file.write_text("super secret outside", encoding="utf-8")
        symlink_path = self.workspace / "symlink_to_outside"

        try:
            os.symlink(outside_file, symlink_path)
            with self.assertRaises((PathTraversalError, PathSanitizerError)):
                self.sanitizer.sanitize_path("symlink_to_outside")
        finally:
            if outside_file.exists():
                outside_file.unlink()


if __name__ == "__main__":
    unittest.main()
