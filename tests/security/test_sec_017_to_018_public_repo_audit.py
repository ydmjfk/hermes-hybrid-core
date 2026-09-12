#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-017 ~ SEC-018: Public Repository Cleanliness & Leakage Scan Test Matrix
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from check_security import run_public_release_audit


class TestPublicRepoAuditSecurity(unittest.TestCase):

    def test_sec_017_public_repo_private_path_clean(self):
        """SEC-017: No hardcoded developer private paths in repository"""
        is_clean, violations, scanned_count = run_public_release_audit()
        path_violations = [v for v in violations if "路徑" in v[1] or "path" in v[1].lower()]
        self.assertEqual(
            len(path_violations), 0,
            f"Found private path violations in repo: {path_violations}"
        )

    def test_sec_018_public_repo_api_token_clean(self):
        """SEC-018: No real API tokens or secrets committed in repository"""
        is_clean, violations, scanned_count = run_public_release_audit()
        token_violations = [v for v in violations if "Key" in v[1] or "Token" in v[1] or "JWT" in v[1]]
        self.assertEqual(
            len(token_violations), 0,
            f"Found secret token violations in repo: {token_violations}"
        )
        self.assertTrue(is_clean, f"Public release audit found violations: {violations}")


if __name__ == "__main__":
    unittest.main()
