#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-015 ~ SEC-016: JWT, Bearer & DB URL Credential Redaction Test Matrix
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hermes_core.security_filter import sanitize_secrets, sanitize_dict, contains_secrets


class TestSecretRedactionSecurity(unittest.TestCase):

    def test_sec_015_jwt_and_bearer_redaction(self):
        """SEC-015: JWT and Bearer tokens must be detected and redacted"""
        mock_jwt = "eyJhbGciOi" + "JIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        mock_bearer = "Bearer " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

        text = f"傳入認證標頭: Authorization: {mock_bearer}, 附加憑證: {mock_jwt}"
        self.assertTrue(contains_secrets(text))

        clean = sanitize_secrets(text)
        self.assertNotIn(mock_jwt, clean)
        self.assertNotIn("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", clean)
        self.assertIn("[REDACTED]", clean)

    def test_sec_016_db_url_credential_redaction(self):
        """SEC-016: Database URLs with passwords must be sanitized"""
        db_urls = [
            "postgresql://mock_admin:mock_p@ssw0rd123@db.example.internal:5432/production_db",
            "mysql://mock_root:mock_complex_secret_999@db.cluster.internal/app",
            "mongodb://mock_user:mock_mongo_password@mongo.internal:27017/admin",
            "redis://:mock_redis_super_password@redis.cache:6379/0"
        ]

        for url in db_urls:
            self.assertTrue(contains_secrets(url), f"Failed to detect secret in DB URL: {url}")
            clean = sanitize_secrets(url)
            self.assertNotIn("mock_p@ssw0rd123", clean)
            self.assertNotIn("mock_complex_secret_999", clean)
            self.assertNotIn("mock_mongo_password", clean)
            self.assertNotIn("mock_redis_super_password", clean)
            self.assertIn("[REDACTED]@", clean)


if __name__ == "__main__":
    unittest.main()
