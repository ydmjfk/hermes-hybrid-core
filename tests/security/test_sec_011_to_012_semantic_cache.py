#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-011 ~ SEC-012: Semantic Cache Isolation & Secret Desensitization Test Matrix
"""

import os
import sys
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hermes_core.semantic_cache import (
    set_cached_response,
    get_cached_response,
    CACHE_DB,
    _get_db
)


class TestSemanticCacheSecurity(unittest.TestCase):

    def setUp(self):
        with _get_db() as conn:
            conn.execute("DELETE FROM query_cache;")

    def test_sec_011_cross_user_and_scope_isolation(self):
        """SEC-011: User A / Scope A response must NOT leak to User B / Scope B"""
        query = "查詢我的個人機密訂單資料"
        private_response_user_a = "訂單機密資料：User A 專屬帳單"

        # User A caches response in scope 'user_a'
        set_cached_response(
            query_str=query,
            response_text=private_response_user_a,
            caller_id="user",
            scope_id="user_a"
        )

        # User A can retrieve it
        hit_user_a = get_cached_response(query, scope_id="user_a", caller_id="user")
        self.assertIsNotNone(hit_user_a)
        self.assertIn("User A 專屬帳單", hit_user_a["response_text"])

        # User B querying same semantic question in scope 'user_b' must NOT hit User A cache
        hit_user_b = get_cached_response(query, scope_id="user_b", caller_id="user")
        self.assertIsNone(hit_user_b, "Cache leaked across scopes (user_a -> user_b)!")

        # Different caller (e.g. system vs user) in same scope also isolated
        hit_other_caller = get_cached_response(query, scope_id="user_a", caller_id="system")
        self.assertIsNone(hit_other_caller, "Cache leaked across callers (user -> system)!")

    def test_sec_012_cache_secret_leakage_prevention(self):
        """SEC-012: API keys, Bearer tokens, and passwords in query and response must be sanitized"""
        mock_api_key = "sk-" + "abcdef1234567890abcdef1234567890"
        query_with_secret = f"查詢連線金鑰 {mock_api_key} 的剩餘額度"
        response_with_secret = f"連線密碼為 password='SuperConfidentialPass123!'"

        set_cached_response(
            query_str=query_with_secret,
            response_text=response_with_secret,
            caller_id="agent",
            scope_id="default"
        )

        # Inspect raw SQLite database content directly
        with sqlite3.connect(str(CACHE_DB)) as conn:
            cur = conn.execute("SELECT normalized_query, response_text FROM query_cache;")
            rows = cur.fetchall()
            self.assertTrue(len(rows) > 0)
            for norm_q, resp in rows:
                self.assertNotIn(mock_api_key, norm_q, "Raw API key persisted in normalized_query!")
                self.assertNotIn("SuperConfidentialPass123!", resp, "Raw password persisted in response_text!")
                self.assertIn("[REDACTED]", resp)


if __name__ == "__main__":
    unittest.main()
