#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit test for hermes_core speed engines and optimization modules.
"""

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import hermes_core
from hermes_core.semantic_cache import set_cached_response, get_cached_response
from hermes_core.skeleton_streamer import generate_instant_skeleton
from hermes_core.speculative_executor import register_prefetch_handler, trigger_speculative_prefetch, get_prefetched_data
from hermes_core.circuit_breaker import check_and_execute_task
from hermes_core.db_pool import get_connection, execute_query


class TestHermesCore(unittest.TestCase):

    def test_semantic_cache(self):
        set_cached_response("最新系統健康狀況", "系統一切正常，負載 12%", category="health")
        cached = get_cached_response("幫我查一下最新系統健康狀況")
        self.assertIsNotNone(cached)
        self.assertIn("系統一切正常", cached["response_text"])

    def test_skeleton_streamer(self):
        skeleton = generate_instant_skeleton("請幫我分析系統日誌")
        self.assertIsNotNone(skeleton)
        self.assertTrue(any(k in skeleton for k in ["日誌", "分析", "診斷", "收到請求"]))

    def test_speculative_executor(self):
        register_prefetch_handler(
            r"health|健康",
            lambda text: "test_health_key",
            lambda text: {"cpu": 12, "mem": 45},
            "test_source"
        )
        k = trigger_speculative_prefetch("查詢健康狀態")
        self.assertEqual(k, "test_health_key")
        import time
        time.sleep(0.05)
        data = get_prefetched_data(k)
        self.assertIsNotNone(data)
        self.assertEqual(data["cpu"], 12)

    def test_circuit_breaker(self):
        def good_task():
            return "SUCCESS"

        ok, res = check_and_execute_task("test_task_1", good_task)
        self.assertTrue(ok)
        self.assertEqual(res, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
