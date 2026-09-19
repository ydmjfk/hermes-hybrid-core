#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_preflight_and_sanitizer.py — Preflight 幾何門禁與 Null-Byte 消毒單元測試
"""

import unittest
from pathlib import Path
from hermes_core import (
    is_intersecting,
    PreflightDeckGuard,
    sanitize_command_payload,
    sanitize_environment,
    SafeAsyncSessionPool,
    __version__,
)
from skills.prompt_inspector.scripts.inspect_prompt import inspect_prompt


class TestPreflightAndSanitizer(unittest.TestCase):

    def test_version(self):
        """驗證版本號為 1.1.0"""
        self.assertEqual(__version__, "1.1.0")

    def test_geometric_intersection(self):
        """驗證 Bounding Box 幾何碰撞演算法"""
        # 實體重疊案例
        box_a = (1.0, 1.0, 3.0, 3.0)
        box_b = (2.0, 2.0, 4.0, 4.0)
        self.assertTrue(is_intersecting(box_a, box_b))

        # 完全分離案例
        box_c = (5.0, 5.0, 7.0, 7.0)
        self.assertFalse(is_intersecting(box_a, box_c))

        # 緊貼但不重疊 (邊距 tolerance 0.05)
        box_d = (3.0, 1.0, 5.0, 3.0)
        self.assertFalse(is_intersecting(box_a, box_d))

    def test_null_byte_command_sanitization(self):
        """驗證命令列字串與清單中的 \x00 物理剝除"""
        # 單一字串
        malicious_str = "python3\x00 -c 'print(1)'\x00"
        clean_str = sanitize_command_payload(malicious_str)
        self.assertEqual(clean_str, "python3 -c 'print(1)'")
        self.assertNotIn("\x00", clean_str)

        # 參數清單
        malicious_list = ["git\x00", "status\x00", "--porcelain"]
        clean_list = sanitize_command_payload(malicious_list)
        self.assertEqual(clean_list, ["git", "status", "--porcelain"])

    def test_null_byte_environment_sanitization(self):
        """驗證環境變數字典之鍵值 \x00 物理剝除"""
        env = {
            "USER\x00": "developer\x00",
            "PATH": "/usr/bin\x00:/bin",
            "CLEAN_KEY": "safe_val"
        }
        clean_env = sanitize_environment(env)
        self.assertIn("USER", clean_env)
        self.assertNotIn("USER\x00", clean_env)
        self.assertEqual(clean_env["USER"], "developer")
        self.assertEqual(clean_env["PATH"], "/usr/bin:/bin")

    def test_prompt_inspector_governance(self):
        """驗證提示詞體檢中心能否精準捕獲潛在返工風險"""
        # 未加幾何門禁的簡報提示詞
        res = inspect_prompt("幫我製作一份系統架構簡報 PPTX")
        self.assertLess(res["score"], 100)
        self.assertTrue(any(w["rule_id"] == "CHK_PPT_GEOMETRY" for w in res["warnings"]))
        self.assertIn("Preflight 幾何碰撞預檢", res["optimized_prompt"])

        # 包含完善約束的優質提示詞
        perfect_prompt = "幫我製作一份系統架構簡報 PPTX，必須執行幾何門禁預檢，確保0重疊"
        res2 = inspect_prompt(perfect_prompt)
        self.assertEqual(res2["score"], 100)
        self.assertEqual(res2["status"], "PASS")

    def test_safe_async_session_pool_structure(self):
        """驗證跨 Loop 安全連線池模組介面完整性"""
        self.assertTrue(hasattr(SafeAsyncSessionPool, "get_session"))


if __name__ == "__main__":
    unittest.main()
