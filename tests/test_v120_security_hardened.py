#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_v120_security_hardened.py — v1.2.0 安全加固與嚴格邊界單元測試
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
測試項目：
1. 嚴格字元預算保證 (<= max_chars)，涵蓋極限單行與極限多行。
2. 暫存落盤安全：POSIX 0700 目錄 / 0600 檔案權限與 O_NOFOLLOW / O_EXCL。
3. 暫存落盤機密脫敏：落盤前自動抹除 API Key 與 Token。
4. 路徑暴露防護：mask_spool_path 模式杜絕實體磁碟路徑外洩。
5. 檔名淨化：task_id 嚴格白名單防止目錄穿越與特殊字元。
6. 重複調用偵測器記憶體有界性 (deque maxlen 限制)。
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from hermes_core.circuit_breaker import ToolDuplicateCallDetector
from hermes_core.runtime_compactor import ToolOutputCompactor, compact_tool_output


class TestV120SecurityHardened(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.spool_path = Path(self.temp_dir.name) / "test_spool"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_budget_enforcement_single_huge_line(self):
        """測試單行極限長度 (100KB) 時，輸出嚴格受限於 max_chars"""
        max_limit = 2048
        huge_line = "A" * 100_000
        compacted, is_truncated, spooled = compact_tool_output(
            huge_line,
            max_chars=max_limit,
            spool_dir=self.spool_path,
            task_id="single_line_test",
        )
        self.assertTrue(is_truncated)
        self.assertLessEqual(len(compacted), max_limit)
        self.assertIn("單行/少行內容超限", compacted)

    def test_budget_enforcement_multi_huge_lines(self):
        """測試多行且每行極長時，Head+Tail 組合嚴格受限於 max_chars"""
        max_limit = 4096
        # 200 行，每行 1000 字元，共 200,000 字元
        lines = [f"LINE {i:03d}: " + ("x" * 1000) for i in range(200)]
        content = "\n".join(lines)

        compacted, is_truncated, spooled = compact_tool_output(
            content,
            max_chars=max_limit,
            spool_dir=self.spool_path,
            task_id="multi_line_test",
        )
        self.assertTrue(is_truncated)
        self.assertLessEqual(len(compacted), max_limit)
        self.assertIn("已雙向保真折疊", compacted)

    def test_spool_permission_and_secret_redaction(self):
        """測試落盤檔案權限為 0600、目錄為 0700，且落盤前金鑰已物理脫敏"""
        secret_key = "sk-" + "ant-" + "api03-" + "testsecret1234567890abcdef1234567890abcdef"
        raw_output = f"Connecting to upstream service with key: {secret_key}\n" + ("log entry\n" * 500)


        compacted, is_truncated, spooled = compact_tool_output(
            raw_output,
            max_chars=1024,
            spool_dir=self.spool_path,
            task_id="secret_leak_test",
        )
        self.assertIsNotNone(spooled)
        spool_file = Path(spooled)
        self.assertTrue(spool_file.exists())

        # 1. 驗證檔案權限 0600
        file_mode = stat.S_IMODE(spool_file.stat().st_mode)
        self.assertEqual(file_mode, 0o600, f"Spool 檔案權限應為 0600，實測為 {oct(file_mode)}")

        # 2. 驗證目錄權限 0700
        dir_mode = stat.S_IMODE(self.spool_path.stat().st_mode)
        self.assertEqual(dir_mode, 0o700, f"Spool 目錄權限應為 0700，實測為 {oct(dir_mode)}")

        # 3. 驗證落盤內容已脫敏，不得殘留真實金鑰
        with open(spool_file, "r", encoding="utf-8") as f:
            spooled_content = f.read()
        self.assertNotIn(secret_key, spooled_content)
        self.assertIn("[REDACTED]", spooled_content)

    def test_mask_spool_path(self):
        """測試 mask_spool_path 模式下，輸出的文字不洩漏內部檔案系統絕對路徑"""
        content = "system diagnostic report\n" + ("status: OK\n" * 600)
        compacted, is_truncated, spooled = compact_tool_output(
            content,
            max_chars=1024,
            spool_dir=self.spool_path,
            task_id="privacy_test",
            mask_spool_path=True,
        )
        self.assertTrue(is_truncated)
        self.assertIsNotNone(spooled)
        # 輸出的文字中絕不可包含物理暫存路徑
        self.assertNotIn(str(self.spool_path), compacted)
        self.assertNotIn("/tmp", compacted)
        self.assertIn("RefID:privacy_test_", compacted)

    def test_task_id_sanitization(self):
        """測試 task_id 包含路徑穿越與特殊字元時，被安全白名單轉義"""
        malicious_task_id = "../../etc/passwd\n\x00;rm -rf /"
        content = "dummy test content\n" * 300

        compacted, is_truncated, spooled = compact_tool_output(
            content,
            max_chars=1024,
            spool_dir=self.spool_path,
            task_id=malicious_task_id,
        )
        self.assertIsNotNone(spooled)
        filename = Path(spooled).name
        # 檔名中不應有任何路徑穿越字元或空字元
        self.assertTrue(filename.startswith("spool_"))
        self.assertNotIn("..", filename)
        self.assertNotIn("/", filename.replace("spool_", ""))
        self.assertNotIn("\x00", filename)

    def test_duplicate_detector_bounded_memory(self):
        """測試重複調用偵測器在大量不同調用下記憶體歷史紀錄有界 (maxlen)"""
        detector = ToolDuplicateCallDetector(max_consecutive_duplicates=2, maxlen=50)
        for i in range(300):
            tripped, msg = detector.record_and_check(f"tool_{i % 10}", {"query": f"var_{i}"})
            self.assertFalse(tripped)

        self.assertLessEqual(len(detector._call_history), 50)


if __name__ == "__main__":
    unittest.main()
