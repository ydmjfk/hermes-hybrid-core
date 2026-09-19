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

    def test_default_mask_spool_path(self):
        """測試預設 mask_spool_path 即為 True，不傳參數也不外洩實體磁碟路徑"""
        content = "default masking verification\n" * 500
        compacted, is_truncated, spooled = compact_tool_output(
            content,
            max_chars=1024,
            spool_dir=self.spool_path,
            task_id="default_mask_task",
        )
        self.assertTrue(is_truncated)
        self.assertIsNotNone(spooled)
        self.assertNotIn(str(self.spool_path), compacted)
        self.assertIn("RefID:default_mask_task_", compacted)

    def test_symlink_rejection_in_spool(self):
        """測試 spool 目錄中若存在惡意 symlink，會被自動清理且絕不盲從"""
        self.spool_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        evil_link = self.spool_path / "spool_evil_test.txt"
        target_file = self.spool_path / "target_file.txt"
        target_file.write_text("protected sensitive file content", encoding="utf-8")
        try:
            evil_link.symlink_to(target_file)
            from hermes_core.runtime_compactor import _clean_spool_dir_quota
            _clean_spool_dir_quota(self.spool_path)
            # 驗證 symlink 已被拔除
            self.assertFalse(evil_link.exists())
            self.assertTrue(target_file.exists())
        finally:
            evil_link.unlink(missing_ok=True)
            target_file.unlink(missing_ok=True)

    def test_duplicate_detector_bounded_memory(self):
        """測試重複調用偵測器在大量不同調用下記憶體歷史紀錄有界 (maxlen)"""
        detector = ToolDuplicateCallDetector(max_consecutive_duplicates=2, maxlen=50)
        for i in range(300):
            tripped, msg = detector.record_and_check(f"tool_{i % 10}", {"query": f"var_{i}"})
            self.assertFalse(tripped)

    def test_spool_dir_symlink_rejection(self):
        """測試 spool 目錄本身若被替換為 symlink，系統必須拒絕落盤"""
        real_dir = Path(self.temp_dir.name) / "real_dir"
        real_dir.mkdir(mode=0o700)
        symlink_dir = Path(self.temp_dir.name) / "symlink_spool_dir"
        symlink_dir.symlink_to(real_dir)

        content = "test content\n" * 500
        compacted, is_truncated, spooled = compact_tool_output(
            content,
            max_chars=1024,
            spool_dir=symlink_dir,
            task_id="symlink_dir_attack",
        )
        self.assertTrue(is_truncated)
        # 由於 spool_dir 是 symlink，安全閘門拒絕落盤，spooled 應為 None
        self.assertIsNone(spooled)

    def test_hard_byte_budget_with_truncation_marker(self):
        """測試超大內容截斷時，含 truncation marker 的實際落盤大小嚴格 <= 10MB"""
        from hermes_core.runtime_compactor import MAX_SPOOL_FILE_BYTES, _safe_spool_write
        # 構造 12MB 的超大資料 (ASCII + UTF-8 中文)
        huge_chunk = "這是中文測試內容與二進位邊界驗證。" * 50
        huge_content = huge_chunk * ((12 * 1024 * 1024) // len(huge_chunk.encode("utf-8")) + 1)
        self.assertGreater(len(huge_content.encode("utf-8")), MAX_SPOOL_FILE_BYTES)

        spooled_file = _safe_spool_write(
            content=huge_content,
            spool_dir=self.spool_path,
            safe_task_id="huge_byte_test",
            content_hash="testhash123",
        )
        self.assertIsNotNone(spooled_file)
        real_file_bytes = os.path.getsize(spooled_file)
        # 驗證包含 marker 後的大小絕對不可超過 10MB
        self.assertLessEqual(real_file_bytes, MAX_SPOOL_FILE_BYTES)


if __name__ == "__main__":
    unittest.main()


