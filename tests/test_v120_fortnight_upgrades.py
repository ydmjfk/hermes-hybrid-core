#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_v120_fortnight_upgrades.py — Hermes Hybrid Core v1.2.0 雙週演進全景測試套件
"""

import unittest
from pathlib import Path
from hermes_core import (
    __version__,
    compact_tool_output,
    ToolOutputCompactor,
    ToolDuplicateCallDetector,
    SmartApprovalTimeoutShield,
    generate_instant_skeleton,
    sanitize_command_payload,
    sanitize_environment,
    is_intersecting,
)


class TestV120FortnightUpgrades(unittest.TestCase):

    def test_version_bump(self):
        """驗證 v1.2.0 大版本宣告"""
        self.assertEqual(__version__, "1.2.0")

    def test_tool_output_compaction_head_tail(self):
        """驗證 4KB 雙向保真截斷 (Head 15 + Tail 35 行保留)"""
        # 構造 100 行之大文本 (模擬長日誌與 Traceback)
        lines = [f"Line {i:03d}: Task initialization info" for i in range(1, 21)]  # 1~20
        lines += [f"Line {i:03d}: Loop intermediate chunk data {i * 12345}" for i in range(21, 80)] # 中間 60 行
        lines += [f"Line {i:03d}: Traceback stack frame {i}" for i in range(80, 99)]
        lines.append("Line 100: CRITICAL Exception Error Exit Code: 1") # 結尾關鍵錯誤

        large_content = "\n".join(lines)
        self.assertGreater(len(large_content), 4096)

        compacted, is_truncated, spool_path = compact_tool_output(
            large_content, max_chars=1024, keep_head=15, keep_tail=35
        )

        self.assertTrue(is_truncated)
        self.assertIsNotNone(spool_path)
        self.assertTrue(Path(spool_path).exists())

        # 檢驗前 15 行保留
        self.assertIn("Line 001: Task initialization", compacted)
        self.assertIn("Line 015: Task initialization", compacted)

        # 檢驗中繼折疊宣告存在
        self.assertIn("RUNTIME CONTROL", compacted)
        self.assertIn("雙向保真折疊", compacted)

        # 檢驗末尾 35 行與 Traceback 關鍵錯誤 100% 完整保留
        self.assertIn("Line 100: CRITICAL Exception Error Exit Code: 1", compacted)
        self.assertIn("Line 090: Traceback stack frame", compacted)

    def test_duplicate_call_hard_circuit_breaker(self):
        """驗證同參數重複調用零容忍硬熔斷 (Zero Exact-Duplicate Retry)"""
        breaker = ToolDuplicateCallDetector(max_consecutive_duplicates=2)

        # 第 1 次調用
        tripped1, _ = breaker.record_and_check("terminal", {"cmd": "curl -s http://faulty.service"})
        self.assertFalse(tripped1)

        # 第 2 次相同調用 -> 觸發硬熔斷
        tripped2, msg2 = breaker.record_and_check("terminal", {"cmd": "curl -s http://faulty.service"})
        self.assertTrue(tripped2)
        self.assertIn("CIRCUIT BREAKER TRIPPED", msg2)
        self.assertIn("零容忍鐵律", msg2)

    def test_smart_approval_timeout_shield(self):
        """驗證審批逾時冷卻護盾"""
        SmartApprovalTimeoutShield.reset()
        self.assertFalse(SmartApprovalTimeoutShield.is_in_timeout_cooldown())

        SmartApprovalTimeoutShield.record_timeout()
        self.assertTrue(SmartApprovalTimeoutShield.is_in_timeout_cooldown())

        SmartApprovalTimeoutShield.reset()
        self.assertFalse(SmartApprovalTimeoutShield.is_in_timeout_cooldown())

    def test_skeleton_streamer_negative_and_silent_defense(self):
        """驗證骨架秒回器：日常短語靜默與否定句語意防禦"""
        # 1. 短詞靜默
        self.assertIsNone(generate_instant_skeleton("好"))
        self.assertIsNone(generate_instant_skeleton("收到"))
        self.assertIsNone(generate_instant_skeleton("謝謝"))

        # 2. 否定句抑制單據調閱
        res = generate_instant_skeleton("不用查發票了")
        self.assertTrue(res is None or "調閱" not in res)

    def test_null_byte_sanitization_integrity(self):
        """驗證 ProcessSupervisor Null-Byte 物理消毒"""
        cmd = ["rm\x00", "-rf\x00", "/tmp/test\x00"]
        cleaned = sanitize_command_payload(cmd)
        self.assertEqual(cleaned, ["rm", "-rf", "/tmp/test"])

        env = {"TOKEN\x00": "secret\x00val"}
        cleaned_env = sanitize_environment(env)
        self.assertEqual(cleaned_env, {"TOKEN": "secretval"})


if __name__ == "__main__":
    unittest.main()
