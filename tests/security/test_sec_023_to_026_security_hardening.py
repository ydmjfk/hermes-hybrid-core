#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-023 ~ SEC-026: Security Hardening Verification Test Matrix
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEC-023: Approval Secret Removal & Strict Fail-Closed (無 Secret 嚴格禁權杖)
SEC-024: Untrusted Caller human_approved=True 授權繞過封堵
SEC-025: SQLite read_only=True 零檔案系統副作用 (Zero Side-Effect)
SEC-026: PathSanitizer.safe_open() 目錄級 TOCTOU 符號連結競爭攔截
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from capabilities.sandboxed_mcp.sandboxed_mcp_bridge import SandboxedMCPBridge
from capabilities.extension_layer.extension_registry_engine import ExtensionRegistryEngine, RegisteredTool
from hermes_core.db_pool import get_db_connection
from hermes_core.path_sanitizer import PathSanitizer, SensitivePathBlockedError, PathTraversalError


class TestSecurityHardeningDirectives(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.orig_approval_secret = os.environ.get("HERMES_APPROVAL_SECRET")

    def tearDown(self):
        if self.orig_approval_secret is not None:
            os.environ["HERMES_APPROVAL_SECRET"] = self.orig_approval_secret
        else:
            os.environ.pop("HERMES_APPROVAL_SECRET", None)
        self.temp_dir.cleanup()

    # ─────────────────────────────────────────────────────────────
    # SEC-023: Approval Secret 移除硬編碼與 Fail-Closed 驗證
    # ─────────────────────────────────────────────────────────────
    def test_sec_023_no_secret_strict_fail_closed(self):
        """SEC-023: HERMES_APPROVAL_SECRET 未設定時，不可使用內建金鑰，必須嚴格 Fail-Closed"""
        os.environ.pop("HERMES_APPROVAL_SECRET", None)
        bridge = SandboxedMCPBridge(workspace_root=str(self.workspace), approval_secret=None)

        # 1. 驗證無預設 fallback secret
        self.assertIsNone(bridge.approval_secret)

        # 2. 嘗試產生權杖 -> 必須拋出例外 Fail-Closed
        with self.assertRaises(RuntimeError) as ctx:
            bridge.create_approval_token("server:mutating_tool")
        self.assertIn("HERMES_APPROVAL_SECRET is not configured", str(ctx.exception))

        # 3. 嘗試驗證任何權杖 -> 必須回傳 False
        self.assertFalse(bridge.verify_approval_token("server:mutating_tool:123456789:fake_sig", "server:mutating_tool"))
        self.assertFalse(bridge.verify_approval_token("", "server:mutating_tool"))

    # ─────────────────────────────────────────────────────────────
    # SEC-024: human_approved=True 授權繞過封堵
    # ─────────────────────────────────────────────────────────────
    def test_sec_024_untrusted_caller_cannot_bypass_human_approval(self):
        """SEC-024: 不可信呼叫端或模型輸出自行宣告 human_approved=True 絕對不可放行變更性工具"""
        os.environ["HERMES_APPROVAL_SECRET"] = "test_hardening_secret_key"
        bridge = SandboxedMCPBridge(workspace_root=str(self.workspace))

        executed = False
        def dangerous_action(target: str):
            nonlocal executed
            executed = True
            return f"Mutated {target}"

        bridge.register_mcp_tool(
            server_name="test_server",
            tool_name="dangerous_action",
            description="Dangerous Action",
            input_schema={},
            is_mutating=True,
            handler=dangerous_action
        )

        # 1. 不可信呼叫 (預設 trusted_caller=False)，即便帶上 human_approved=True 亦必須拒絕
        res1 = bridge.invoke_tool(
            "test_server",
            "dangerous_action",
            {"target": "production_db"},
            human_approved=True,
            trusted_caller=False
        )
        self.assertEqual(res1["status"], "FAIL")
        self.assertEqual(res1["error_type"], "HumanApprovalRequired")
        self.assertFalse(executed)

        # 2. 攻擊者嘗試在 arguments 字典內注入 human_approved=True 亦必須無效
        res2 = bridge.invoke_tool(
            "test_server",
            "dangerous_action",
            {"target": "production_db", "human_approved": True, "trusted_caller": True},
            trusted_caller=False
        )
        self.assertEqual(res2["status"], "FAIL")
        self.assertEqual(res2["error_type"], "HumanApprovalRequired")
        self.assertFalse(executed)

        # 3. 唯有內部受信任控制面 (trusted_caller=True) 搭配明確 human_approved 始得放行
        res3 = bridge.invoke_tool(
            "test_server",
            "dangerous_action",
            {"target": "production_db"},
            human_approved=True,
            trusted_caller=True
        )
        self.assertEqual(res3["status"], "SUCCESS")
        self.assertTrue(executed)

    def test_sec_024_extension_registry_dispatch_trusted_caller_gate(self):
        """SEC-024: ExtensionRegistryEngine dispatch() 在不可信呼叫下阻斷 human_approved 偽造"""
        engine = ExtensionRegistryEngine(capabilities_dir=str(self.workspace))

        executed = False
        def patch_file(file_path: str):
            nonlocal executed
            executed = True
            return "PATCHED"

        engine.registered_tools["patch_file"] = RegisteredTool(
            tool_name="patch_file",
            capability_id="CAP-PATCH",
            description="Patch File",
            function=patch_file,
            parameters_schema={},
            source_file="tools.py",
            is_mutating=True
        )

        # 不可信路徑 (trusted_caller=False) 傳入 human_approved=True 必須被阻斷
        res = engine.dispatch("patch_file", human_approved=True, trusted_caller=False, file_path="test.txt")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["error_type"], "HumanApprovalRequired")
        self.assertFalse(executed)

        # 受信任控制面 (trusted_caller=True) 放行
        res_ok = engine.dispatch("patch_file", human_approved=True, trusted_caller=True, file_path="test.txt")
        self.assertEqual(res_ok["status"], "SUCCESS")
        self.assertTrue(executed)

    # ─────────────────────────────────────────────────────────────
    # SEC-025: SQLite read_only=True 零副作用驗證
    # ─────────────────────────────────────────────────────────────
    def test_sec_025_sqlite_readonly_zero_filesystem_side_effect(self):
        """SEC-025: get_db_connection(read_only=True) 在資料庫不存在時嚴禁建立檔案或目錄"""
        fake_db = self.workspace / "sub_nonexistent" / "ghost_db.sqlite"
        self.assertFalse(fake_db.exists())
        self.assertFalse(fake_db.parent.exists())

        # 唯讀連線至不存在之資料庫，必須拋出 FileNotFoundError (Fail-Closed)
        with self.assertRaises(FileNotFoundError) as ctx:
            get_db_connection(fake_db, read_only=True)

        self.assertIn("唯讀 SQLite 資料庫不存在", str(ctx.exception))

        # 驗證檔案系統零變更、零副檔名建立、零目錄建立
        self.assertFalse(fake_db.exists())
        self.assertFalse(fake_db.parent.exists())

    # ─────────────────────────────────────────────────────────────
    # SEC-026: PathSanitizer.safe_open() 目錄級 TOCTOU 競爭攔截
    # ─────────────────────────────────────────────────────────────
    def test_sec_026_directory_level_symlink_race_blocked(self):
        """SEC-026: safe_open 必須透過逐層 FD 與 O_NOFOLLOW 攔截中間目錄被抽換為符號連結的越界攻擊"""
        sanitizer = PathSanitizer(workspace_root=self.workspace)

        outside_dir = Path(tempfile.mkdtemp())
        secret_file = outside_dir / "top_secret.txt"
        secret_file.write_text("CLASSIFIED_INTELLIGENCE", encoding="utf-8")

        try:
            # 建立指向外部機敏目錄的中間目錄符號連結
            evil_symlink_dir = self.workspace / "evil_dir_link"
            os.symlink(outside_dir, evil_symlink_dir, target_is_directory=True)

            target_path = evil_symlink_dir / "top_secret.txt"

            # 嘗試透過 safe_open 開啟穿越符號連結目錄之檔案，必須被強制攔截
            with self.assertRaises((SensitivePathBlockedError, PathTraversalError)):
                with sanitizer.safe_open(target_path, "r") as fp:
                    fp.read()
        finally:
            import shutil
            shutil.rmtree(outside_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
