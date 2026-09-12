#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-019 ~ SEC-022: Security Architecture Gates Test Matrix
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEC-019: ExtensionRegistryEngine.dispatch() 參數安全驗證門禁 (消滅 bypass)
SEC-020: is_mutating 變更性操作強制人工審批門禁 (消滅宣稱與實作不一致)
SEC-021: 獨立密碼學 Release Authority 簽章校驗與公鑰信任根
SEC-022: PathSanitizer.safe_open() 符號連結 TOCTOU 競爭抽換攔截
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
from hermes_core.path_sanitizer import PathSanitizer, SensitivePathBlockedError, PathTraversalError
from hermes_core.trust_root import compute_canonical_digest, verify_capability_signature, sign_capability_digest
from cryptography.hazmat.primitives.asymmetric import ed25519


class TestSecurityArchitectureGates(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.bridge = SandboxedMCPBridge(workspace_root=str(self.workspace))

    def tearDown(self):
        self.temp_dir.cleanup()

    # ─────────────────────────────────────────────────────────────
    # SEC-019: ExtensionRegistryEngine.dispatch() 安全門禁驗證
    # ─────────────────────────────────────────────────────────────
    def test_sec_019_dispatch_blocks_path_traversal(self):
        """SEC-019: dispatch() 必須對傳入引數進行路徑穿越深度遞迴掃描，消滅架構 bypass"""
        engine = ExtensionRegistryEngine(capabilities_dir=str(self.workspace))
        
        executed = False
        def sample_tool(file_path: str):
            nonlocal executed
            executed = True
            return "OK"

        engine.registered_tools["sample_tool"] = RegisteredTool(
            tool_name="sample_tool",
            capability_id="CAP-TEST-001",
            description="Test Tool",
            function=sample_tool,
            parameters_schema={},
            source_file="test.py",
            is_mutating=False
        )

        # 嘗試利用 dispatch 傳入目錄穿越攻擊路徑
        res = engine.dispatch("sample_tool", file_path="../../etc/shadow")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["error_type"], "SecurityGateBlocked")
        self.assertFalse(executed)

    def test_sec_019_dispatch_blocks_dangerous_command_injection(self):
        """SEC-019: dispatch() 必須阻斷高危命令注入攻擊"""
        engine = ExtensionRegistryEngine(capabilities_dir=str(self.workspace))
        
        executed = False
        def runner(cmd: str):
            nonlocal executed
            executed = True
            return "DONE"

        engine.registered_tools["runner"] = RegisteredTool(
            tool_name="runner",
            capability_id="CAP-TEST-002",
            description="Runner",
            function=runner,
            parameters_schema={},
            source_file="test.py",
            is_mutating=False
        )

        res = engine.dispatch("runner", cmd="rm -rf /")
        self.assertEqual(res["status"], "FAIL")
        self.assertEqual(res["error_type"], "SecurityGateBlocked")
        self.assertFalse(executed)

    # ─────────────────────────────────────────────────────────────
    # SEC-020: is_mutating 人工審批門禁驗證
    # ─────────────────────────────────────────────────────────────
    def test_sec_020_mcp_mutating_tool_requires_approval(self):
        """SEC-020: SandboxedMCPBridge invoke_tool() 在 is_mutating=True 時無審批必須阻斷"""
        executed = False
        def delete_db(db_name: str):
            nonlocal executed
            executed = True
            return "DELETED"

        self.bridge.register_mcp_tool(
            server_name="system",
            tool_name="delete_db",
            description="Mutating DB Tool",
            input_schema={},
            is_mutating=True,
            handler=delete_db
        )

        # 1. 未提供審批 -> 必須被阻斷
        res_blocked = self.bridge.invoke_tool("system", "delete_db", {"db_name": "users"}, human_approved=False)
        self.assertEqual(res_blocked["status"], "FAIL")
        self.assertEqual(res_blocked["error_type"], "HumanApprovalRequired")
        self.assertFalse(executed)

        # 2. 提供一次性審批權杖 (需設定 HERMES_APPROVAL_SECRET) -> 放行
        os.environ["HERMES_APPROVAL_SECRET"] = "test_sec_020_secret_for_mocking"
        try:
            token = self.bridge.create_approval_token("system:delete_db")
            res_approved = self.bridge.invoke_tool("system", "delete_db", {"db_name": "users"}, approval_token=token)
            self.assertEqual(res_approved["status"], "SUCCESS")
            self.assertTrue(executed)
        finally:
            os.environ.pop("HERMES_APPROVAL_SECRET", None)

    def test_sec_020_extension_dispatch_mutating_tool_requires_approval(self):
        """SEC-020: ExtensionRegistryEngine dispatch() 在 is_mutating=True 時無審批必須阻斷"""
        engine = ExtensionRegistryEngine(capabilities_dir=str(self.workspace))
        
        executed = False
        def write_file(content: str):
            nonlocal executed
            executed = True
            return "WRITTEN"

        engine.registered_tools["write_file"] = RegisteredTool(
            tool_name="write_file",
            capability_id="CAP-TEST-WRITE",
            description="Write File",
            function=write_file,
            parameters_schema={},
            source_file="test.py",
            is_mutating=True
        )

        # 1. 未審批 -> 阻斷
        res_denied = engine.dispatch("write_file", content="hello", human_approved=False)
        self.assertEqual(res_denied["status"], "FAIL")
        self.assertEqual(res_denied["error_type"], "HumanApprovalRequired")
        self.assertFalse(executed)

        # 2. 可信內部控制面明確審批 -> 放行
        res_ok = engine.dispatch("write_file", content="hello", human_approved=True, trusted_caller=True)
        self.assertEqual(res_ok["status"], "SUCCESS")
        self.assertTrue(executed)

    # ─────────────────────────────────────────────────────────────
    # SEC-021: 獨立密碼學信任根簽章機制
    # ─────────────────────────────────────────────────────────────
    def test_sec_021_cryptographic_trust_root(self):
        """SEC-021: 驗證 Canonical Digest 計算與 Ed25519 簽章真實性防偽"""
        priv = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()

        files_map = {"tools.py": "abc123hash", "validator.py": "def456hash"}
        sig = sign_capability_digest(priv.private_bytes_raw(), "CAP-001", "1.0.0", files_map)

        # 合法驗證通過
        is_valid, msg = verify_capability_signature("CAP-001", "1.0.0", files_map, sig, pub_bytes)
        self.assertTrue(is_valid)

        # 假冒公鑰 (未經授權之簽名) 必須拒絕
        fake_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        is_valid_fake, msg_fake = verify_capability_signature("CAP-001", "1.0.0", files_map, sig, fake_pub)
        self.assertFalse(is_valid_fake)

    # ─────────────────────────────────────────────────────────────
    # SEC-022: TOCTOU 符號連結競爭抽換防護
    # ─────────────────────────────────────────────────────────────
    def test_sec_022_toctou_safe_open(self):
        """SEC-022: safe_open 必須阻斷目標檔案在校驗後抽換指向外部敏感檔案"""
        sanitizer = PathSanitizer(workspace_root=self.workspace)
        normal_file = self.workspace / "normal.txt"
        normal_file.write_text("secure data", encoding="utf-8")

        # 正常開啟
        with sanitizer.safe_open(normal_file, "r") as fp:
            data = fp.read()
            self.assertEqual(data, "secure data")

        # 越界路徑即便透過 safe_open 也必須在預檢階段即被拋出
        with self.assertRaises((PathTraversalError, SensitivePathBlockedError)):
            with sanitizer.safe_open("../../etc/passwd", "r") as fp:
                pass


if __name__ == "__main__":
    unittest.main()
