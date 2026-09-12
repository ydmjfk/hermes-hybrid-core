#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-005 ~ SEC-007: Nested MCP Arguments Security Gate Test Matrix
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from capabilities.sandboxed_mcp.sandboxed_mcp_bridge import SandboxedMCPBridge


class TestNestedMCPSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.bridge = SandboxedMCPBridge(str(self.workspace))
        self.bridge.register_mcp_tool(
            server_name="test_server",
            tool_name="nested_tool",
            description="Tool with nested arguments",
            input_schema={},
            handler=lambda **kwargs: {"received": kwargs}
        )
        self.bridge.register_mcp_tool(
            server_name="test_server",
            tool_name="readonly_query",
            description="Readonly DB query tool",
            input_schema={},
            is_mutating=False,
            handler=lambda **kwargs: {"result": "ok"}
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sec_005_nested_mcp_path_injection(self):
        """SEC-005: Deeply Nested Path Traversal in MCP Arguments Blocked"""
        # Nested dict traversal
        payload_dict = {
            "options": {
                "config": {
                    "path": "../../outside_secret.txt"
                }
            }
        }
        res1 = self.bridge.invoke_tool("test_server", "nested_tool", payload_dict)
        self.assertEqual(res1.get("status"), "FAIL")
        self.assertEqual(res1.get("error_type"), "SecurityGateBlocked")

        # Nested list traversal
        payload_list = {
            "items": [
                {"file": "safe.txt"},
                {"file": "/etc/shadow"}
            ]
        }
        res2 = self.bridge.invoke_tool("test_server", "nested_tool", payload_list)
        self.assertEqual(res2.get("status"), "FAIL")
        self.assertEqual(res2.get("error_type"), "SecurityGateBlocked")

        # URL encoded nested traversal
        payload_encoded = {
            "batch": [
                {"dest": "%2e%2e/%2e%2e/etc/passwd"}
            ]
        }
        res3 = self.bridge.invoke_tool("test_server", "nested_tool", payload_encoded)
        self.assertEqual(res3.get("status"), "FAIL")
        self.assertEqual(res3.get("error_type"), "SecurityGateBlocked")

    def test_sec_006_nested_shell_injection(self):
        """SEC-006: Deeply Nested Shell Command Injection Blocked"""
        payload = {
            "execution": {
                "steps": [
                    {"command": "echo safe"},
                    {"command": "rm -rf / --no-preserve-root"}
                ]
            }
        }
        res = self.bridge.invoke_tool("test_server", "nested_tool", payload)
        self.assertEqual(res.get("status"), "FAIL")
        self.assertEqual(res.get("error_type"), "SecurityGateBlocked")
        self.assertIn("破壞性指令", res.get("error", ""))

    def test_sec_007_nested_sql_mutation(self):
        """SEC-007: Deeply Nested SQL Mutation in Readonly MCP Blocked"""
        payload = {
            "db_opts": {
                "queries": [
                    {"query": "SELECT * FROM metrics"},
                    {"query": "DROP TABLE users"}
                ]
            }
        }
        res = self.bridge.invoke_tool("test_server", "readonly_query", payload)
        self.assertEqual(res.get("status"), "FAIL")
        self.assertEqual(res.get("error_type"), "SecurityGateBlocked")
        self.assertIn("唯讀 MCP 工具禁止執行變更性 SQL", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()
