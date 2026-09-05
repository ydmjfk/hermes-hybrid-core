#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Health Validator for CAP-006 Sandboxed MCP Capability
"""

import sys
from typing import Tuple

try:
    from .sandboxed_mcp_bridge import SandboxedMCPBridge
except ImportError:
    from sandboxed_mcp_bridge import SandboxedMCPBridge


def validate_capability() -> Tuple[bool, str]:
    """Perform self-diagnostic check on the sandboxed_mcp capability."""
    try:
        bridge = SandboxedMCPBridge("${HERMES_WORKSPACE_ROOT}")
        bridge.register_mcp_tool(
            server_name="diag_server",
            tool_name="diag_tool",
            description="Diagnostic MCP Tool",
            input_schema={},
            handler=lambda path: f"Read: {path}"
        )

        # 1. Test normal call
        res1 = bridge.invoke_tool("diag_server", "diag_tool", {"path": "${HERMES_WORKSPACE_ROOT}/ok.txt"})
        if res1.get("status") != "SUCCESS":
            return False, "Self-test failed: Legitimate path invocation failed."

        # 2. Test attack interception
        res2 = bridge.invoke_tool("diag_server", "diag_tool", {"path": "/etc/shadow"})
        if res2.get("status") != "FAIL" or res2.get("error_type") != "SecurityGateBlocked":
            return False, "Self-test failed: Sandbox gate failed to block /etc/shadow access."

        return True, "CAP-006 Sandboxed MCP Capability is healthy and operational."
    except Exception as e:
        return False, f"Exception during validation: {e}"


if __name__ == "__main__":
    ok, msg = validate_capability()
    print(f"Status: {'PASS' if ok else 'FAIL'} | Message: {msg}")
    sys.exit(0 if ok else 1)
