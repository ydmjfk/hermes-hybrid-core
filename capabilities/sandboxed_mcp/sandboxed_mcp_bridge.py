#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAP-006: Goose-Style Sandboxed MCP Adapter & Safety Bridge Engine (Promoted Capability)
=======================================================================================
A security-first MCP (Model Context Protocol) tool adapter and bridge.
Features:
  1. Standard JSON-RPC 2.0 Tool Invocation Normalization.
  2. Pre-Execution HAOS Sandbox Gate (Path traversal & sensitive file block).
  3. Dangerous Shell & Mutating SQL Command Filtering.
  4. Fail-Closed Security Policy (0 bypass for unauthorized directory access).
"""

import os
import re
import sys
import json
import time
import hmac
import hashlib
import unicodedata
from urllib.parse import unquote
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple, Callable

ALLOWED_WORKSPACE_ROOT = Path.home().resolve()

# Explicit blocklist of sensitive paths inside workspace
BLOCKED_SENSITIVE_PATHS = [
    ALLOWED_WORKSPACE_ROOT / ".ssh",
    ALLOWED_WORKSPACE_ROOT / ".gnupg",
    ALLOWED_WORKSPACE_ROOT / ".aws",
    ALLOWED_WORKSPACE_ROOT / ".azure",
    ALLOWED_WORKSPACE_ROOT / ".gcp",
    ALLOWED_WORKSPACE_ROOT / ".env",
    ALLOWED_WORKSPACE_ROOT / ".env.local",
    ALLOWED_WORKSPACE_ROOT / "config.yaml",
    ALLOWED_WORKSPACE_ROOT / ".git",
    ALLOWED_WORKSPACE_ROOT / ".kube",
    ALLOWED_WORKSPACE_ROOT / ".docker",
    ALLOWED_WORKSPACE_ROOT / ".npmrc",
    ALLOWED_WORKSPACE_ROOT / ".bash_history",
    ALLOWED_WORKSPACE_ROOT / ".local/share/keyrings",
    ALLOWED_WORKSPACE_ROOT / ".vscode",
    ALLOWED_WORKSPACE_ROOT / ".idea",
    ALLOWED_WORKSPACE_ROOT / ".terraform"
]

DANGEROUS_COMMAND_PATTERNS = [
    r"\brm\s+-[rfRF]+\s+/",
    r"\bsudo\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+777\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",  # Fork bomb
    r"\b>\s*/dev/sd[a-z]",
]

DESTRUCTIVE_SQL_PATTERNS = [
    r"\bDROP\s+TABLE\b",
    r"\bDROP\s+DATABASE\b",
    r"\bTRUNCATE\s+TABLE\b",
    r"\bDELETE\s+FROM\b",
    r"\bALTER\s+TABLE\b"
]


@dataclass
class MCPToolDefinition:
    server_name: str
    tool_name: str
    description: str
    input_schema: Dict[str, Any]
    is_mutating: bool = False
    handler: Optional[Callable] = None


class SandboxedMCPBridge:
    """
    Goose-style Sandboxed MCP adapter bridge with pre-execution safety gate.
    """

    def __init__(
        self,
        workspace_root: str = str(Path.home()),
        approval_handler: Optional[Callable[[str, str, Dict[str, Any]], bool]] = None,
        approval_secret: Optional[str] = None
    ):
        self.workspace_root = Path(workspace_root).expanduser().resolve()
        self.servers: Dict[str, Dict[str, Any]] = {}
        self.tools: Dict[str, MCPToolDefinition] = {}
        self.approval_handler = approval_handler
        # Strict Fail-Closed: No hardcoded fallback secret is permitted
        self.approval_secret = approval_secret

    def _get_approval_secret(self) -> Optional[str]:
        return self.approval_secret or os.environ.get("HERMES_APPROVAL_SECRET")

    def create_approval_token(self, full_key: str, ttl_seconds: int = 300) -> str:
        """Create a cryptographic approval token for mutating tool execution (Strict Fail-Closed)."""
        secret = self._get_approval_secret()
        if not secret:
            raise RuntimeError("Approval token creation failed: HERMES_APPROVAL_SECRET is not configured (Fail-Closed)")
        expire_ts = int(time.time()) + ttl_seconds
        payload = f"{full_key}:{expire_ts}"
        sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}:{sig}"

    def verify_approval_token(self, token: Optional[str], full_key: str) -> bool:
        """Verify the cryptographic approval token (Strict Fail-Closed)."""
        secret = self._get_approval_secret()
        if not secret or not token or not isinstance(token, str):
            return False
        parts = token.rsplit(":", 2)
        if len(parts) != 3:
            return False
        tok_key, exp_str, sig = parts
        if tok_key != full_key:
            return False
        try:
            exp = int(exp_str)
            if time.time() > exp:
                return False
        except ValueError:
            return False
        expected_sig = hmac.new(secret.encode("utf-8"), f"{tok_key}:{exp_str}".encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)

    def register_mcp_tool(
        self,
        server_name: str,
        tool_name: str,
        description: str,
        input_schema: Dict[str, Any],
        is_mutating: bool = False,
        handler: Optional[Callable] = None
    ) -> None:
        """Register an MCP tool into the bridge."""
        full_key = f"{server_name}:{tool_name}"
        tool_def = MCPToolDefinition(
            server_name=server_name,
            tool_name=tool_name,
            description=description,
            input_schema=input_schema,
            is_mutating=is_mutating,
            handler=handler
        )
        self.tools[full_key] = tool_def

    def validate_nested_arguments(
        self,
        value: Any,
        context: str = "",
        tool_name: str = ""
    ) -> Tuple[bool, str, Any]:
        """
        遞迴安全檢查引數資料結構 (P0-02)：
        支援 dict、list、tuple、set、str 的深度遞迴掃描。
        在任何巢狀層級針對 path / command / sql / credential 執行強制安全門禁。
        """
        # 1. 巢狀字典處理
        if isinstance(value, dict):
            sanitized_dict = {}
            for k, v in value.items():
                child_ctx = f"{context}.{k}" if context else str(k)
                # 亦檢查 Key 本身是否含有攻擊代碼
                if isinstance(k, str) and ("\x00" in k or "%00" in k):
                    return False, "安全阻斷：鍵名偵測到空字節注入攻擊", value
                is_safe, reason, clean_v = self.validate_nested_arguments(v, context=child_ctx, tool_name=tool_name)
                if not is_safe:
                    return False, reason, value
                sanitized_dict[k] = clean_v
            return True, "Security validation passed", sanitized_dict

        # 2. 巢狀清單 / 元組 / 集合處理
        if isinstance(value, (list, tuple, set)):
            sanitized_items = []
            for idx, item in enumerate(value):
                child_ctx = f"{context}[{idx}]"
                is_safe, reason, clean_item = self.validate_nested_arguments(item, context=child_ctx, tool_name=tool_name)
                if not is_safe:
                    return False, reason, value
                sanitized_items.append(clean_item)
            if isinstance(value, tuple):
                return True, "Security validation passed", tuple(sanitized_items)
            if isinstance(value, set):
                return True, "Security validation passed", set(sanitized_items)
            return True, "Security validation passed", sanitized_items

        # 3. 字串值安全檢查 (依據 context 與內容特徵啟動對應安全門禁)
        if isinstance(value, str):
            ctx_lower = context.lower()

            # A. 路徑安全檢查 (Path Security Gate)
            is_path_ctx = any(k in ctx_lower for k in ("path", "file", "dir", "uri", "target", "dest", "source", "location"))
            has_path_features = any(feat in value for feat in ("..", "/", "\\", "~", "%2e", "%2E", "\uff0e", "\x00", "%00"))

            if is_path_ctx or (has_path_features and not any(ck in ctx_lower for ck in ("command", "cmd", "exec", "sql", "query"))):
                decoded_v = unquote(value)
                normalized_v = unicodedata.normalize('NFKC', decoded_v)

                if "\x00" in normalized_v or "%00" in normalized_v:
                    return False, "安全阻斷：偵測到空字節注入攻擊", value

                if ".." in normalized_v or normalized_v.startswith("/") or normalized_v.startswith("~") or "/" in normalized_v or "\\" in normalized_v:
                    try:
                        raw_p = Path(normalized_v).expanduser()
                        if raw_p.is_absolute():
                            resolved = raw_p.resolve()
                        else:
                            resolved = (self.workspace_root / raw_p).resolve()
                    except Exception as e:
                        return False, f"安全阻斷：無效路徑格式 ({e})", value

                    # 邊界檢查：必須鎖定在 workspace_root 內
                    try:
                        resolved.relative_to(self.workspace_root)
                    except ValueError:
                        return False, f"安全阻斷：MCP 存取路徑 {resolved} 超出工作區邊界 {self.workspace_root}", value

                    # 符號連結攻擊防護
                    if raw_p.is_symlink():
                        return False, f"安全阻斷：禁止直接存取符號連結 (Symlink not allowed: {raw_p})", value
                    for parent in resolved.parents:
                        if parent == self.workspace_root or self.workspace_root in parent.parents:
                            if parent.is_symlink():
                                return False, f"安全阻斷：工作區內禁止穿越符號連結目錄 ({parent})", value

                    # 敏感黑名單檔案與路徑檢查
                    sensitive_names = {
                        ".ssh", ".gnupg", ".aws", ".azure", ".gcp", ".env", ".env.local",
                        "config.yaml", ".git", ".kube", ".docker", ".npmrc", ".bash_history",
                        ".vscode", ".idea", ".terraform", "id_rsa", "id_ed25519", "authorized_keys"
                    }
                    if any(name in resolved.parts for name in sensitive_names):
                        return False, f"安全阻斷：禁止 MCP 存取高敏感資安路徑 {resolved}", value

                    for sensitive in BLOCKED_SENSITIVE_PATHS:
                        if resolved == sensitive or sensitive in resolved.parents:
                            return False, f"安全阻斷：禁止 MCP 存取高敏感資安路徑 {resolved}", value

            # B. 破壞性 Shell 指令檢查 (Shell Command Security Gate)
            is_cmd_ctx = any(k in ctx_lower for k in ("command", "cmd", "exec", "shell", "script", "bash", "sh"))
            if is_cmd_ctx:
                for pattern in DANGEROUS_COMMAND_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        return False, f"安全阻斷：偵測到高危系統破壞性指令 ({pattern})", value
            else:
                for pattern in [r"\brm\s+-[rfRF]+\s+/", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", r"\bmkfs\b", r"\bdd\s+if="]:
                    if re.search(pattern, value, re.IGNORECASE):
                        return False, f"安全阻斷：偵測到高危系統破壞性指令 ({pattern})", value

            # C. 變更性 SQL 語句檢查 (SQL Mutation Security Gate)
            is_sql_ctx = any(k in ctx_lower for k in ("sql", "query", "statement", "mutation"))
            is_readonly_tool = "readonly" in tool_name.lower() or "query" in tool_name.lower()
            if (is_sql_ctx or is_readonly_tool) and is_readonly_tool:
                for pattern in DESTRUCTIVE_SQL_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        return False, f"安全阻斷：唯讀 MCP 工具禁止執行變更性 SQL 指令 ({pattern})", value

            # D. 機密私鑰檢查 (Credential Security Gate)
            if any(k in ctx_lower for k in ("token", "credential", "password", "passwd", "secret", "key")):
                if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
                    return False, "安全阻斷：禁止在 MCP 引數中傳遞原始私鑰區塊", value

        return True, "Security validation passed", value

    def validate_and_sanitize_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Pre-execution security gate:
        Checks paths, dangerous shell commands, destructive SQL queries, and credentials recursively.
        Returns: (is_safe, error_reason, sanitized_arguments)
        """
        return self.validate_nested_arguments(arguments, context="", tool_name=tool_name)

    def invoke_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        human_approved: bool = False,
        approval_token: Optional[str] = None,
        trusted_caller: bool = False
    ) -> Dict[str, Any]:
        """
        Execute MCP tool invocation through the security bridge.
        """
        full_key = f"{server_name}:{tool_name}"
        if full_key not in self.tools:
            return {
                "status": "FAIL",
                "error_type": "ToolNotFound",
                "error": f"MCP Tool '{full_key}' is not registered."
            }

        tool_def = self.tools[full_key]

        # Prevent untrusted caller/model payload from injecting approval arguments
        if isinstance(arguments, dict):
            arguments = {k: v for k, v in arguments.items() if k not in ("human_approved", "approval_token", "trusted_caller")}

        # Step 1: Pre-Execution Security Gate
        is_safe, sec_reason, sanitized_args = self.validate_and_sanitize_arguments(tool_name, arguments)
        if not is_safe:
            return {
                "status": "FAIL",
                "error_type": "SecurityGateBlocked",
                "error": sec_reason,
                "server": server_name,
                "tool": tool_name
            }

        # Step 2: Mutating Human Approval Enforcement Gate (P0-02)
        # Agent / Untrusted caller passing boolean human_approved=True alone is strictly rejected.
        # Human approval MUST originate from registered approval_handler, cryptographic token, or verified internal trusted_caller.
        if tool_def.is_mutating:
            is_approved = (
                (self.approval_handler is not None and self.approval_handler(server_name, tool_name, sanitized_args)) or
                self.verify_approval_token(approval_token, full_key) or
                (trusted_caller and human_approved)
            )
            if not is_approved:
                return {
                    "status": "FAIL",
                    "error_type": "HumanApprovalRequired",
                    "error": f"Security Enforcement: Mutating tool '{full_key}' is blocked pending explicit human approval.",
                    "server": server_name,
                    "tool": tool_name,
                    "is_mutating": True
                }

        # Step 3: Invoke Handler
        if tool_def.handler:
            try:
                start_t = time.perf_counter()
                res = tool_def.handler(**sanitized_args)
                latency_ms = (time.perf_counter() - start_t) * 1000
                return {
                    "status": "SUCCESS",
                    "server": server_name,
                    "tool": tool_name,
                    "latency_ms": round(latency_ms, 3),
                    "result": res
                }
            except Exception as e:
                return {
                    "status": "FAIL",
                    "error_type": "ExecutionError",
                    "error": f"MCP Tool execution error: {e}"
                }
        else:
            return {
                "status": "SUCCESS",
                "server": server_name,
                "tool": tool_name,
                "result": {"message": f"MCP tool {full_key} validated and ready for external RPC bridge."}
            }
