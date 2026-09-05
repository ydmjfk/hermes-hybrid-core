#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAP-004: Pi-Style Minimal Extension Dynamic Registry Engine (Promoted Capability)
=================================================================================
A hot-pluggable, zero-dependency extension discovery and dispatch engine.
Features:
  1. Auto-Discovery & Manifest Parsing from capabilities directories.
  2. Health Self-Check Quarantine (Executes validator.py before activation).
  3. Automatic Tool Schema Generation from python docstrings & type hints.
  4. Safe Dynamic Dispatcher with sandbox boundary verification.
"""

import os
import sys
import json
import inspect
import hashlib
import importlib.util
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Tuple

ALLOWED_ROOT = Path.home().resolve()
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@dataclass
class ExtensionManifest:
    capability_id: str
    name: str
    version: str
    description: str = ""
    author: str = ""
    approved_by: str = ""
    entrypoint: str = ""
    files: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    integrity: Dict[str, Any] = field(default_factory=dict)
    trust: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExtensionManifest":
        return cls(
            capability_id=data.get("capability_id", ""),
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            approved_by=data.get("approved_by", ""),
            entrypoint=data.get("entrypoint", ""),
            files=data.get("files", []),
            dependencies=data.get("dependencies", []),
            integrity=data.get("integrity", {}),
            trust=data.get("trust", {})
        )


@dataclass
class RegisteredTool:
    tool_name: str
    capability_id: str
    description: str
    function: Callable
    parameters_schema: Dict[str, Any]
    source_file: str
    is_mutating: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "capability_id": self.capability_id,
            "description": self.description,
            "source_file": self.source_file,
            "schema": self.parameters_schema,
            "is_mutating": self.is_mutating
        }


class ExtensionRegistryEngine:
    """
    Pi-style minimal extension registry and dynamic tool dispatcher.
    """

    def __init__(
        self,
        capabilities_dir: str = str(Path(__file__).resolve().parent),
        approval_handler: Optional[Callable[[str, Dict[str, Any]], bool]] = None
    ):
        self.capabilities_dir = Path(capabilities_dir).expanduser().resolve()
        self.active_extensions: Dict[str, ExtensionManifest] = {}
        self.quarantined_extensions: Dict[str, Dict[str, Any]] = {}
        self.registered_tools: Dict[str, RegisteredTool] = {}
        self.approval_handler = approval_handler

        # Lazy initialize sandboxed MCP bridge for pre-execution argument validation
        try:
            from capabilities.sandboxed_mcp.sandboxed_mcp_bridge import SandboxedMCPBridge
            self._mcp_bridge = SandboxedMCPBridge(workspace_root=str(self.capabilities_dir.parent))
        except Exception:
            try:
                from sandboxed_mcp.sandboxed_mcp_bridge import SandboxedMCPBridge
                self._mcp_bridge = SandboxedMCPBridge(workspace_root=str(self.capabilities_dir.parent))
            except Exception:
                self._mcp_bridge = None

    def discover_and_register_all(self) -> Dict[str, Any]:
        """
        Scan capabilities directory, run health validation, and register healthy tools.
        """
        self.active_extensions.clear()
        self.quarantined_extensions.clear()
        self.registered_tools.clear()

        if not self.capabilities_dir.exists() or not self.capabilities_dir.is_dir():
            return {
                "status": "DIR_NOT_FOUND",
                "registered_extensions_count": 0,
                "registered_tools_count": 0
            }

        for sub_dir in sorted(self.capabilities_dir.iterdir()):
            if sub_dir.is_dir() and not sub_dir.name.startswith("."):
                self._process_extension_directory(sub_dir)

        return {
            "status": "DISCOVERY_COMPLETE",
            "active_extensions": list(self.active_extensions.keys()),
            "quarantined_extensions": list(self.quarantined_extensions.keys()),
            "registered_tools": list(self.registered_tools.keys()),
            "total_active": len(self.active_extensions),
            "total_quarantined": len(self.quarantined_extensions),
            "total_tools": len(self.registered_tools)
        }

    def _process_extension_directory(self, ext_dir: Path) -> None:
        manifest_file = ext_dir / "manifest.json"
        if not manifest_file.exists():
            return

        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            manifest = ExtensionManifest.from_dict(data)
        except Exception as e:
            self.quarantined_extensions[ext_dir.name] = {
                "reason": f"Manifest JSON parsing error: {e}",
                "path": str(ext_dir)
            }
            return

        # 1. 結構與基本宣告校驗
        if not manifest.capability_id or not manifest.name:
            self.quarantined_extensions[ext_dir.name] = {
                "reason": "Invalid manifest: missing capability_id or name",
                "path": str(ext_dir)
            }
            return

        # 2. 來源路徑信任根檢查 (Source path inside trusted capabilities root)
        try:
            ext_dir.resolve().relative_to(self.capabilities_dir)
        except ValueError:
            self.quarantined_extensions[manifest.name] = {
                "capability_id": manifest.capability_id,
                "reason": f"Security Gate Blocked: untrusted capability path outside {self.capabilities_dir}",
                "path": str(ext_dir)
            }
            return

        # 3. SHA-256 完整性校驗 (Integrity Allowlist Verification - P0-03 & P1-05)
        integrity = manifest.integrity
        if not integrity or integrity.get("algorithm") != "sha256" or not integrity.get("files"):
            self.quarantined_extensions[manifest.name] = {
                "capability_id": manifest.capability_id,
                "reason": "Security Gate Blocked: missing or invalid SHA-256 integrity block in manifest",
                "path": str(ext_dir)
            }
            return

        files_map = integrity.get("files", {})
        for rel_file, expected_hash in files_map.items():
            fpath = ext_dir / rel_file
            if not fpath.exists() or not fpath.is_file():
                self.quarantined_extensions[manifest.name] = {
                    "capability_id": manifest.capability_id,
                    "reason": f"Security Gate Blocked: integrity file missing '{rel_file}'",
                    "path": str(ext_dir)
                }
                return
            hasher = hashlib.sha256()
            with open(fpath, "rb") as fp:
                while chunk := fp.read(65536):
                    hasher.update(chunk)
            actual_hash = hasher.hexdigest()
            if actual_hash != expected_hash:
                self.quarantined_extensions[manifest.name] = {
                    "capability_id": manifest.capability_id,
                    "reason": f"Security Gate Blocked: SHA-256 integrity mismatch for '{rel_file}'",
                    "path": str(ext_dir)
                }
                return

        # 4. 密碼學數位簽章與信任根校驗 (Cryptographic Trust Root Signature Verification - P0-03)
        trust = manifest.trust
        if not trust or not trust.get("approved"):
            self.quarantined_extensions[manifest.name] = {
                "capability_id": manifest.capability_id,
                "reason": "Security Gate Blocked: Capability trust approval missing or not approved (trust.approved != true)",
                "path": str(ext_dir)
            }
            return

        sig_hex = trust.get("signature")
        try:
            from hermes_core.trust_root import verify_capability_signature
            is_valid_sig, sig_reason = verify_capability_signature(
                capability_id=manifest.capability_id,
                version=manifest.version,
                files_map=files_map,
                signature_hex=sig_hex
            )
        except Exception as e:
            is_valid_sig, sig_reason = False, f"Trust root verification error: {e}"

        if not is_valid_sig:
            self.quarantined_extensions[manifest.name] = {
                "capability_id": manifest.capability_id,
                "reason": f"Security Gate Blocked: Cryptographic signature verification failed ({sig_reason})",
                "path": str(ext_dir)
            }
            return

        # 5. 健全度自我驗證 (只有通過前置誠信與授權驗證後，方允許載入 validator.py)
        validator_file = ext_dir / "validator.py"
        if validator_file.exists():
            is_healthy, diag_msg = self._run_validator(validator_file)
            if not is_healthy:
                self.quarantined_extensions[manifest.name] = {
                    "capability_id": manifest.capability_id,
                    "reason": f"Health Validator Failed: {diag_msg}",
                    "path": str(ext_dir)
                }
                return

        # Dynamic Module Import & Tool Registration
        entrypoint = manifest.entrypoint
        if entrypoint and ":" in entrypoint:
            module_rel_path, func_name = entrypoint.split(":", 1)
            module_file = ext_dir / module_rel_path
            if module_file.exists():
                try:
                    tool_func = self._import_callable(module_file, func_name)
                    if callable(tool_func):
                        schema = self._generate_param_schema(tool_func)
                        is_mutating = bool(data.get("is_mutating", False)) or any(
                            kw in manifest.name.lower() for kw in ("patch", "write", "delete", "recover", "deadletter")
                        )
                        reg_tool = RegisteredTool(
                            tool_name=manifest.name,
                            capability_id=manifest.capability_id,
                            description=manifest.description or (tool_func.__doc__ or "").strip(),
                            function=tool_func,
                            parameters_schema=schema,
                            source_file=str(module_file),
                            is_mutating=is_mutating
                        )
                        self.registered_tools[manifest.name] = reg_tool
                except Exception as e:
                    self.quarantined_extensions[manifest.name] = {
                        "capability_id": manifest.capability_id,
                        "reason": f"Import/Registration error: {e}",
                        "path": str(ext_dir)
                    }
                    return

        self.active_extensions[manifest.name] = manifest

    def _run_validator(self, validator_path: Path) -> Tuple[bool, str]:
        """Import validator module and execute validate_capability()."""
        parent_dir = str(validator_path.parent)
        added_to_path = False
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
            added_to_path = True

        try:
            spec = importlib.util.spec_from_file_location(
                f"validator_{validator_path.parent.name}",
                str(validator_path)
            )
            if not spec or not spec.loader:
                return False, "Failed to create module spec"
            val_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(val_mod)
            if hasattr(val_mod, "validate_capability"):
                return val_mod.validate_capability()
            return True, "No validate_capability function found, assumed pass"
        except Exception as e:
            return False, f"Exception during validator execution: {e}"
        finally:
            if added_to_path and parent_dir in sys.path:
                sys.path.remove(parent_dir)

    def _import_callable(self, file_path: Path, callable_name: str) -> Callable:
        parent_dir = str(file_path.parent)
        added_to_path = False
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
            added_to_path = True

        try:
            spec = importlib.util.spec_from_file_location(
                f"mod_{file_path.parent.name}_{file_path.stem}",
                str(file_path)
            )
            if not spec or not spec.loader:
                raise ImportError(f"Cannot load spec from {file_path}")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not hasattr(mod, callable_name):
                raise AttributeError(f"Module {file_path.name} has no function '{callable_name}'")
            return getattr(mod, callable_name)
        finally:
            if added_to_path and parent_dir in sys.path:
                sys.path.remove(parent_dir)

    def _generate_param_schema(self, func: Callable) -> Dict[str, Any]:
        """Generate JSON schema from function signature and type hints."""
        sig = inspect.signature(func)
        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            param_type = "string"
            if param.annotation is int:
                param_type = "integer"
            elif param.annotation is bool:
                param_type = "boolean"
            elif param.annotation is float:
                param_type = "number"
            elif param.annotation is dict:
                param_type = "object"
            elif param.annotation is list:
                param_type = "array"

            properties[param_name] = {
                "type": param_type,
                "description": f"Parameter {param_name}"
            }
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required
        }

    def dispatch(
        self,
        tool_name: str,
        human_approved: bool = False,
        approval_token: Optional[str] = None,
        trusted_caller: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Dispatch tool invocation safely with pre-execution security gate and human approval (P0-01, P0-02).
        """
        if tool_name not in self.registered_tools:
            return {
                "status": "FAIL",
                "error_type": "ToolNotFound",
                "error": f"Tool '{tool_name}' is not registered in active capabilities."
            }

        tool = self.registered_tools[tool_name]

        # Strip any caller injected approval fields
        for forbidden in ("human_approved", "approval_token", "trusted_caller"):
            kwargs.pop(forbidden, None)

        # Step 1: Pre-Execution Recursive Argument Security Gate (P0-01)
        if self._mcp_bridge is not None:
            is_safe, sec_reason, sanitized_args = self._mcp_bridge.validate_nested_arguments(kwargs, tool_name=tool_name)
            if not is_safe:
                return {
                    "status": "FAIL",
                    "error_type": "SecurityGateBlocked",
                    "error": sec_reason,
                    "tool_name": tool_name,
                    "capability_id": tool.capability_id
                }
        else:
            sanitized_args = kwargs

        # Step 2: Mutating Human Approval Enforcement Gate (P0-02)
        if tool.is_mutating:
            approved = (
                (self.approval_handler is not None and self.approval_handler(tool_name, sanitized_args)) or
                (self._mcp_bridge is not None and self._mcp_bridge.verify_approval_token(approval_token, f"extension:{tool_name}")) or
                (trusted_caller and human_approved)
            )
            if not approved:
                return {
                    "status": "FAIL",
                    "error_type": "HumanApprovalRequired",
                    "error": f"Security Enforcement: Mutating tool '{tool_name}' is blocked pending explicit human approval.",
                    "tool_name": tool_name,
                    "capability_id": tool.capability_id,
                    "is_mutating": True
                }

        # Step 3: Execute tool function
        try:
            res = tool.function(**sanitized_args)
            return {
                "status": "SUCCESS",
                "tool_name": tool_name,
                "capability_id": tool.capability_id,
                "result": res
            }
        except Exception as e:
            return {
                "status": "FAIL",
                "error_type": "ExecutionError",
                "tool_name": tool_name,
                "capability_id": tool.capability_id,
                "error": f"Tool execution failed: {e}"
            }
