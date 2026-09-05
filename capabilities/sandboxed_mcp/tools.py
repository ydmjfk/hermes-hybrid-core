#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sandboxed MCP Tool Entrypoint for Hermes Capability Library
"""

from typing import Dict, Any, List, Optional
try:
    from .sandboxed_mcp_bridge import SandboxedMCPBridge
except ImportError:
    from sandboxed_mcp_bridge import SandboxedMCPBridge


def get_sandboxed_mcp_bridge(workspace_root: str = str(Path.home())) -> SandboxedMCPBridge:
    """Get initialized SandboxedMCPBridge instance."""
    return SandboxedMCPBridge(workspace_root)
