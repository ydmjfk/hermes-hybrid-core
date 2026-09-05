#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agent Loop Recover Tool Entrypoint for Hermes Capability Library
"""

from typing import Dict, Any

try:
    from .diagnostic_recover_engine import DiagnosticRecoverEngine, DiagnosticSignature
except ImportError:
    from diagnostic_recover_engine import DiagnosticRecoverEngine, DiagnosticSignature


def extract_and_diagnose_error(exit_code: int, stderr: str, stdout: str = "") -> Dict[str, Any]:
    """
    Claude-Style error diagnostic feature extractor and recovery directive generator.

    Args:
        exit_code: Process exit code.
        stderr: Raw standard error output.
        stdout: Standard output string.

    Returns:
        dict: {"attempt": N, "is_escalated": bool, "signature": dict, "directive_markdown": str}
    """
    engine = DiagnosticRecoverEngine()
    sig = engine.extract_signature(exit_code, stderr, stdout)
    return engine.generate_recovery_directive(sig)
