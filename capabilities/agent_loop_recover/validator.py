#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Health Validator for CAP-003 Agent Loop Recover Capability
"""

import sys
from typing import Tuple

try:
    from .diagnostic_recover_engine import DiagnosticRecoverEngine, ErrorCategory
except ImportError:
    from diagnostic_recover_engine import DiagnosticRecoverEngine, ErrorCategory


def validate_capability() -> Tuple[bool, str]:
    """Perform self-diagnostic check on the agent_loop_recover capability."""
    try:
        engine = DiagnosticRecoverEngine()
        sample_stderr = """
  File "${HERMES_WORKSPACE_ROOT}/test.py", line 10
    print("hello"
                 ^
SyntaxError: was never closed
"""
        sig = engine.extract_signature(exit_code=1, stderr=sample_stderr)
        if sig.category != ErrorCategory.SYNTAX_ERROR:
            return False, f"Signature categorization failed: {sig.category}"

        directive = engine.generate_recovery_directive(sig)
        if "🚨 錯誤自癒診斷提示" not in directive.get("directive_markdown", ""):
            return False, "Directive markdown generation failed."

        return True, "CAP-003 Agent Loop Recover Capability is healthy and operational."
    except Exception as e:
        return False, f"Exception during validation: {e}"


if __name__ == "__main__":
    ok, msg = validate_capability()
    print(f"Status: {'PASS' if ok else 'FAIL'} | Message: {msg}")
    sys.exit(0 if ok else 1)
