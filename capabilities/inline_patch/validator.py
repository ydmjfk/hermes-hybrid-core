#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Health Validator for CAP-001 Inline Patch Capability
"""

import sys
from pathlib import Path
from typing import Tuple

try:
    from .inline_patch_engine import apply_inline_patch
except ImportError:
    from inline_patch_engine import apply_inline_patch


def validate_capability() -> Tuple[bool, str]:
    """Perform self-diagnostic check on the inline_patch capability."""
    temp_file = Path(__file__).resolve().parent / ".diag_temp.py"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("def foo():\n    return 1\n")

        res = apply_inline_patch(str(temp_file), "    return 1", "    return 2", validate_ast=True)
        if res["status"] != "SUCCESS":
            return False, f"Self-test failed: {res.get('error')}"

        with open(temp_file, "r", encoding="utf-8") as f:
            content = f.read()

        if "return 2" not in content:
            return False, "Self-test failed: content not modified as expected."

        return True, "CAP-001 Inline Patch Capability is healthy and operational."
    except Exception as e:
        return False, f"Exception during validation: {e}"
    finally:
        if temp_file.exists():
            temp_file.unlink(missing_ok=True)


if __name__ == "__main__":
    ok, msg = validate_capability()
    print(f"Status: {'PASS' if ok else 'FAIL'} | Message: {msg}")
    sys.exit(0 if ok else 1)
