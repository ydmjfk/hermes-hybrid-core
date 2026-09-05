#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inline Patch Tool Entrypoint for Hermes Capability Library
"""

from typing import Dict, Any

try:
    from .inline_patch_engine import apply_inline_patch
except ImportError:
    from inline_patch_engine import apply_inline_patch


def inline_patch(file_path: str, target_block: str, replacement_block: str, allow_multiple: bool = False) -> Dict[str, Any]:
    """
    Aider-style precision search-and-replace block patch.

    Args:
        file_path: Absolute path to the file to modify.
        target_block: Exact block of lines to search for.
        replacement_block: Replacement block of lines.
        allow_multiple: Replace all matches if True, fail if False and duplicate.

    Returns:
        dict: {"status": "SUCCESS" | "FAIL", "diff": "...", "lines_changed": N, "error": None | str}
    """
    return apply_inline_patch(
        file_path=file_path,
        target_block=target_block,
        replacement_block=replacement_block,
        allow_multiple=allow_multiple,
        validate_ast=True
    )
