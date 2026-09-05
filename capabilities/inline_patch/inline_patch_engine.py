#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAP-001: Aider-Style Precision Inline Patch Engine (Promoted Capability)
========================================================================
A lightweight, zero-dependency, atomic search-and-replace patching engine.
Ensures strict exact matching, AST syntax validation for Python, unified diff generation,
and path sandbox boundaries.
"""

import os
import sys
import ast
import difflib
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

ALLOWED_ROOT = Path(os.environ.get("HERMES_WORKSPACE_ROOT", Path.home())).resolve()

# 敏感受保護檔案黑名單 (禁止 Agent 透過 patch 修改)
BLOCKED_SENSITIVE_TARGETS = {
    ".ssh", ".gnupg", ".env", "config.yaml", ".git", ".bashrc",
    ".profile", ".zshrc", ".bash_profile", "passwd", "shadow"
}


class InlinePatchError(Exception):
    """Base exception for InlinePatch failures."""
    pass


class TargetNotFoundError(InlinePatchError):
    """Raised when target_block cannot be found in the file."""
    pass


class AmbiguousTargetError(InlinePatchError):
    """Raised when target_block matches multiple locations without allow_multiple=True."""
    pass


class SyntaxValidationError(InlinePatchError):
    """Raised when the resulting Python file fails AST parsing."""
    pass


class SecurityBoundaryError(InlinePatchError):
    """Raised when the target file violates sandbox boundaries."""
    pass


def validate_path_sandbox(file_path: str) -> Path:
    """Validate that file_path is strictly within the allowed workspace boundary and not sensitive."""
    if not file_path:
        raise SecurityBoundaryError("檔案路徑不可為空")

    if "\x00" in file_path or "%00" in file_path:
        raise SecurityBoundaryError("偵測到空位元組注入 (Null byte injection)")

    try:
        resolved = Path(file_path).expanduser().resolve()
    except Exception as e:
        raise SecurityBoundaryError(f"無效的檔案路徑: {file_path} ({e})")

    # 1. Check if resolved is within ALLOWED_ROOT
    try:
        resolved.relative_to(ALLOWED_ROOT)
    except ValueError:
        raise SecurityBoundaryError(f"安全阻斷：路徑 {resolved} 超出工作區邊界 {ALLOWED_ROOT}")

    # 2. Check against sensitive file blacklist
    for part in resolved.parts:
        if part in BLOCKED_SENSITIVE_TARGETS:
            raise SecurityBoundaryError(f"安全阻斷：禁止修補高敏感保護目標 '{part}' (路徑: {resolved})")

    # 3. Check system directory escapes
    for sys_dir in ("/etc", "/proc", "/sys", "/dev", "/root"):
        if str(resolved).startswith(sys_dir):
            raise SecurityBoundaryError(f"安全阻斷：禁止存取系統核心目錄 '{resolved}'")

    return resolved


def find_block_matches(content_lines: List[str], target_lines: List[str]) -> List[int]:
    """Find all starting 0-indexed line numbers where target_lines match content_lines exactly."""
    if not target_lines:
        return []
    
    matches = []
    target_len = len(target_lines)
    max_start = len(content_lines) - target_len + 1

    for i in range(max_start):
        if content_lines[i:i + target_len] == target_lines:
            matches.append(i)

    return matches


def find_normalized_matches(content_lines: List[str], target_lines: List[str]) -> List[int]:
    """Fallback fuzzy match: compare lines ignoring trailing whitespace/newlines."""
    norm_content = [l.rstrip() for l in content_lines]
    norm_target = [l.rstrip() for l in target_lines]

    matches = []
    target_len = len(norm_target)
    max_start = len(norm_content) - target_len + 1

    for i in range(max_start):
        if norm_content[i:i + target_len] == norm_target:
            matches.append(i)

    return matches


def apply_inline_patch(
    file_path: str,
    target_block: str,
    replacement_block: str,
    allow_multiple: bool = False,
    validate_ast: bool = True
) -> Dict[str, Any]:
    """
    Atomically apply an inline patch by replacing `target_block` with `replacement_block`.

    Args:
        file_path: Absolute or relative path to the target file.
        target_block: Exact block of lines to search for.
        replacement_block: Exact replacement block of lines.
        allow_multiple: Whether to allow replacing multiple occurrences.
        validate_ast: If True and target is a .py file, perform AST parsing.

    Returns:
        dict containing status, diff, lines_changed, matched_lines, and details.
    """
    try:
        resolved_path = validate_path_sandbox(file_path)
    except SecurityBoundaryError as e:
        return {
            "status": "FAIL",
            "error_type": "SecurityBoundaryError",
            "error": str(e),
            "diff": "",
            "lines_changed": 0
        }

    if not resolved_path.exists():
        return {
            "status": "FAIL",
            "error_type": "FileNotFoundError",
            "error": f"檔案不存在: {resolved_path}",
            "diff": "",
            "lines_changed": 0
        }

    if not resolved_path.is_file():
        return {
            "status": "FAIL",
            "error_type": "NotAFileError",
            "error": f"路徑非普通檔案: {resolved_path}",
            "diff": "",
            "lines_changed": 0
        }

    # Read original file
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            original_content = f.read()
    except UnicodeDecodeError:
        return {
            "status": "FAIL",
            "error_type": "BinaryOrEncodingError",
            "error": f"無法以 UTF-8 解碼檔案（可能是二進位檔）: {resolved_path}",
            "diff": "",
            "lines_changed": 0
        }

    # Split lines preserving exact characters
    original_lines = original_content.splitlines(keepends=True)
    target_lines = target_block.splitlines(keepends=True)
    replacement_lines = replacement_block.splitlines(keepends=True)

    # Normalize newline at end if target or replacement has single trailing newline
    if target_lines and not target_lines[-1].endswith(("\n", "\r")):
        # If original content has newlines, ensure consistent comparison
        if original_lines and original_lines[0].endswith("\n"):
            target_lines[-1] += "\n"
    if replacement_lines and not replacement_lines[-1].endswith(("\n", "\r")):
        if original_lines and original_lines[0].endswith("\n"):
            replacement_lines[-1] += "\n"

    # Step 1: Search exact matches
    match_indices = find_block_matches(original_lines, target_lines)

    # Step 2: Fallback normalized search if no exact match
    is_fuzzy = False
    if not match_indices:
        match_indices = find_normalized_matches(original_lines, target_lines)
        if match_indices:
            is_fuzzy = True

    # Error handling for matches
    if not match_indices:
        # Provide helpful context clues
        snippet = target_block[:120].strip()
        return {
            "status": "FAIL",
            "error_type": "TargetNotFoundError",
            "error": f"在檔案中找不到目標區塊。\n搜尋片段摘要: [{snippet}...]",
            "diff": "",
            "lines_changed": 0,
            "total_file_lines": len(original_lines)
        }

    if len(match_indices) > 1 and not allow_multiple:
        line_numbers = [idx + 1 for idx in match_indices]
        return {
            "status": "FAIL",
            "error_type": "AmbiguousTargetError",
            "error": f"目標區塊在多處出現 (行號: {line_numbers})。請提供更多前後上下文以保持唯一性，或指定 allow_multiple=True。",
            "diff": "",
            "lines_changed": 0,
            "match_count": len(match_indices)
        }

    # Step 3: Construct patched content
    new_lines = []
    last_end = 0
    target_len = len(target_lines)

    for start_idx in match_indices:
        new_lines.extend(original_lines[last_end:start_idx])
        new_lines.extend(replacement_lines)
        last_end = start_idx + target_len

    new_lines.extend(original_lines[last_end:])
    patched_content = "".join(new_lines)

    # Step 4: Python AST syntax validation if applicable
    if validate_ast and resolved_path.suffix == ".py":
        try:
            ast.parse(patched_content, filename=str(resolved_path))
        except SyntaxError as e:
            return {
                "status": "FAIL",
                "error_type": "SyntaxValidationError",
                "error": f"語法防護阻斷：補丁應用後會導致 Python 語法錯誤 (行 {e.lineno}: {e.msg})",
                "diff": "",
                "lines_changed": 0,
                "syntax_error_details": {
                    "line": e.lineno,
                    "offset": e.offset,
                    "text": e.text
                }
            }

    # Step 5: Generate Unified Diff
    diff_gen = difflib.unified_diff(
        original_lines,
        new_lines,
        fromfile=f"a/{resolved_path.name}",
        tofile=f"b/{resolved_path.name}",
        lineterm=""
    )
    unified_diff = "\n".join(diff_gen)

    # Step 6: Atomic Disk Write (write to temp file then atomic rename)
    temp_file = resolved_path.with_suffix(f".tmp.{os.getpid()}")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(patched_content)
        os.replace(temp_file, resolved_path)
    except Exception as e:
        if temp_file.exists():
            temp_file.unlink(missing_ok=True)
        return {
            "status": "FAIL",
            "error_type": "DiskWriteError",
            "error": f"磁碟原子寫入失敗: {e}",
            "diff": "",
            "lines_changed": 0
        }

    return {
        "status": "SUCCESS",
        "file_path": str(resolved_path),
        "matches_replaced": len(match_indices),
        "match_lines": [idx + 1 for idx in match_indices],
        "is_fuzzy_match": is_fuzzy,
        "diff": unified_diff,
        "lines_changed": abs(len(new_lines) - len(original_lines)) + len(target_lines),
        "error": None
    }


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: inline_patch_engine.py <file_path> <target_block> <replacement_block> [--allow-multiple]")
        sys.exit(1)

    path = sys.argv[1]
    tgt = sys.argv[2]
    rep = sys.argv[3]
    allow_mult = "--allow-multiple" in sys.argv

    result = apply_inline_patch(path, tgt, rep, allow_multiple=allow_mult)
    import json
    print(json.dumps(result, ensure_ascii=False, indent=2))
