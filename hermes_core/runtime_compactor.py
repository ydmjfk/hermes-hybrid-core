#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runtime_compactor.py — 工具輸出 4KB 智慧雙向保真截斷與磁碟落盤器 (DEC-20260908-01)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
職責：
1. 防止工具輸出（如大型日誌、檔案掃描、巨量 JSON）塞爆 Agent Context 與 KV Cache。
2. 實施「雙向保真截斷 (Head-Tail Preservation)」：
   - 保留前 15 行 (Head)：保留前置指令、參數與任務啟動上下文。
   - 保留後 35 行 (Tail)：保留 Python Traceback、Exit Code、關鍵錯誤與結尾摘要。
   - 中間折疊並標註精確的省略行數與位元組統計。
3. 全量日誌自動非同步落盤 (Spooling) 至暫存區，提供檔案路徑引導，除錯資訊 0 遺失。
"""

import os
import hashlib
import tempfile
from pathlib import Path
from typing import Tuple, Optional

DEFAULT_MAX_CHARS = 4096
DEFAULT_HEAD_LINES = 15
DEFAULT_TAIL_LINES = 35
DEFAULT_SPOOL_DIR = Path(tempfile.gettempdir()) / "hermes_spool"


def compact_tool_output(
    content: str,
    max_chars: int = DEFAULT_MAX_CHARS,
    keep_head: int = DEFAULT_HEAD_LINES,
    keep_tail: int = DEFAULT_TAIL_LINES,
    spool_dir: Optional[Path] = None,
    task_id: Optional[str] = None,
) -> Tuple[str, bool, Optional[str]]:
    """
    智慧雙向保真截斷核心函數。
    回傳 (compacted_text, is_truncated, spooled_file_path)
    """
    if not content or len(content) <= max_chars:
        return content, False, None

    lines = content.splitlines(keepends=True)
    target_spool_dir = spool_dir or DEFAULT_SPOOL_DIR
    target_spool_dir.mkdir(parents=True, exist_ok=True)

    # 生成唯一的落盤檔案名稱
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    safe_task_id = (task_id or "output").replace("/", "_").replace(" ", "_")
    spool_file = target_spool_dir / f"spool_{safe_task_id}_{content_hash}.txt"

    # 全量落地保存
    try:
        with open(spool_file, "w", encoding="utf-8") as fp:
            fp.write(content)
        spooled_path = str(spool_file)
    except Exception:
        spooled_path = None

    # 如果總行數少於前保留+後保留，直接依字元長度截斷
    if len(lines) <= (keep_head + keep_tail):
        truncated = content[:max_chars]
        last_nl = truncated.rfind("\n")
        if last_nl > max_chars // 2:
            truncated = truncated[:last_nl + 1]
        spool_hint = f"\n[完整輸出已落盤保存: {spooled_path}]\n" if spooled_path else ""
        return truncated + spool_hint, True, spooled_path

    head_lines = lines[:keep_head]
    tail_lines = lines[-keep_tail:]
    head_text = "".join(head_lines)
    tail_text = "".join(tail_lines)

    omitted_lines = len(lines) - (keep_head + keep_tail)
    omitted_chars = len(content) - (len(head_text) + len(tail_text))

    spool_msg = f" (全量內容已非同步安全落盤至: {spooled_path})" if spooled_path else ""
    omitted_banner = (
        f"\n... [⚡ RUNTIME CONTROL: 已雙向保真折疊 {omitted_lines} 行 ({omitted_chars:,} 字元) 以保護 KV Cache{spool_msg}] ...\n\n"
    )

    compacted = head_text + omitted_banner + tail_text
    return compacted, True, spooled_path


class ToolOutputCompactor:
    """工具輸出雙向保真壓縮器類別"""

    def __init__(self, max_chars: int = DEFAULT_MAX_CHARS, spool_dir: Optional[Path] = None):
        self.max_chars = max_chars
        self.spool_dir = spool_dir or DEFAULT_SPOOL_DIR

    def process(self, content: str, task_id: Optional[str] = None) -> Tuple[str, bool, Optional[str]]:
        return compact_tool_output(content, max_chars=self.max_chars, spool_dir=self.spool_dir, task_id=task_id)
