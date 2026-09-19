#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runtime_compactor.py — 工具輸出 4KB 智慧雙向保真截斷與磁碟落盤器 (DEC-20260908-01 / SEC-HARDENED v3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
職責與安全保證：
1. 【0 上下文溢出保證】：保證任何輸入下，輸出字元數嚴格 <= max_chars。
2. 【雙向保真截斷 (Head-Tail Preservation)】：
   - Head：保留前置指令、參數與任務啟動上下文。
   - Tail：保留 Python Traceback、Exit Code、關鍵錯誤與結尾摘要。
3. 【工業級無菌落盤安全 (SEC-HARDENED)】：
   - 預設路徑隔離：mask_spool_path 預設為 True，預設不向模型/外部暴露真實實體路徑。
   - 權限約束：目錄嚴格 0700、檔案嚴格 0600 (POSIX 最小特權)。
   - 競態防禦：採用 os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW 防禦符號連結劫持；拒絕任何 Symlink 參照。
   - 深度脫敏：落盤前強制執行 sanitize_secrets 物理脫敏，抹除常見憑證格式。
   - 真實位元組配額：單檔 10MB (UTF-8 Bytes) 上限。
   - 雙重容量有界與 TTL：目錄總容量 100MB 上限、最多 100 檔、24 小時 (TTL) 自動滾動過期清理。
   - 檔名淨化：task_id 採嚴格正則白名單過濾 (禁用點號與特殊字元)，徹底阻斷目錄穿越。
"""

import collections
import hashlib
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple

from hermes_core.security_filter import sanitize_secrets

DEFAULT_MAX_CHARS = 4096
DEFAULT_HEAD_LINES = 15
DEFAULT_TAIL_LINES = 35
DEFAULT_SPOOL_DIR = Path(tempfile.gettempdir()) / "hermes_spool"

# 安全配額常數 (以真實位元組 UTF-8 計算)
MAX_SPOOL_FILE_BYTES = 10 * 1024 * 1024    # 10MB 單檔落盤上限 (Bytes)
MAX_SPOOL_DIR_BYTES = 100 * 1024 * 1024    # 100MB 目錄總容量上限 (Bytes)
MAX_SPOOL_DIR_FILES = 100                  # 目錄最多保留 100 個 spool 快照
SPOOL_FILE_TTL_SECONDS = 86400             # 24 小時 TTL 自動清理


def _sanitize_task_id(task_id: Optional[str]) -> str:
    """以嚴格安全字元白名單淨化 task_id，嚴禁點號、特殊字元、換行與路徑遍歷"""
    raw = str(task_id or "output").strip()
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "_", raw)[:64]
    # 清理連續底線並去除首尾底線
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "output"


def _clean_spool_dir_quota(
    spool_dir: Path,
    max_files: int = MAX_SPOOL_DIR_FILES,
    max_total_bytes: int = MAX_SPOOL_DIR_BYTES,
    ttl_seconds: int = SPOOL_FILE_TTL_SECONDS,
) -> None:
    """
    維持 spool 目錄配額健全度：
    1. 超過 TTL (24h) 的舊快照自動刪除。
    2. 檢查總容量 (<=100MB) 與總檔數 (<=100)，超限時按 mtime FIFO 滾動清理。
    3. 自動拔除任何異常的 symlink 檔案。
    """
    try:
        now = time.time()
        file_entries = []

        for p in spool_dir.glob("spool_*.txt"):
            if p.is_symlink():
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
                continue

            if p.is_file():
                try:
                    st = p.stat()
                    # 1. TTL 清理
                    if now - st.st_mtime > ttl_seconds:
                        p.unlink(missing_ok=True)
                        continue
                    file_entries.append((p, st.st_size, st.st_mtime))
                except OSError:
                    pass

        # 2. 總檔案數與總容量 FIFO 清理
        file_entries.sort(key=lambda x: x[2])  # 由舊到新排序
        total_bytes = sum(x[1] for x in file_entries)
        total_files = len(file_entries)

        for p, size, _ in file_entries:
            if total_files <= max_files and total_bytes <= max_total_bytes:
                break
            try:
                p.unlink(missing_ok=True)
                total_files -= 1
                total_bytes -= size
            except OSError:
                pass
    except Exception:
        pass


def _safe_spool_write(
    content: str,
    spool_dir: Path,
    safe_task_id: str,
    content_hash: str,
) -> Optional[str]:
    """
    高安全物理無菌落盤：
    1. 目錄強制 0700、檔案強制 0600
    2. 防禦符號連結競爭 (O_EXCL | O_NOFOLLOW)，拒絕任何既有 Symlink
    3. 寫入前執行憑證敏感資訊脫敏 (sanitize_secrets)
    4. 實施真實 UTF-8 位元組截斷 (單檔上限 10MB)
    5. 執行 100MB / 100 檔 / 24h TTL 自動滾動清理
    """
    try:
        spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(spool_dir, 0o700)
        except OSError:
            pass

        _clean_spool_dir_quota(spool_dir)

        spool_file = spool_dir / f"spool_{safe_task_id}_{content_hash}.txt"

        # 嚴格校驗已存在的檔案：若為 Symlink 則拔除；若為正常檔案則安全複用
        if spool_file.is_symlink():
            try:
                spool_file.unlink(missing_ok=True)
            except OSError:
                return None
        elif spool_file.is_file():
            return str(spool_file)

        # 落盤前物理脫敏
        sanitized_content = sanitize_secrets(content)

        # 以真實 UTF-8 位元組數計算與截斷
        encoded_bytes = sanitized_content.encode("utf-8")
        if len(encoded_bytes) > MAX_SPOOL_FILE_BYTES:
            truncated_bytes = encoded_bytes[:MAX_SPOOL_FILE_BYTES]
            sanitized_content = (
                truncated_bytes.decode("utf-8", errors="ignore")
                + "\n... [TRUNCATED: Spool file exceeded 10MB safety quota] ...\n"
            )

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(spool_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(sanitized_content)

        return str(spool_file)
    except Exception:
        return None


def compact_tool_output(
    content: str,
    max_chars: int = DEFAULT_MAX_CHARS,
    keep_head: int = DEFAULT_HEAD_LINES,
    keep_tail: int = DEFAULT_TAIL_LINES,
    spool_dir: Optional[Path] = None,
    task_id: Optional[str] = None,
    mask_spool_path: bool = True,  # 預設啟用遮罩，防止伺服器實體路徑外洩
) -> Tuple[str, bool, Optional[str]]:
    """
    智慧雙向保真截斷核心函數。
    保證：回傳的 compacted 字串長度絕對不超過 max_chars。
    mask_spool_path 預設為 True，不在回傳文字中暴露伺服器檔案路徑。
    回傳 (compacted_text, is_truncated, spooled_file_path)
    """
    if not content or len(content) <= max_chars:
        return content, False, None

    target_spool_dir = spool_dir or DEFAULT_SPOOL_DIR
    safe_task_id = _sanitize_task_id(task_id)
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]

    # 全量安全落盤
    spooled_path = _safe_spool_write(
        content=content,
        spool_dir=target_spool_dir,
        safe_task_id=safe_task_id,
        content_hash=content_hash,
    )

    # 決定提示訊息中的路徑展示方式（預設遮罩實體檔案路徑）
    if spooled_path:
        if mask_spool_path:
            spool_label = f"RefID:{safe_task_id}_{content_hash}"
        else:
            spool_label = spooled_path
        spool_hint_msg = f" (全量內容已安全落盤至: {spool_label})"
    else:
        spool_hint_msg = ""

    lines = content.splitlines(keepends=True)

    # 情況 A：總行數較少（例如單行或少行超長），直接以字元預算折疊
    if len(lines) <= (keep_head + keep_tail):
        omitted_chars = len(content) - max_chars
        banner = (
            f"\n... [⚡ RUNTIME CONTROL: 單行/少行內容超限，已折疊 {omitted_chars:,} 字元"
            f"{spool_hint_msg}] ...\n"
        )
        if len(banner) >= max_chars:
            return content[:max_chars], True, spooled_path

        budget_rem = max_chars - len(banner)
        head_budget = budget_rem // 3
        tail_budget = budget_rem - head_budget

        head_part = content[:head_budget]
        tail_part = content[-tail_budget:] if tail_budget > 0 else ""
        compacted = head_part + banner + tail_part
        return compacted[:max_chars], True, spooled_path

    # 情況 B：多行結構化輸出（雙向保留行數）
    head_lines = lines[:keep_head]
    tail_lines = lines[-keep_tail:]
    head_text = "".join(head_lines)
    tail_text = "".join(tail_lines)

    omitted_lines = len(lines) - (keep_head + keep_tail)
    omitted_chars = len(content) - (len(head_text) + len(tail_text))

    omitted_banner = (
        f"\n... [⚡ RUNTIME CONTROL: 已雙向保真折疊 {omitted_lines} 行 ({omitted_chars:,} 字元) 以保護 KV Cache"
        f"{spool_hint_msg}] ...\n\n"
    )

    combined = head_text + omitted_banner + tail_text

    # 嚴格預算門禁：若 head/tail 本身每行極長導致超過 max_chars，動態微縮以確保 <= max_chars
    if len(combined) > max_chars:
        banner_len = len(omitted_banner)
        if banner_len >= max_chars:
            return combined[:max_chars], True, spooled_path

        available_budget = max_chars - banner_len
        # Head 分配 35%，Tail (含錯誤與堆疊) 分配 65%
        head_alloc = int(available_budget * 0.35)
        tail_alloc = available_budget - head_alloc

        head_fitted = head_text[:head_alloc]
        tail_fitted = tail_text[-tail_alloc:] if tail_alloc > 0 else ""
        compacted = head_fitted + omitted_banner + tail_fitted
        return compacted[:max_chars], True, spooled_path

    return combined, True, spooled_path


class ToolOutputCompactor:
    """工具輸出雙向保真壓縮器類別"""

    def __init__(
        self,
        max_chars: int = DEFAULT_MAX_CHARS,
        spool_dir: Optional[Path] = None,
        mask_spool_path: bool = True,  # 預設啟用安全遮罩
    ):
        self.max_chars = max_chars
        self.spool_dir = spool_dir or DEFAULT_SPOOL_DIR
        self.mask_spool_path = mask_spool_path

    def process(self, content: str, task_id: Optional[str] = None) -> Tuple[str, bool, Optional[str]]:
        return compact_tool_output(
            content,
            max_chars=self.max_chars,
            spool_dir=self.spool_dir,
            task_id=task_id,
            mask_spool_path=self.mask_spool_path,
        )

    @classmethod
    def compact_text(
        cls,
        content: str,
        max_chars: int = DEFAULT_MAX_CHARS,
        task_id: Optional[str] = None,
        mask_spool_path: bool = True,
        max_bytes: Optional[int] = None,  # 向前相容別名
    ) -> str:
        """便捷類別方法：直接回傳壓縮後的字串結果 (預設 mask_spool_path=True)"""
        limit = max_bytes if max_bytes is not None else max_chars
        compacted, _, _ = compact_tool_output(
            content,
            max_chars=limit,
            task_id=task_id,
            mask_spool_path=mask_spool_path,
        )
        return compacted
