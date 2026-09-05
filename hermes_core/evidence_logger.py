"""
evidence_logger.py — 統一客觀審計與結構化日誌記錄器
"""

import json
import logging
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from .config_loader import get_db_path, get_hermes_path
from .security_filter import sanitize_secrets, sanitize_dict

LOGS_DIR = get_hermes_path("logs")
LOGS_DIR.mkdir(parents=True, exist_ok=True)


MAX_TASK_ID_LENGTH: int = 128
MAX_TOOL_NAME_LENGTH: int = 128
MAX_SUMMARY_BYTES: int = 65536
MAX_JSON_DEPTH: int = 8


def _check_json_depth(obj: Any, current_depth: int = 1) -> bool:
    """防範深層巢狀 JSON 造成的記憶體耗盡或遞迴爆炸攻擊 (P2-02)"""
    if current_depth > MAX_JSON_DEPTH:
        return False
    if isinstance(obj, dict):
        return all(_check_json_depth(v, current_depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return all(_check_json_depth(v, current_depth + 1) for v in obj)
    return True


def get_logger(name: str) -> logging.Logger:
    """取得標準格式化之 Logger"""
    logger = logging.getLogger(f"hermes.{name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(formatter)
        logger.addHandler(sh)
    return logger


def log_event(category: str, message: str, level: str = "INFO", details: Optional[Dict[str, Any]] = None):
    """記錄結構化事件日誌 (自動進行機密脫敏過濾與深度限制 - P2-01, P2-02)"""
    logger = get_logger(category)
    log_fn = getattr(logger, level.lower(), logger.info)
    clean_msg = sanitize_secrets(message)
    if details:
        if not _check_json_depth(details):
            clean_details = {"error": f"JSON depth exceeds limit of {MAX_JSON_DEPTH}"}
        else:
            clean_details = sanitize_dict(details)
        log_fn(f"{clean_msg} | details={json.dumps(clean_details, ensure_ascii=False)}")
    else:
        log_fn(clean_msg)


def record_evidence(task_id: str, tool_name: str, exit_code: int, status: str, evidence_summary: str):
    """
    將物理執行結果寫入 verification_evidence.db 帳本。
    安全加固 (P2-01, P2-02, P2-03)：
    1. 限制 TASK_ID, TOOL_NAME, SUMMARY_BYTES 長度，防止 DoS 與日誌膨脹。
    2. 自動機密脫敏過濾。
    3. SQLite 檔案建立嚴格驗證 chmod 600 stat 權限後始得寫入。
    4. 例外日誌強制經過 sanitize_secrets 脫敏。
    """
    ev_db = get_db_path("verification_evidence")
    ev_db.parent.mkdir(parents=True, exist_ok=True)
    is_new = not ev_db.exists()

    # 欄位長度與大小上限防禦 (P2-02)
    safe_task_id = str(task_id)[:MAX_TASK_ID_LENGTH]
    safe_tool_name = str(tool_name)[:MAX_TOOL_NAME_LENGTH]
    safe_status = str(status)[:64]
    clean_summary = sanitize_secrets(str(evidence_summary))
    summary_bytes = clean_summary.encode("utf-8")
    if len(summary_bytes) > MAX_SUMMARY_BYTES:
        clean_summary = summary_bytes[:MAX_SUMMARY_BYTES].decode("utf-8", errors="ignore") + "... [TRUNCATED]"

    try:
        import os
        if is_new:
            try:
                # P2-03: create -> chmod 600 -> verify stat -> only then write
                ev_db.touch(mode=0o600, exist_ok=True)
                os.chmod(ev_db, 0o600)
                st = os.stat(ev_db)
                if (st.st_mode & 0o077) != 0:
                    logger = logging.getLogger("hermes.evidence_logger")
                    logger.warning(f"資安警告：證據資料庫權限不安全 ({oct(st.st_mode)})！")
            except OSError:
                pass

        conn = sqlite3.connect(str(ev_db), timeout=5.0)
        with conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    exit_code INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    recorded_at REAL NOT NULL
                );
                """
            )
            conn.execute(
                """
                INSERT INTO evidence_records (task_id, tool_name, exit_code, status, summary, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (safe_task_id, safe_tool_name, int(exit_code), safe_status, clean_summary, time.time())
            )
            # 保持最多 10000 筆審計記錄，避免空間無限制膨脹 (日誌輪轉策略)
            conn.execute(
                """
                DELETE FROM evidence_records WHERE id NOT IN (
                    SELECT id FROM evidence_records ORDER BY id DESC LIMIT 10000
                );
                """
            )
        conn.close()
    except Exception as e:
        logger = logging.getLogger("hermes.evidence_logger")
        logger.warning(f"記錄審計證據失敗: {sanitize_secrets(str(e))}")


def get_recent_evidence(limit: int = 10) -> List[Dict[str, Any]]:
    """讀取最近的證據記錄"""
    ev_db = get_db_path("verification_evidence")
    if not ev_db.exists():
        return []
    try:
        conn = sqlite3.connect(str(ev_db), timeout=5.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM evidence_records ORDER BY id DESC LIMIT ?;", (limit,))
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger = logging.getLogger("hermes.evidence_logger")
        logger.warning(f"讀取審計證據失敗: {sanitize_secrets(str(e))}")
        return []
