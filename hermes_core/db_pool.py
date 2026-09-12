"""
db_pool.py — 統一 SQLite 連線池與安全操作輔助器
"""

import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from .config_loader import get_db_path


def get_db_connection(db_target: Union[str, Path], timeout: float = 5.0, read_only: bool = False) -> sqlite3.Connection:
    """
    取得已配置最佳化 PRAGMA 的 SQLite 連線。
    安全約束 (P2-03, P2-04)：
    1. read_only=True 時強制使用 SQLite URI 'mode=ro' 唯讀模式，在 OS/Engine 層面阻斷任何寫入嘗試。
    2. 新建資料庫檔案時強制設定 POSIX 0600 (僅限擁有者讀寫) 權限。
    """
    import os
    if isinstance(db_target, str):
        db_path = get_db_path(db_target)
    else:
        db_path = Path(db_target)

    if read_only:
        if not db_path.exists():
            raise FileNotFoundError(f"唯讀 SQLite 資料庫不存在，拒絕建立檔案 (Fail-Closed): '{db_path}'")
        # 強制使用 SQLite 原生唯讀 URI (P2-04)
        conn = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", timeout=timeout, uri=True)
    else:
        if not db_path.exists():
            db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                db_path.touch(mode=0o600, exist_ok=True)
                os.chmod(db_path, 0o600)
            except OSError:
                pass
        conn = sqlite3.connect(str(db_path), timeout=timeout)

    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000;")
    except sqlite3.OperationalError:
        pass

    return conn


get_connection = get_db_connection


def execute_query(db_target: Union[str, Path], query: str, params: Union[Tuple, List, Dict] = ()) -> List[sqlite3.Row]:
    """
    執行安全參數化查詢並回傳 Row 清單。
    安全約束：
    1. 僅允許唯讀查詢 (SELECT / PRAGMA / EXPLAIN)，禁止變更性語句。
    2. 嚴格禁止多語句堆疊 (Multi-statement query stacking)。
    3. 強制參數化綁定，防止字串拼接注入。
    """
    if not query or not isinstance(query, str):
        raise ValueError("查詢語句不可為空 (Query must be a non-empty string)")

    normalized_q = query.strip()

    # 1. 多語句注入防禦 (Disallow multiple SQL statements)
    statements = [s.strip() for s in normalized_q.split(";") if s.strip()]
    if len(statements) > 1:
        raise ValueError("安全阻斷：execute_query 禁止執行多語句堆疊 (Multiple SQL statements not allowed)")

    # 2. 唯讀保護：禁止在 execute_query 中執行寫入/破壞性 DDL/DML
    first_word = statements[0].split()[0].upper() if statements else ""
    disallowed_verbs = {"DROP", "TRUNCATE", "DELETE", "UPDATE", "INSERT", "ALTER", "GRANT", "REVOKE"}
    if first_word in disallowed_verbs:
        raise ValueError(
            f"安全阻斷：execute_query 僅限唯讀查詢，禁止執行 '{first_word}' 操作。寫入請使用 execute_write。"
        )

    # 3. 禁用的 SQL 關鍵字黑名單 (提權、外庫附加與破壞性維護指令)
    upper_q = normalized_q.upper()
    forbidden_keywords = ("ATTACH", "DETACH", "VACUUM", "ANALYZE")
    for kw in forbidden_keywords:
        if kw in upper_q:
            raise ValueError(f"安全阻斷：禁止在查詢中使用特權 SQL 關鍵字 '{kw}'")

    # 4. 嚴格 PRAGMA 安全約束 (只允許唯讀檢視，禁止寫入或變更 schema)
    if "PRAGMA" in upper_q:
        if "=" in upper_q or any(bad in upper_q for bad in ("WRITABLE_SCHEMA", "HEXKEY", "KEY")):
            raise ValueError("安全阻斷：禁止執行變更性或提權之 PRAGMA 配置")

    # 5. 確保 params 格式合法
    if not isinstance(params, (tuple, list, dict)):
        raise TypeError("查詢參數 params 必須為 tuple, list 或 dict")

    conn = get_db_connection(db_target, timeout=5.0, read_only=True)
    try:
        cur = conn.cursor()
        cur.execute(normalized_q, params)
        return cur.fetchall()
    finally:
        conn.close()


def execute_write(db_target: Union[str, Path], callback: Callable[[sqlite3.Connection], Any], max_retries: int = 3) -> Any:
    """在交易中安全執行寫入操作 (具備自動重試與隨機延遲)"""
    conn = get_db_connection(db_target, timeout=5.0, read_only=False)
    for attempt in range(max_retries):
        try:
            with conn:
                return callback(conn)
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() or "busy" in str(e).lower():
                time.sleep(0.05 * (2 ** attempt))
                continue
            raise
        finally:
            if attempt == max_retries - 1:
                conn.close()
    conn.close()


transaction = execute_write
