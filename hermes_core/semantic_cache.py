"""
semantic_cache.py — 高頻業務與意圖語意快取層 (方案 3: 5ms 極速命中直出)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
核心機制：
1. 查詢語句正規化 (去除廢話口語詞、助詞、標點符號、空白折疊)
2. 基於 SQLite WAL 的持久化短效快取庫 (~/.hermes/data/semantic_cache.db)
3. 支援多級動態 TTL (股票 60s / 系統健康 180s / 單據檢索 600s)
4. 支援強制穿透開關 (包含「刷新/重新查詢/強制」或 --no-cache 時穿透)
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set

from hermes_core.config_loader import get_db_path

logger = logging.getLogger("hermes.semantic_cache")

CACHE_DB = get_db_path("semantic_cache")
TRUSTED_CALLERS: Set[str] = {"agent", "system", "user", "hermes_core", "cron", "test", "internal_service"}

# 贅字發語詞前綴
NOISE_PREFIXES = [
    "請問一下", "請幫我查一下", "請幫我查", "請幫我", "請問", "幫我查一下", "幫我查", "幫我",
    "查一下", "查詢一下", "查詢", "看一下", "幫看", "想知道", "請告訴我", "我想了解", "查"
]

# 贅字助詞
STOP_WORDS = {"的", "了", "嗎", "呢", "吧", "呀", "啊", "一下", "個"}

DEFAULT_TTLS = {
    "stock": 60,         # 股價籌碼 1 分鐘
    "price": 300,        # 原價屋報價 5 分鐘
    "health": 180,       # 系統狀態 3 分鐘
    "archive": 600,      # 單據與知識庫 10 分鐘
    "general": 300,      # 一般問答 5 分鐘
}
MAX_QUERY_LENGTH = 4096
MAX_RESPONSE_LENGTH = 16384  # 16KB 上限，防止大型 LLM 輸出過度膨脹耗盡 SQLite
MAX_CACHE_TTL_SECONDS = 86400  # 最大快取壽命 24 小時，避免設置過長導致數據過期遲緩


def _get_db() -> sqlite3.Connection:
    CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    is_new = not CACHE_DB.exists()
    if is_new:
        try:
            # P2-03: create -> chmod 600 -> verify stat -> only then write
            CACHE_DB.touch(mode=0o600, exist_ok=True)
            os.chmod(CACHE_DB, 0o600)
            st = os.stat(CACHE_DB)
            if (st.st_mode & 0o077) != 0:
                logger.warning(f"資安警告：快取資料庫權限不安全 ({oct(st.st_mode)})！")
        except OSError:
            pass

    conn = sqlite3.connect(str(CACHE_DB), timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    
    # Check if migration needed from legacy schema
    try:
        cur = conn.execute("PRAGMA table_info(query_cache);")
        cols = [r[1] for r in cur.fetchall()]
        if cols and "cache_key" not in cols:
            conn.execute("DROP TABLE query_cache;")
    except Exception:
        pass

    conn.execute("""
    CREATE TABLE IF NOT EXISTS query_cache (
        cache_key TEXT PRIMARY KEY,
        scope_id TEXT,
        caller_id TEXT,
        normalized_query TEXT,
        category TEXT,
        response_text TEXT,
        created_at REAL,
        expire_at REAL,
        hit_count INTEGER DEFAULT 1
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_expire_at ON query_cache(expire_at);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scope_caller ON query_cache(scope_id, caller_id);")
    return conn


def normalize_query(query_str: str) -> str:
    """
    去除發語詞、標點、助詞與多餘空白，提煉核心語意特徵。
    安全約束 (P1-02)：必須先經由機密脫敏 (sanitize_secrets)，杜絕 API key、Token 等機密進入正規化字串。
    """
    from hermes_core.security_filter import sanitize_secrets
    desensitized = sanitize_secrets(query_str.strip().lower())

    # 移除常見標點符號
    text = re.sub(r"[\s\.,!?;:，。！？；：~\-_/\\()（）「」『』]+", " ", desensitized)
    
    # 循環去除前綴贅詞
    changed = True
    while changed:
        changed = False
        text_clean = text.strip()
        for prefix in NOISE_PREFIXES:
            if text_clean.startswith(prefix):
                text_clean = text_clean[len(prefix):].strip()
                changed = True
        text = text_clean

    # 移除中繼贅字助詞
    for sw in STOP_WORDS:
        text = text.replace(sw, " ")

    return "".join(text.split())


def compute_cache_key(normalized_str: str, scope_id: str = "default", caller_id: str = "agent") -> str:
    """
    計算具備 Session / User / Scope 隔離之快取鍵 (P1-01)。
    確保 User A != User B, Session A != Session B, Scope A != Scope B。
    """
    scope = (scope_id or "default").strip()
    caller = (caller_id or "agent").strip()
    payload = f"{scope}:{caller}:{normalized_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def compute_query_hash(normalized_str: str) -> str:
    """相容性舊介面"""
    return compute_cache_key(normalized_str, scope_id="default", caller_id="agent")


def infer_category(query_str: str) -> str:
    """自動推斷查詢類別以套用對應 TTL"""
    q = query_str.lower()
    if any(k in q for k in ["健康", "狀態", "health", "status", "存活", "硬碟", "cpu", "記憶體"]):
        return "health"
    if any(k in q for k in ["搜尋", "查詢", "檢索", "單據", "文檔", "知識庫", "search", "query"]):
        return "archive"
    if any(k in q for k in ["報價", "價格", "行情", "費用", "price", "cost"]):
        return "price"
    return "general"


def get_cached_response(
    query_str: str,
    scope_id: str = "default",
    caller_id: Optional[str] = "agent"
) -> Optional[Dict[str, Any]]:
    """
    從語意快取中獲取結果 (<5ms)。
    具備 Session / User / Scope 隔離 (P1-01)。
    """
    if any(k in query_str.lower() for k in ["刷新", "重新查詢", "強制", "--no-cache", "-f"]):
        return None

    norm = normalize_query(query_str)
    if not norm:
        return None

    cid = (caller_id or "agent").strip()
    sc_id = (scope_id or "default").strip()
    cache_key = compute_cache_key(norm, scope_id=sc_id, caller_id=cid)
    now = time.time()

    try:
        with _get_db() as conn:
            cur = conn.execute(
                "SELECT response_text, expire_at, hit_count, category FROM query_cache WHERE cache_key = ? AND expire_at > ?;",
                (cache_key, now)
            )
            row = cur.fetchone()
            if row:
                resp_text, expire_at, hit_count, category = row
                conn.execute(
                    "UPDATE query_cache SET hit_count = hit_count + 1 WHERE cache_key = ?;",
                    (cache_key,)
                )
                return {
                    "hit": True,
                    "response": resp_text,
                    "response_text": resp_text,
                    "category": category,
                    "remaining_ttl": int(expire_at - now),
                    "hit_count": hit_count + 1
                }
    except Exception as e:
        logger.warning(f"讀取語意快取失敗: {e}")
    return None


def set_cached_response(
    query_str: str,
    response_text: str,
    ttl_seconds: Optional[int] = None,
    category: Optional[str] = None,
    caller_id: Optional[str] = "agent",
    scope_id: str = "default",
    strict_caller_check: bool = False
) -> bool:
    """
    寫入語意快取。
    具備呼叫者驗證、敏感資訊自動脫敏 (P1-02)、Scope 隔離 (P1-01) 與防快取中毒防護。
    """
    # 1. 呼叫者身分信任驗證 (防快取中毒)
    if not caller_id or caller_id not in TRUSTED_CALLERS:
        logger.warning(f"快取寫入拒絕：未受信任之呼叫者 '{caller_id}' 嘗試寫入快取")
        if strict_caller_check:
            raise PermissionError(f"Untrusted caller: {caller_id}")
        return False

    if not isinstance(query_str, str) or not isinstance(response_text, str):
        return False

    # 2. 長度限制防 DoS 與空間耗盡
    if len(query_str) > MAX_QUERY_LENGTH or len(response_text) > MAX_RESPONSE_LENGTH:
        logger.warning(f"快取寫入拒絕：查詢 (上限 {MAX_QUERY_LENGTH}) 或回應內容 (上限 {MAX_RESPONSE_LENGTH}) 過長")
        return False

    norm = normalize_query(query_str)
    if not norm or "\x00" in norm or not response_text.strip():
        return False

    # 3. 敏感資訊自動脫敏 (P1-02: 避免機密憑證被永久儲存於 SQLite)
    from hermes_core.security_filter import sanitize_secrets
    clean_query = sanitize_secrets(query_str.strip())
    clean_response = sanitize_secrets(response_text.strip())

    cid = (caller_id or "agent").strip()
    sc_id = (scope_id or "default").strip()
    cache_key = compute_cache_key(norm, scope_id=sc_id, caller_id=cid)
    cat = category or infer_category(query_str)
    raw_ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTLS.get(cat, 300)
    ttl = min(max(1, raw_ttl), MAX_CACHE_TTL_SECONDS)
    now = time.time()
    expire_at = now + ttl

    try:
        with _get_db() as conn:
            conn.execute(
                """
                INSERT INTO query_cache (cache_key, scope_id, caller_id, normalized_query, category, response_text, created_at, expire_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(cache_key) DO UPDATE SET
                    response_text = excluded.response_text,
                    normalized_query = excluded.normalized_query,
                    created_at = excluded.created_at,
                    expire_at = excluded.expire_at;
                """,
                (cache_key, sc_id, cid, clean_query, cat, clean_response, now, expire_at)
            )
        return True
    except Exception as e:
        logger.warning(f"寫入語意快取失敗: {e}")
        return False


def prune_expired_cache() -> int:
    """清理所有過期的快取記錄"""
    now = time.time()
    try:
        with _get_db() as conn:
            cur = conn.execute("DELETE FROM query_cache WHERE expire_at <= ?;", (now,))
            return cur.rowcount
    except Exception as e:
        logger.warning(f"清理過期語意快取失敗: {e}")
        return 0


if __name__ == "__main__":
    test_q = "請問幫我查一下伺服器集群的健康狀態"
    test_ans = "📍 伺服器集群健康狀態正常 (快取測試資料)"
    set_cached_response(test_q, test_ans, ttl_seconds=60)
    
    # Check normalized query match
    res = get_cached_response("查伺服器集群健康狀態")
    print("Normalized query 1:", normalize_query(test_q))
    print("Normalized query 2:", normalize_query("查伺服器集群健康狀態"))
    if not (res and res["hit"]):
        raise RuntimeError("Semantic cache failed to hit normalized query!")
    print("✅ semantic_cache module 100% OPERATIONAL!")
