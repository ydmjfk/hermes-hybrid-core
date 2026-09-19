"""
circuit_breaker.py — 任務熔斷器與死信佇列防護 (基於 CAP-005 核心規範)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
核心功能：
1. 失敗計數閾值 (連續失敗 3 次觸發 DEGRADED_QUARANTINED 隔離)
2. 自動降級與死信阻斷 (防止外部目標故障時的無效重試風暴)
3. 慢探針自我復原 (隔離期滿後允許 1 次探針測試，成功則自動恢復 HEALTHY)
4. 負向快取隔離 (Negative Caching - 阻絕故障網址或端點反覆重試)
"""

import collections
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple


from hermes_core.config_loader import get_hermes_path

logger = logging.getLogger("hermes_core.circuit_breaker")

STATE_FILE = get_hermes_path("data/breaker_state.json")
FAILURE_THRESHOLD = 3
PROBE_INTERVAL_SECONDS = 300  # 5 minutes
MAX_JSON_SIZE = 1_048_576  # 1MB 限制以防範 JSON 反序列化 DoS 攻擊


def _load_breakers() -> Dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        if STATE_FILE.stat().st_size > MAX_JSON_SIZE:
            logger.warning(f"狀態檔過大 (超過 {MAX_JSON_SIZE} bytes)，略過載入")
            return {}
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            content = f.read(MAX_JSON_SIZE)
            return json.loads(content, strict=True)
    except Exception as e:
        logger.debug(f"讀取熔斷狀態略過: {e}")
        return {}


def _save_breakers(data: Dict[str, Any]):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(STATE_FILE)
    except Exception as e:
        logger.warning(f"儲存熔斷器狀態檔案失敗: {e}")


def check_and_execute_task(task_id: str, task_fn: Callable[[], Any], fallback_fn: Callable[[str], Any] = None) -> Tuple[bool, Any]:
    """
    以熔斷器保護執行任務
    """
    now = time.time()
    breakers = _load_breakers()
    entry = breakers.get(task_id, {
        "consecutive_failures": 0,
        "state": "HEALTHY",
        "last_error": "",
        "last_failure_time": 0.0,
        "last_probe_time": 0.0,
    })

    # Check state
    if entry["state"] == "DEGRADED_QUARANTINED":
        if now - entry.get("last_probe_time", 0.0) >= PROBE_INTERVAL_SECONDS:
            entry["state"] = "SLOW_PROBING"
            entry["last_probe_time"] = now
            breakers[task_id] = entry
            _save_breakers(breakers)
        else:
            rem_s = int(PROBE_INTERVAL_SECONDS - (now - entry.get("last_probe_time", 0.0)))
            reason = f"Job in Dead Letter Quarantine (連續失敗 {entry['consecutive_failures']} 次)。距下次慢探針尚餘 {rem_s} 秒。"
            if fallback_fn:
                return False, fallback_fn(reason)
            return False, f"Blocked: {reason}"

    # Execute task
    try:
        result = task_fn()
        # Record Success
        entry["consecutive_failures"] = 0
        entry["state"] = "HEALTHY"
        entry["last_error"] = ""
        breakers[task_id] = entry
        _save_breakers(breakers)
        return True, result
    except Exception as e:
        entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
        entry["last_error"] = str(e)
        entry["last_failure_time"] = now
        if entry["consecutive_failures"] >= FAILURE_THRESHOLD:
            entry["state"] = "DEGRADED_QUARANTINED"
            entry["last_probe_time"] = now
        breakers[task_id] = entry
        _save_breakers(breakers)
        return False, str(e)


# ==============================================================================
# 負向快取機制 (Negative Caching - 防止目標資源故障時的無效重試)
# ==============================================================================
NEGATIVE_CACHE_FILE = get_hermes_path("data/negative_cache.json")


def _load_negative_cache() -> Dict[str, Any]:
    if not NEGATIVE_CACHE_FILE.exists():
        return {}
    try:
        if NEGATIVE_CACHE_FILE.stat().st_size > MAX_JSON_SIZE:
            logger.warning(f"負向快取檔案過大 (超過 {MAX_JSON_SIZE} bytes)，略過載入")
            return {}
        with open(NEGATIVE_CACHE_FILE, "r", encoding="utf-8") as f:
            content = f.read(MAX_JSON_SIZE)
            return json.loads(content, strict=True)
    except Exception as e:
        logger.debug(f"讀取負向快取檔案略過: {e}")
        return {}


def _save_negative_cache(data: Dict[str, Any]):
    NEGATIVE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        tmp = NEGATIVE_CACHE_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(NEGATIVE_CACHE_FILE)
    except Exception as e:
        logger.warning(f"儲存負向快取檔案失敗: {e}")


def check_negative_cache(resource_key: str) -> Optional[Tuple[bool, str]]:
    """
    檢查目標資源是否處於負向快取隔離期。
    若命中，返回 (True, 阻斷原因與自癒建議)。
    """
    cache = _load_negative_cache()
    entry = cache.get(resource_key)
    if not entry:
        return None

    expires_at = entry.get("expires_at", 0.0)
    now = time.time()
    if now < expires_at:
        rem_s = int(expires_at - now)
        reason = entry.get("reason", "目標資源暫時不可達")
        guidance = (
            f"NEGATIVE CACHE BLOCKED: 目標 '{resource_key}' 於近期失敗（{reason}），負向隔離尚餘 {rem_s} 秒。"
            "【自癒引導】：請勿原地重試，請切換至次選搜尋結果或利用現有摘要輸出。"
        )
        return True, guidance
    return None


def record_negative_cache(resource_key: str, reason: str, ttl_seconds: float = 600.0):
    """
    將失敗資源（如 403 / 404 / Challenge 的網址）登記至負向快取。
    具備 JSON 注入防護、長度截斷與敏感資訊脫敏。
    """
    if not isinstance(resource_key, str) or not isinstance(reason, str):
        raise TypeError("resource_key 與 reason 必須為字串 (Must be strings)")

    # 1. 限制長度防範 DoS / 空間耗盡
    sanitized_key = resource_key.strip()[:255]
    sanitized_reason = reason.strip()[:200]

    # 2. 清除控制字元與換行防範日誌 / JSON 注入
    sanitized_reason = re.sub(r"[\r\n\x00-\x1f\x7f-\x9f]", " ", sanitized_reason).strip()

    # 3. 脫敏過濾避免機密資訊外洩至負向快取檔案
    try:
        from hermes_core.security_filter import sanitize_secrets
        sanitized_reason = sanitize_secrets(sanitized_reason)
    except Exception as e:
        logger.debug(f"脫敏過濾略過: {e}")

    cache = _load_negative_cache()
    now = time.time()
    # 順便清理已過期項目
    active_cache = {k: v for k, v in cache.items() if v.get("expires_at", 0.0) > now}
    active_cache[sanitized_key] = {
        "reason": sanitized_reason,
        "recorded_at": now,
        "expires_at": now + ttl_seconds,
    }
    _save_negative_cache(active_cache)


def clear_negative_cache(resource_key: str = None):
    """清除負向快取"""
    if resource_key is None:
        _save_negative_cache({})
    else:
        cache = _load_negative_cache()
        if resource_key in cache:
            del cache[resource_key]
            _save_negative_cache(cache)


class ToolDuplicateCallDetector:
    """
    同參數重複調用零容忍硬熔斷器 (Zero Exact-Duplicate Retry Guard)
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    解決 Agent 在工具執行失敗或 inaccessible 時，以完全相同之參數原地重試
    導致陷入 9~10 輪重複空轉死循環。
    連續相同調用 >= 2 次即啟動硬熔斷，阻斷後續無效嘗試。
    """
    def __init__(self, max_consecutive_duplicates: int = 2, maxlen: int = 1000):
        self.max_duplicates = max_consecutive_duplicates
        self._call_history = collections.deque(maxlen=maxlen)  # [(tool_name, params_hash, count)]

    def record_and_check(self, tool_name: str, params: Any) -> Tuple[bool, str]:
        """
        記錄一次調用並檢驗是否觸發重複熔斷。
        回傳 (is_tripped, explanation)
        """
        import hashlib
        serialized = json.dumps(params, sort_keys=True, default=str) if isinstance(params, (dict, list)) else str(params)
        p_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]

        if self._call_history and self._call_history[-1][0] == tool_name and self._call_history[-1][1] == p_hash:
            prev = self._call_history[-1]
            new_count = prev[2] + 1
            self._call_history[-1] = (tool_name, p_hash, new_count)
            if new_count >= self.max_duplicates:
                return True, (
                    f"🚨 [HAOS CIRCUIT BREAKER TRIPPED]: 檢測到工具 '{tool_name}' 以完全相同之參數連續重複調用 {new_count} 次！"
                    "【零容忍鐵律】：嚴禁以相同假設原地重試，已啟動硬熔斷，請立即切換策略或回退向使用者請示。"
                )
        else:
            self._call_history.append((tool_name, p_hash, 1))

        return False, ""



class SmartApprovalTimeoutShield:
    """
    審批逾時防卡死熔斷護盾 (Smart Approval Timeout Shield)
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    當高風險指令請求人工審批逾時時，在冷卻窗口 (預設 120s) 內再度觸發需審批
    操作時，立即 0 秒快速拒絕收尾，杜絕連續等待導致系統卡死 180 秒。
    """
    _last_timeout_timestamp: float = 0.0
    COOLDOWN_WINDOW_SECONDS: float = 120.0

    @classmethod
    def record_timeout(cls):
        cls._last_timeout_timestamp = time.time()

    @classmethod
    def is_in_timeout_cooldown(cls) -> bool:
        if cls._last_timeout_timestamp <= 0:
            return False
        return (time.time() - cls._last_timeout_timestamp) < cls.COOLDOWN_WINDOW_SECONDS

    @classmethod
    def reset(cls):
        cls._last_timeout_timestamp = 0.0
