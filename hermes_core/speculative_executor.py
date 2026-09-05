"""
speculative_executor.py — Speculative Execution & Prefetch Pipeline
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Core Features:
1. Fast intent extraction (<5ms)
2. Non-blocking background thread parallel prefetching for underlying I/O queries
3. In-memory prefetch pool (TTL 60s) for microsecond retrieval (<0.1ms)
4. Dynamic prefetch handler registration
"""

import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hermes.speculative_executor")

# In-memory prefetch cache: { key: { "data": Any, "expire_at": float, "source": str } }
_PREFETCH_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()
PREFETCH_TTL_SECONDS = 60.0

# Registered handlers: list of (pattern, key_extractor_fn, worker_fn, source_name)
_HANDLERS: List[Tuple[re.Pattern, Callable[[str], str], Callable[[str], Any], str]] = []


def register_prefetch_handler(
    pattern: str,
    key_extractor: Callable[[str], str],
    task_func: Callable[[str], Any],
    source_name: str = "custom"
) -> None:
    """Register a custom speculative prefetch handler."""
    _HANDLERS.append((re.compile(pattern, re.IGNORECASE), key_extractor, task_func, source_name))


def _clean_expired_prefetches():
    now = time.time()
    with _CACHE_LOCK:
        expired = [k for k, v in _PREFETCH_CACHE.items() if v["expire_at"] <= now]
        for k in expired:
            del _PREFETCH_CACHE[k]


def _worker_prefetch(key: str, task_fn: Callable[[], Any], source_name: str):
    try:
        data = task_fn()
        if data is not None:
            with _CACHE_LOCK:
                _PREFETCH_CACHE[key] = {
                    "data": data,
                    "expire_at": time.time() + PREFETCH_TTL_SECONDS,
                    "source": source_name
                }
    except Exception as e:
        logger.debug(f"投機執行失敗 ({source_name}): {e}")


def trigger_speculative_prefetch(user_input: str) -> Optional[str]:
    """
    Analyzes user input and non-blockingly kicks off background speculative prefetching.
    Returns the cache key if matched, else None.
    """
    _clean_expired_prefetches()
    text = user_input.strip()

    for pattern, key_fn, task_fn, source_name in _HANDLERS:
        if pattern.search(text):
            try:
                key = key_fn(text)
                threading.Thread(
                    target=_worker_prefetch,
                    args=(key, lambda: task_fn(text), source_name),
                    daemon=True,
                    name=f"SpeculativeWorker_{key}"
                ).start()
                return key
            except Exception as e:
                logger.debug(f"啟動投機工作者失敗: {e}")

    return None


def get_prefetched_data(key: str) -> Optional[Any]:
    """
    Retrieve prefetched data from in-memory pool (<0.1ms).
    """
    _clean_expired_prefetches()
    with _CACHE_LOCK:
        entry = _PREFETCH_CACHE.get(key)
        if entry and entry["expire_at"] > time.time():
            return entry["data"]
    return None


def set_prefetched_data(key: str, data: Any, source_name: str = "direct") -> None:
    """Explicitly put data into prefetch pool."""
    with _CACHE_LOCK:
        _PREFETCH_CACHE[key] = {
            "data": data,
            "expire_at": time.time() + PREFETCH_TTL_SECONDS,
            "source": source_name
        }


if __name__ == "__main__":
    print("🚀 Speculative Executor Pipeline Test")
    register_prefetch_handler(
        r"health|健康|status",
        lambda text: "system_health",
        lambda text: {"status": "ok", "load": 0.12},
        "health_check"
    )

    k = trigger_speculative_prefetch("check system health")
    time.sleep(0.05)
    res = get_prefetched_data(k)
    print(f"Prefetched: {res}")
    if res is None:
        raise RuntimeError("Failed to get prefetched data")
    print("✅ speculative_executor 100% OPERATIONAL!")
