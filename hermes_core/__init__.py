"""
hermes_core — Hermes 代理人系統統一共用底座 SDK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
包含模組：
1. config_loader: 統一路徑、環境變數與資料庫路徑查詢
2. db_pool: 高併發 SQLite 連線池與安全交易執行
3. chat_client: Synology Chat 訊息與附件原生推播
4. evidence_logger: 結構化日誌與客觀證據帳本
5. circuit_breaker: CAP-005 任務熔斷器與死信防護
6. async_attachment_worker: 背景異步附件推播佇列
7. semantic_cache: 方案 3 語意快取層 (<5ms 直出)
8. skeleton_streamer: 方案 4 模板骨架秒回推播器 (<50ms)
9. speculative_executor: 方案 5 樂觀預先執行管線 (<0.1ms 記憶體預取)
"""

from .config_loader import (
    get_hermes_path,
    get_db_path,
    get_env_var,
    HERMES_HOME,
    DATA_DIR,
    LOGS_DIR,
    BACKUPS_DIR,
    DB_MAP,
)
from .db_pool import (
    get_connection,
    execute_query,
    execute_write,
    transaction,
)
from .chat_client import (
    send_chat_message,
    send_chat_file,
    send_error_alert,
)
from .evidence_logger import (
    log_event,
    record_evidence,
    get_recent_evidence,
)
from .circuit_breaker import (
    check_and_execute_task,
)
from .async_attachment_worker import (
    enqueue_chat_file,
    ensure_worker_running,
)
from .semantic_cache import (
    get_cached_response,
    set_cached_response,
    prune_expired_cache,
)
from .skeleton_streamer import (
    generate_instant_skeleton,
    send_instant_skeleton,
)
from .speculative_executor import (
    trigger_speculative_prefetch,
    get_prefetched_data,
)
from .path_sanitizer import (
    PathSanitizer,
    sanitize_path,
    is_safe_path,
    PathSanitizerError,
    PathTraversalError,
    SensitivePathBlockedError,
)
from .security_filter import (
    sanitize_secrets,
    sanitize_dict,
    contains_secrets,
    mask_secret_string,
)

__all__ = [
    "get_hermes_path",
    "get_db_path",
    "get_env_var",
    "HERMES_HOME",
    "DATA_DIR",
    "LOGS_DIR",
    "BACKUPS_DIR",
    "DB_MAP",
    "get_connection",
    "execute_query",
    "execute_write",
    "transaction",
    "send_chat_message",
    "send_chat_file",
    "send_error_alert",
    "log_event",
    "record_evidence",
    "get_recent_evidence",
    "check_and_execute_task",
    "enqueue_chat_file",
    "ensure_worker_running",
    "get_cached_response",
    "set_cached_response",
    "prune_expired_cache",
    "generate_instant_skeleton",
    "send_instant_skeleton",
    "trigger_speculative_prefetch",
    "get_prefetched_data",
    "PathSanitizer",
    "sanitize_path",
    "is_safe_path",
    "PathSanitizerError",
    "PathTraversalError",
    "SensitivePathBlockedError",
    "sanitize_secrets",
    "sanitize_dict",
    "contains_secrets",
    "mask_secret_string",
]
