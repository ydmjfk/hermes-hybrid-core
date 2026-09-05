"""
skeleton_streamer.py — Sub-50ms Instant Skeleton Streamer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Core Features:
1. Ultra-fast intent & entity feature extraction (<5ms)
2. Generates warm, context-aware instant skeleton frames (<50ms)
3. Pluggable template registry for custom domain extensions
"""

import logging
import re
from typing import Dict, List, Optional, Tuple, Callable

logger = logging.getLogger("hermes.skeleton_streamer")

# Default generic skeleton templates
DEFAULT_TEMPLATES: List[Tuple[str, str]] = [
    (
        r"(分析|診斷|分析日誌|排錯|除錯|debug|inspect)",
        "🔍 收到請求，正在為您快速調閱相關日誌與系統診斷資訊中..."
    ),
    (
        r"(搜尋|查詢|檢索|search|find|query)",
        "📂 收到請求，正在為您即時比對與檢索關聯檔案與知識庫紀錄中..."
    ),
    (
        r"(修復|修正|重構|優化|patch|fix|refactor)",
        "🛠️ 收到請求，正在為您解析程式碼結構與建立安全變更計畫中..."
    ),
    (
        r"(健康|狀態|health|status|存活|負載)",
        "⚡ 收到請求，正在為您全面巡檢系統核心服務與資源健康狀態中..."
    ),
]

_custom_templates: List[Tuple[str, str]] = []


def register_skeleton_template(pattern: str, template: str) -> None:
    """Register a custom regex pattern and response template."""
    _custom_templates.append((pattern, template))


def extract_entity_anchor(user_input: str) -> str:
    """Extract key entity from input string."""
    text = user_input.strip()
    words = [w for w in re.split(r"[\s,，.。!！?？]+", text) if len(w) > 1]
    return words[0] if words else "任務"


# Short ack words that should be silenced without sending skeleton bubble
SILENT_WORDS = {
    "好", "好的", "收到", "謝謝", "多謝", "感謝", "了解", "明白",
    "好的謝謝", "好喔", "好哦", "ok", "okay", "yes", "thanks", "thx"
}


def generate_instant_skeleton(user_input: str) -> Optional[str]:
    """
    Generate instant skeleton response string within <10ms.
    Returns None if the input is a short ack word (smart reduction).
    """
    cleaned = user_input.strip().lower()
    # 1. Smart Reduction: Silence short ack messages to avoid chat spam
    if cleaned in SILENT_WORDS or (len(cleaned) <= 2 and any(w in cleaned for w in ("好", "收", "謝"))):
        return None

    entity = extract_entity_anchor(user_input)
    # Check custom templates first
    for pattern, template in _custom_templates:
        if re.search(pattern, user_input, re.IGNORECASE):
            return template.format(entity=entity)

    # Check default templates
    for pattern, template in DEFAULT_TEMPLATES:
        if re.search(pattern, user_input, re.IGNORECASE):
            return template.format(entity=entity)

    # Compact default skeleton bubble
    return "💭 思考中，請稍候..."


def send_instant_skeleton(user_input: str, channel_id: Optional[str] = None) -> bool:
    """Send skeleton feedback if client is available."""
    try:
        from .chat_client import send_chat_message
        skeleton = generate_instant_skeleton(user_input)
        if skeleton:
            return send_chat_message(skeleton, channel_id=channel_id)
    except Exception as e:
        logger.warning(f"骨架訊息發送失敗: {e}")
    return False


if __name__ == "__main__":
    test_queries = [
        "請幫我分析系統日誌",
        "查詢昨天的建置紀錄",
        "修復這個函式的語法錯誤",
        "檢查系統健康狀態",
    ]
    for q in test_queries:
        print(f"Q: {q}\nA: {generate_instant_skeleton(q)}\n")
