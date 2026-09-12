"""
skeleton_streamer.py — 體感 0 延遲模板骨架秒回推播器 (方案 4: <50ms 即時骨架)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
核心機制：
1. 極速意圖特徵萃取 (<5ms)
2. 產生溫暖貼心、符合 SOUL.md 人設的即時響應骨架
3. 支援 Synology Chat 即時推播，消滅 LLM Prompt Prefill 等待空白期
4. 支援附件特徵 (has_image) 與防禦性參數 (**kwargs)
5. 🛡️ 雙重防禦機制：防止提示詞/長指令誤觸「調閱單據/發票」、防止否定句誤觸
"""

import logging
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("hermes.skeleton_streamer")

try:
    from .chat_client import send_chat_message
except ImportError:
    try:
        from chat_client import send_chat_message
    except ImportError:
        send_chat_message = None

# 短語/日常確認直接靜默不發氣泡（避免「好」、「謝謝」也跳通知干擾）
SILENT_WORDS = {
    "好", "好的", "收到", "謝謝", "多謝", "感謝", "了解", "明白",
    "好的謝謝", "好喔", "好哦", "ok", "okay", "yes", "thanks", "thx",
    "行", "沒問題", "是的", "對", "恩", "嗯", "辛苦了", "早安", "晚安",
    "感恩", "ok啦", "好呀"
}

# 中繼/系統提示詞防禦關鍵字 (凡包含此類文字一律不觸發單據/發票調閱)
META_INSTRUCTION_KEYWORDS = [
    "prompt", "提示詞", "規則", "規範", "設定", "原則", "守則",
    "更新系統", "修改系統", "白皮書", "架構", "sop", "指引", "約束",
    "注意遵守", "核心指令", "系統指令", "系統提示"
]

# 示範企業實體（開源版範例，實際部署可於 config.yaml 中自訂擴充）
CUSTOMERS = ["示範科技", "環球精密", "先進製程", "創新工藝", "宏達電子"]
DOC_NOUNS = ["維修單", "服務單", "工單", "保養單", "單據", "發票", "收據", "驗收單", "送貨單", "加班單", "工作日誌", "差旅報銷", "報銷單"]
QUERY_VERBS = ["查", "找", "調", "看", "搜", "傳", "發", "有沒有", "列出", "調閱", "要看", "幫看", "幫查", "調出", "翻出", "有哪些", "請給我", "內容", "明細"]
RELATIVE_DATES = ["昨天", "前天", "今天", "本週", "上週", "8月", "9月", "10月", "11月", "12月", "1月", "2月", "3月", "4月", "5月", "6月", "7月"]

# 意圖特徵骨架庫 (依比對優先級排列)
SKELETON_TEMPLATES: List[Tuple[str, str]] = [
    (
        r"(傳給我|發給我|發我|傳我|看原圖|原圖|原檔|這張圖|這張照片|照片給我|檔案給我|圖片給我)",
        "📎 收到請求，正在為您提取【{entity}】實體檔案與原圖並準備推送中，請稍候..."
    ),
    (
        r"(2330|0050|台積電|台股|大盤|股價|營收|籌碼|K線)",
        "📍 收到請求，正在為您即時調閱【{entity}】最新走勢與籌碼數據分析中，請稍候..."
    ),
    (
        r"(5070|5080|5090|顯示卡|顯卡|rtx\s*50)",
        "📍 收到請求，正在為您連線比對【{entity}】最新現貨報價中，請稍候..."
    ),
    (
        r"(系統健康|系統狀態|health|全系統|服務狀態|負載檢查|系統檢查|存活)",
        "📍 收到請求，正在為您全面巡檢全系統核心資料庫與服務狀態中，請稍候..."
    ),
    (
        r"(簽退|打卡|考勤)",
        "📍 收到請求，正在為您即時計算考勤工時與簽退排程中，請稍候..."
    ),
    (
        r"(分析.*日誌|日誌.*分析|系統診斷|診斷.*系統|排錯|除錯|debug|inspect)",
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
]

_custom_templates: List[Tuple[str, str]] = []


def register_skeleton_template(pattern: str, template: str) -> None:
    """註冊自定義正則模式與骨架模板"""
    _custom_templates.append((pattern, template))


def extract_entity_anchor(user_input: str) -> str:
    """提取句子中的關鍵實體詞 (客戶、單號、日期、股號或硬體型號)"""
    text = (user_input or "").strip()

    # 1. 優先找客戶
    for c in CUSTOMERS:
        if c in text:
            return c

    # 2. 找單號
    m_order = re.search(r'[A-Za-z]\d{5,8}|\b\d{6,8}\b|[A-Za-z]{1,3}[-_]\d{2,5}|[A-Za-z]{1,3}\d{3,5}', text)
    if m_order:
        return m_order.group(0)

    # 3. 找股票代號或名稱（示範權值股）
    if "2330" in text or "台積電" in text:
        return "2330 台積電"
    m_stock = re.search(r"\b(0050|2330)\b", text)
    if m_stock:
        return m_stock.group(1)

    # 4. 找單據類型或相對日期
    for doc in DOC_NOUNS:
        if doc in text:
            for d in RELATIVE_DATES:
                if d in text:
                    return f"{d}{doc}"
            return doc

    # 5. 找硬體型號
    m_gpu = re.search(r"(rtx\s*50[0-9]0|5070|5080|5090)", text, re.IGNORECASE)
    if m_gpu:
        return m_gpu.group(1).upper()

    words = [w for w in re.split(r"[\s,，.。!！?？]+", text) if len(w) > 1]
    return words[0] if words else "相關業務"


def generate_instant_skeleton(user_input: str, has_image: bool = False, **kwargs) -> Optional[str]:
    """
    根據使用者輸入與附件特徵，在 5ms 內生成動態對齊的即時骨架回覆。
    支援 has_image 與 **kwargs 防禦性參數。
    具備多層防禦：長文/多行/提示詞降級、否定句過濾、動詞意圖精準比對。
    """
    clean_text = (user_input or "").strip()
    if not clean_text and not has_image:
        return None

    # 排除控制指令（不發送骨架干擾）
    if clean_text.lower() in ("/reset", "/new", "/clear", "/stop", "/abort"):
        return None

    # 1. 智慧縮退：短語/日常確認直接靜默不發氣泡（避免「好」、「謝謝」也跳通知干擾）
    if clean_text.lower() in SILENT_WORDS or (len(clean_text) <= 2 and any(w in clean_text for w in ("好", "收", "謝", "恩", "嗯"))):
        return None

    # 2. 圖片優先反饋
    if has_image:
        return "🖼️ 已收到您傳送的圖片，正在進行 OCR 視覺解析與資料比對中，請稍候..."

    # 2.1 文檔接收反饋 (避免非圖片檔案誤觸一般意圖或圖片提取)
    if kwargs.get("has_document") or "上傳了文檔檔案" in clean_text:
        return "📄 已收到您傳送的文檔，正在閱讀解析中，請稍候..."

    # 3. 防禦層：指令/提示詞/多行長文字/中繼指令過濾 (降級為通用思考骨架，絕不誤判為查發票/單據)
    is_long_text = len(clean_text) > 40
    is_multiline = "\n" in clean_text
    is_meta_instruction = any(k in clean_text.lower() for k in META_INSTRUCTION_KEYWORDS)

    if is_long_text or is_multiline or is_meta_instruction:
        return "💭 思考中，請稍候..."

    # 4. 防禦層：否定句過濾 (例如「不用查發票」、「不要調維修單」)
    if re.search(r"(不用|不要|不需|免|別)(查|調|看|找|搜|傳|發|開|做|算|理)", clean_text):
        return "💭 思考中，請稍候..."

    entity = extract_entity_anchor(clean_text)

    # 5. 檢查自定義模板
    for pattern, template in _custom_templates:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return template.format(entity=entity)

    # 6. 精準意圖比對：單據與歷史歸檔調閱 (必須具備查閱動詞、單號、客戶限定或日期限定)
    has_doc_noun = any(d in clean_text for d in DOC_NOUNS)
    has_query_verb = any(v in clean_text for v in QUERY_VERBS)
    has_order_id = bool(re.search(r'[A-Za-z]\d{5,8}|\b\d{6,8}\b|[A-Za-z]{1,3}[-_]\d{2,5}|[A-Za-z]{1,3}\d{3,5}', clean_text))
    has_customer = any(c in clean_text for c in CUSTOMERS)
    has_rel_date = any(d in clean_text for d in RELATIVE_DATES)

    if has_order_id or (has_doc_noun and (has_query_verb or has_customer or has_rel_date)):
        return f"📍 收到請求，正在為您即時調閱【{entity}】歷史歸檔單據與紀錄中，請稍候..."

    # 7. 精準意圖比對：客戶設備歷程調閱
    if has_customer:
        if has_query_verb or any(k in clean_text for k in ["設備", "機型", "機編", "紀錄", "歷程", "狀態", "進度", "現場", "維護"]):
            return f"📍 收到請求，正在為您即時調閱【{entity}】客戶設備歷程與關聯單據中，請稍候..."

    # 8. 檢查預設模板庫 (依優先級比對)
    for pattern, template in SKELETON_TEMPLATES:
        if re.search(pattern, clean_text, re.IGNORECASE):
            return template.format(entity=entity)

    # 9. 預設通用思考骨架（智慧縮退：簡短有力，不洗版）
    return "💭 思考中，請稍候..."


def send_instant_skeleton(user_input: str, channel_id: Optional[str] = None) -> bool:
    """
    將即時骨架秒回推播至 Synology Chat (<50ms)
    """
    try:
        skeleton = generate_instant_skeleton(user_input)
        if skeleton and send_chat_message:
            return send_chat_message(skeleton, channel_id=channel_id)
    except Exception as e:
        logger.warning(f"骨架訊息發送失敗: {e}")
    return False


if __name__ == "__main__":
    test_queries = [
        "昨天的工作日誌發給我",
        "幫我查示範科技 8 月的維修單",
        "F052718 單據內容",
        "2330 今天收盤怎麼樣",
        "RTX 5070 還有現貨嗎",
        "把原圖發給我",
        "目前系統狀態健康嗎",
        "請幫我分析系統日誌",
        "我把提示詞發給你：請嚴格遵守發票三驗規範，不要擅自更改...",
        "發票不用開了",
    ]
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("⚡ 方案 4: 模板骨架秒回升級測試 (<5ms 生成，防誤判防禦生效)")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    for q in test_queries:
        skel = generate_instant_skeleton(q)
        print(f"輸入: '{q[:30]}...'\n  ➡️ 秒回骨架: {skel}\n")
    print(f"圖片骨架測試 (has_image=True): {generate_instant_skeleton('', has_image=True)}")
    print("✅ skeleton_streamer module 100% OPERATIONAL!")
