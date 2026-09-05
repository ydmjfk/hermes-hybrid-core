"""
chat_client.py — 統一 Synology Chat 訊息與檔案發送客戶端
"""

import json
import logging
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, Union

from hermes_core.config_loader import get_hermes_path
from hermes_core.path_sanitizer import sanitize_path, PathSanitizerError

logger = logging.getLogger("hermes_core.chat_client")
MAX_JSON_SIZE: int = 1_048_576  # 1MB 限制以防範 JSON 反序列化 DoS 攻擊


def _redact_url(url: str) -> str:
    """遮蔽 URL 中的 token 與敏感參數以防日誌與例外洩漏 (P1-10)"""
    if not url:
        return ""
    # Mask token parameter: ?token=... or &token=...
    masked = re.sub(r"([?&]token=)[^&]+", r"\1[REDACTED]", str(url))
    # Mask user:pass in authority
    masked = re.sub(r"(://[^:\s/]+):([^@\s/]+)@", r"\1:[REDACTED]@", masked)
    return masked


def _get_ssl_context() -> ssl.SSLContext:
    """
    建立標準且安全的 SSL/TLS Context。
    預設強制要求 CERT_REQUIRED 與主機名稱檢驗，杜絕 MITM 中間人攻擊。
    僅在 TESTING_MODE == "local_sandbox" 且顯式宣告跳過驗證時放寬。
    """
    ctx = ssl.create_default_context()
    insecure_flag = os.getenv("SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY", "0").strip().lower() in ("1", "true", "yes")
    is_local_sandbox = os.getenv("TESTING_MODE") == "local_sandbox"

    if insecure_flag:
        if is_local_sandbox:
            logger.critical("🚨【重大安全警示】檢測到 TESTING_MODE=local_sandbox，已臨時放寬 SSL 憑證驗證 (僅限本地測試)！")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            logger.error("🚨【資安審計拒絕】檢測到 SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY 被設置，但在非 local_sandbox 環境下被強制忽略！SSL 驗證維持最高嚴格級別。")
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    return ctx


def _ensure_env():
    env_path = get_hermes_path(".env")
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and not os.getenv(key):
                        os.environ[key] = value


def send_chat_message(message: str, channel_id: Optional[str] = None) -> bool:
    """發送文字訊息至 Synology Chat"""
    _ensure_env()
    outgoing_token = os.getenv("SYNOLOGY_CHAT_OUTGOING_TOKEN", "").strip()
    incoming_url = os.getenv("SYNOLOGY_CHAT_INCOMING_URL", "").strip()
    target_channel = channel_id or os.getenv("SYNOLOGY_CHAT_HOME_CHANNEL", "5").strip()

    if not outgoing_token or not incoming_url:
        logger.warning("Synology Chat 發送取消：未配置 outgoing_token 或 incoming_url")
        return False

    api_url = f"{incoming_url}?token={outgoing_token}"

    try:
        from opencc import OpenCC
        message = OpenCC('s2tw').convert(message)
    except Exception as e:
        logger.debug(f"OpenCC 簡繁轉換略過: {e}")

    payload = {
        "text": message,
        "user_ids": [int(target_channel) if str(target_channel).isdigit() else 5],
    }

    try:
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"不支援的 URL 協定: {parsed.scheme}")

        form_data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
        req = urllib.request.Request(api_url, data=form_data, method="POST")
        req.add_header("User-Agent", "HermesCore/1.0")

        ctx = _get_ssl_context()

        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # nosec B310
            raw_bytes = resp.read(MAX_JSON_SIZE)
            if len(raw_bytes) >= MAX_JSON_SIZE:
                raise ValueError(f"伺服器回應過大 (超過 {MAX_JSON_SIZE} bytes 上限)")
            resp_data = raw_bytes.decode("utf-8", errors="ignore")
            res = json.loads(resp_data, strict=True)
            return bool(resp.status == 200 and res.get("success"))
    except Exception as e:
        logger.warning(f"發送訊息至 Synology Chat 失敗: {_redact_url(str(e))}")
        return False


def send_chat_file(file_path: Union[str, Path], message: str = "", channel_id: Optional[str] = None) -> bool:
    """
    發送檔案至 Synology Chat。
    安全約束 (P0-01)：
    1. 強制透過 PathSanitizer 安全邊界門禁，禁止存取沙盒外檔案。
    2. 禁止使用 'file://' 繞過沙盒路徑驗證。
    3. 嚴格驗證實體路徑 (realpath) 與符號連結 (symlink)。
    4. 阻斷敏感檔名與黑名單副檔名 (.env, .ssh, id_rsa, .pem 等)。
    5. 不存在之檔案一律 Fail Closed。
    """
    _ensure_env()

    # 1. 規範化輸入路徑，防範 file:// 協議前綴繞過
    raw_path_str = str(file_path).strip()
    if not raw_path_str:
        logger.warning("Synology Chat 檔案發送拒絕：檔案路徑為空")
        return False

    if raw_path_str.startswith("file://"):
        raw_path_str = raw_path_str[7:].lstrip()

    # 2. 強制透過 PathSanitizer 安全門禁 (Fail Closed)
    try:
        workspace_root = os.environ.get("HERMES_WORKSPACE_ROOT")
        safe_path = sanitize_path(raw_path_str, workspace_root=workspace_root, must_exist=True)

        # 3. 實體節點與類型二次驗證 (Anti-TOCTOU & Anti-Symlink Swap)
        real_path = Path(os.path.realpath(safe_path))
        if not real_path.exists() or not real_path.is_file():
            logger.warning("Synology Chat 檔案發送拒絕：目標非標準存在檔案")
            return False

        # 4. 再次對 real_path 執行沙盒邊界驗證
        verified_path = sanitize_path(real_path, workspace_root=workspace_root, must_exist=True)
    except (PathSanitizerError, FileNotFoundError, ValueError, OSError) as e:
        logger.warning(f"Synology Chat 檔案外送安全門禁阻斷: {type(e).__name__}")
        return False
    except Exception as e:
        logger.warning(f"Synology Chat 檔案安全檢驗未知例外阻斷: {type(e).__name__}")
        return False

    outgoing_token = os.getenv("SYNOLOGY_CHAT_OUTGOING_TOKEN", "").strip()
    incoming_url = os.getenv("SYNOLOGY_CHAT_INCOMING_URL", "").strip()
    target_channel = channel_id or os.getenv("SYNOLOGY_CHAT_HOME_CHANNEL", "5").strip()

    if not outgoing_token or not incoming_url:
        logger.warning("Synology Chat 發送取消：未配置 outgoing_token 或 incoming_url")
        return False

    file_url = f"file://{verified_path.resolve()}"
    api_url = f"{incoming_url}?token={outgoing_token}"

    payload = {
        "text": message,
        "file_url": file_url,
        "user_ids": [int(target_channel) if str(target_channel).isdigit() else 5],
    }

    try:
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"不支援的 URL 協定: {parsed.scheme}")

        form_data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
        req = urllib.request.Request(api_url, data=form_data, method="POST")
        req.add_header("User-Agent", "HermesCore/1.0")

        ctx = _get_ssl_context()

        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # nosec B310
            raw_bytes = resp.read(MAX_JSON_SIZE)
            if len(raw_bytes) >= MAX_JSON_SIZE:
                raise ValueError(f"伺服器回應過大 (超過 {MAX_JSON_SIZE} bytes 上限)")
            resp_data = raw_bytes.decode("utf-8", errors="ignore")
            res = json.loads(resp_data, strict=True)
            return bool(resp.status == 200 and res.get("success"))
    except Exception as e:
        logger.warning(f"發送檔案至 Synology Chat 失敗: {_redact_url(str(e))}")
        return False


def send_error_alert(error_title: str, error_details: str, channel_id: Optional[str] = None) -> bool:
    """發送格式化異常警報至 Synology Chat"""
    alert_msg = f"🚨 **【Hermes 系統異常警報】**\n📍 **項目**：{error_title}\n⚠️ **詳情**：{error_details}"
    return send_chat_message(alert_msg, channel_id=channel_id)
