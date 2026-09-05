"""
security_filter.py — 企業級機密資訊與密鑰自動脫敏引擎 (HAOS CAP-006 & 20_SecurityFilter)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
架構設計 (P1-03 & P1-04)：
1. SecretRule: 獨立命名之規則實體，徹底移除魔術陣列索引 (如 SECRET_PATTERNS[5])。
2. SecretPolicy: 宣告脫敏政策、策略與遮蔽程度 (完全遮蔽 / 部分掩碼)。
3. SecretDetector: 掃描文字與結構體，提供精準機密偵測結果。
4. SecretRedactor: 根據政策執行文字與巢狀資料結構的單向脫敏。
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple, Union


def mask_secret_string(secret: str, unmasked_prefix: int = 3, unmasked_suffix: int = 2) -> str:
    """
    對敏感字串進行部分掩碼遮蔽，例如 'sk-1234567890abcdef' -> 'sk-***ef'
    """
    if not secret:
        return "[REDACTED]"
    s = secret.strip()
    if len(s) <= (unmasked_prefix + unmasked_suffix):
        return "[REDACTED]"
    prefix = s[:unmasked_prefix]
    suffix = s[-unmasked_suffix:]
    return f"{prefix}***{suffix}"


@dataclass
class SecretRule:
    """單一脫敏特徵規則 (P1-04)"""
    name: str
    pattern: Pattern
    category: str
    description: str = ""
    redactor: Optional[Callable[[re.Match, bool], str]] = None


@dataclass
class SecretPolicy:
    """脫敏策略控制 (P1-03)"""
    full_redact: bool = True
    mask_prefix: int = 3
    mask_suffix: int = 2
    enabled_categories: Optional[Set[str]] = None


# 1. 統一規則庫定義 (具名字典，禁止依賴整數陣列索引)
_RAW_RULES: List[SecretRule] = [
    # 平台 API Key 與 Token
    SecretRule(
        name="OPENAI_KEY",
        pattern=re.compile(r"\b(sk-[a-zA-Z0-9_\-]{16,})\b"),
        category="api_key",
        description="OpenAI API Key"
    ),
    SecretRule(
        name="ANTHROPIC_KEY",
        pattern=re.compile(r"\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b"),
        category="api_key",
        description="Anthropic Claude API Key"
    ),
    SecretRule(
        name="GITHUB_TOKEN",
        pattern=re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{20,})\b"),
        category="token",
        description="GitHub Personal Access / OAuth Token"
    ),
    SecretRule(
        name="AWS_KEY_ID",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        category="cloud_credential",
        description="AWS Access Key ID"
    ),
    SecretRule(
        name="AWS_SECRET",
        pattern=re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"),
        category="cloud_credential",
        description="AWS Secret Access Key",
        redactor=lambda m, full: "aws_secret=[REDACTED]" if full else f"aws_secret={mask_secret_string(m.group(1))}"
    ),

    # Bearer, JWT 與 HTTP Authorization 標頭
    SecretRule(
        name="BEARER_TOKEN",
        pattern=re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b"),
        category="auth",
        description="HTTP Bearer Token",
        redactor=lambda m, full: "Bearer [REDACTED]" if full else f"Bearer {mask_secret_string(m.group(1))}"
    ),
    SecretRule(
        name="JWT_TOKEN",
        pattern=re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
        category="token",
        description="JSON Web Token (JWT)"
    ),
    SecretRule(
        name="AUTHORIZATION_HEADER",
        pattern=re.compile(r"(?i)\b(Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)([^\r\n,;]+)"),
        category="auth",
        description="Authorization Header Credential",
        redactor=lambda m, full: f"{m.group(1)}[REDACTED]" if full else f"{m.group(1)}{mask_secret_string(m.group(2))}"
    ),
    SecretRule(
        name="COOKIE_CREDENTIAL",
        pattern=re.compile(r"(?i)\b(?:cookie|set-cookie)\s*:\s*([^;\r\n]*(?:session|token|auth|jwt|id)[^;\r\n]*)"),
        category="auth",
        description="Sensitive Session / Auth Cookie",
        redactor=lambda m, full: "Cookie: [REDACTED]"
    ),

    # 連線字串與 URL 內嵌帳密 (DB URLs & URL Credentials)
    SecretRule(
        name="URL_CREDENTIALS",
        pattern=re.compile(r"(://[^:\s/]{0,256}):([^@\s/]{1,256})@"),
        category="credential",
        description="Embedded URL Credentials in URI scheme",
        redactor=lambda m, full: f"{m.group(1)}:[REDACTED]@"
    ),
    SecretRule(
        name="DB_URL_CREDENTIALS",
        pattern=re.compile(r"(?i)\b((?:postgres|postgresql|mysql|mssql|oracle|mongodb|redis)://[^:\s/]*):([^@\s/]+)@"),
        category="credential",
        description="Database Connection String Credentials",
        redactor=lambda m, full: f"{m.group(1)}:[REDACTED]@"
    ),

    # 鍵值對配置密碼 (Config / JSON / YAML)
    SecretRule(
        name="KV_PASSWORD",
        pattern=re.compile(r"(?i)(['\"]?(?:password|passwd|secret|api_key|token|access_token|private_key)['\"]?\s*[:=]\s*['\"])([^'\"\s\r\n]{6,128}?)(['\"])"),
        category="credential",
        description="Key-Value Pair Password / Secret",
        redactor=lambda m, full: f"{m.group(1)}[REDACTED]{m.group(3)}" if full else f"{m.group(1)}{mask_secret_string(m.group(2))}{m.group(3)}"
    ),
    SecretRule(
        name="GENERIC_ENV_SECRET",
        pattern=re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY))\s*=\s*['\"]?([^'\"\s\r\n]{6,128}?)['\"]?(?=\s|$)"),
        category="credential",
        description="Generic Environment Variable Secret",
        redactor=lambda m, full: f"{m.group(1)}=[REDACTED]" if full else f"{m.group(1)}={mask_secret_string(m.group(2))}"
    ),

    # PEM / RSA / EC 私鑰區塊
    SecretRule(
        name="PRIVATE_KEY_BLOCK",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
        category="private_key",
        description="PEM / RSA / EC / SSH Private Key Block",
        redactor=lambda m, full: "[REDACTED_PRIVATE_KEY_BLOCK]"
    ),
]

# 具名字典映射 (方便 O(1) 依名存取，杜絕魔術索引)
RULES: Dict[str, SecretRule] = {r.name: r for r in _RAW_RULES}

# 向後相容全域特徵清單
SECRET_PATTERNS: List[Tuple[str, Pattern]] = [(r.name, r.pattern) for r in _RAW_RULES]


class SecretDetector:
    """機密資訊檢測器 (P1-03)"""

    def __init__(self, rules: Optional[Dict[str, SecretRule]] = None):
        self.rules = rules or RULES

    def contains_secrets(self, text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        for rule in self.rules.values():
            if rule.pattern.search(text):
                return True
        return False

    def detect(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        if not text or not isinstance(text, str):
            return findings
        for rule in self.rules.values():
            for m in rule.pattern.finditer(text):
                findings.append({
                    "rule": rule.name,
                    "category": rule.category,
                    "description": rule.description,
                    "span": m.span(),
                })
        return findings


class SecretRedactor:
    """機密資訊脫敏器 (P1-03)"""

    def __init__(self, policy: Optional[SecretPolicy] = None, rules: Optional[Dict[str, SecretRule]] = None):
        self.policy = policy or SecretPolicy()
        self.rules = rules or RULES

    def redact_text(self, text: str, full_redact: Optional[bool] = None) -> str:
        if not text or not isinstance(text, str):
            return text

        is_full = self.policy.full_redact if full_redact is None else full_redact
        sanitized = text

        for rule in self.rules.values():
            if self.policy.enabled_categories and rule.category not in self.policy.enabled_categories:
                continue

            if rule.redactor:
                sanitized = rule.pattern.sub(lambda m, r=rule: r.redactor(m, is_full), sanitized)
            else:
                if is_full:
                    sanitized = rule.pattern.sub("[REDACTED]", sanitized)
                else:
                    def _sub_mask(m):
                        val = m.group(1) if m.groups() else m.group(0)
                        return mask_secret_string(
                            val,
                            unmasked_prefix=self.policy.mask_prefix,
                            unmasked_suffix=self.policy.mask_suffix
                        )
                    sanitized = rule.pattern.sub(_sub_mask, sanitized)

        return sanitized

    def redact_structure(self, data: Union[Dict, List, Any], full_redact: Optional[bool] = None) -> Union[Dict, List, Any]:
        is_full = self.policy.full_redact if full_redact is None else full_redact

        if isinstance(data, dict):
            clean_dict = {}
            for k, v in data.items():
                key_str = str(k).lower()
                if isinstance(v, (dict, list)):
                    clean_dict[k] = self.redact_structure(v, full_redact=is_full)
                elif any(s in key_str for s in ("password", "passwd", "secret", "token", "key", "credential", "auth")):
                    if isinstance(v, str):
                        clean_dict[k] = "[REDACTED]" if is_full else mask_secret_string(v)
                    else:
                        clean_dict[k] = "[REDACTED]"
                else:
                    clean_dict[k] = self.redact_structure(v, full_redact=is_full)
            return clean_dict
        elif isinstance(data, list):
            return [self.redact_structure(item, full_redact=is_full) for item in data]
        elif isinstance(data, str):
            return self.redact_text(data, full_redact=is_full)
        return data


# 預設共用單例
_default_detector = SecretDetector()
_default_redactor = SecretRedactor()


def sanitize_secrets(text: str, full_redact: bool = True) -> str:
    """掃描並淨化文字內容中的敏感資訊 (向後相容捷徑 API)"""
    return _default_redactor.redact_text(text, full_redact=full_redact)


def sanitize_dict(data: Union[Dict, List, Any], full_redact: bool = True) -> Union[Dict, List, Any]:
    """遞迴清洗字典或列表中的敏感資料結構 (向後相容捷徑 API)"""
    return _default_redactor.redact_structure(data, full_redact=full_redact)


def contains_secrets(text: str) -> bool:
    """檢測文字是否含有潛在機密字串 (向後相容捷徑 API)"""
    return _default_detector.contains_secrets(text)
