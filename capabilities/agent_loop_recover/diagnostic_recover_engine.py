#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAP-003: Claude-Style Structured Diagnostic Extraction & Recovery Engine (Promoted Capability)
=============================================================================================
Parses raw tool/command failure stderr into deterministic, structured
Diagnostic Signatures, and produces surgical Recovery Directives for the model.
Features:
  1. Multi-domain Error Extraction (Python AST, SQLite, Shell, Network, Permission).
  2. Bounded 2-Attempt Fix Controller (Prevents repeating identical hypotheses).
  3. Actionable Structured Recovery Directives (Provides root cause, file/line, and anti-patterns).
  4. Fail-Closed Unknown Handling (Unknown errors are explicitly marked and not guessed).
"""

import re
import time
import json
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple


class ErrorCategory(str, Enum):
    SYNTAX_ERROR = "SYNTAX_ERROR"
    MODULE_NOT_FOUND = "MODULE_NOT_FOUND"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SQLITE_ERROR = "SQLITE_ERROR"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    TYPE_OR_VALUE_ERROR = "TYPE_OR_VALUE_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class DiagnosticSignature:
    category: ErrorCategory
    exception_type: str
    summary: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    matched_text: str = ""
    suggested_action: str = ""
    signature_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


class DiagnosticRecoverEngine:
    """
    Claude-style Observe & Recover engine for error feature extraction and guided repair.
    """

    MAX_REPAIR_ATTEMPTS = 2

    def __init__(self):
        self.repair_history: Dict[str, List[Dict[str, Any]]] = {}

    def extract_signature(self, exit_code: int, stderr: str, stdout: str = "") -> DiagnosticSignature:
        """
        Parse stderr and exit code into a structured DiagnosticSignature.
        """
        combined = f"{stderr}\n{stdout}".strip()

        # 1. Python Syntax / Indentation Error
        syntax_match = re.search(
            r'File "([^"]+)", line (\d+)(?:, in (\w+))?.*?\n\s*(.*?)\n(?:([a-zA-Z]+Error):\s*(.*))',
            combined,
            re.DOTALL
        )
        if syntax_match and ("SyntaxError" in combined or "IndentationError" in combined):
            fpath, lno, func, snippet, exc_type, msg = syntax_match.groups()
            sig = DiagnosticSignature(
                category=ErrorCategory.SYNTAX_ERROR,
                exception_type=exc_type or "SyntaxError",
                summary=f"語法錯誤：{msg.strip() if msg else '語法不合規'}",
                file_path=fpath,
                line_number=int(lno) if lno else None,
                function_name=func,
                matched_text=snippet.strip() if snippet else "",
                suggested_action="使用 inline_patch 精準修復該行之括號、縮排或關鍵字語法，嚴禁全檔盲寫。"
            )
            sig.signature_hash = f"SYNTAX:{fpath}:{lno}"
            return sig

        # 2. Module / Import Error
        mod_match = re.search(r'(?:ModuleNotFoundError|ImportError):\s*No module named [\'"]([^\'"]+)[\'"]', combined)
        if mod_match:
            mod_name = mod_match.group(1)
            sig = DiagnosticSignature(
                category=ErrorCategory.MODULE_NOT_FOUND,
                exception_type="ModuleNotFoundError",
                summary=f"套件缺失：找不到模組 '{mod_name}'",
                matched_text=mod_match.group(0),
                suggested_action=f"檢查環境中是否已安裝 '{mod_name}'，或改用標準函式庫替代方案。"
            )
            sig.signature_hash = f"MODULE:{mod_name}"
            return sig

        # 3. SQLite Database Locked / Operational Error
        sqlite_match = re.search(r'sqlite3\.(?:OperationalError|DatabaseError):\s*(.*)', combined)
        if sqlite_match:
            msg = sqlite_match.group(1).strip()
            action = "執行 PRAGMA table_info 檢查 schema，或使用 WAL 模式/重試釋放鎖定。" if "locked" in msg else "請先執行 .schema 檢查資料表與欄位真實性。"
            sig = DiagnosticSignature(
                category=ErrorCategory.SQLITE_ERROR,
                exception_type="sqlite3.OperationalError",
                summary=f"SQLite 資料庫錯誤：{msg}",
                matched_text=sqlite_match.group(0),
                suggested_action=action
            )
            sig.signature_hash = f"SQLITE:{msg[:30]}"
            return sig

        # 4. Permission Denied / EACCES
        perm_match = re.search(r'(?:PermissionError:\s*\[Errno 13\]\s*Permission denied:\s*[\'"]?([^\'"\n]+)[\'"]?|Permission denied)', combined)
        if perm_match:
            target = perm_match.group(1) if perm_match.group(1) else "目標資源"
            sig = DiagnosticSignature(
                category=ErrorCategory.PERMISSION_DENIED,
                exception_type="PermissionError",
                summary=f"權限不足：無法存取或寫入 '{target}'",
                matched_text=perm_match.group(0),
                suggested_action="檢查檔案權限 (chmod) 或沙盒邊界設定，切勿嘗試 sudo 越權。"
            )
            sig.signature_hash = f"PERM:{target}"
            return sig

        # 5. File Not Found
        fnf_match = re.search(r'(?:FileNotFoundError:\s*\[Errno 2\]\s*No such file or directory:\s*[\'"]?([^\'"\n]+)[\'"]?|No such file or directory:\s*([^\n]+))', combined)
        if fnf_match:
            fpath = fnf_match.group(1) or fnf_match.group(2)
            sig = DiagnosticSignature(
                category=ErrorCategory.FILE_NOT_FOUND,
                exception_type="FileNotFoundError",
                summary=f"檔案不存在：找不到 '{fpath.strip()}'",
                matched_text=fnf_match.group(0),
                suggested_action="先透過 search_files 或 ls 探測真實實體路徑，嚴禁盲猜路徑。"
            )
            sig.signature_hash = f"FNF:{fpath.strip()}"
            return sig

        # 6. Network Timeout / Connection Refused
        net_match = re.search(r'(?:TimeoutError|ConnectionRefusedError|ConnectTimeout|HTTPError.*(?:408|504|Connection refused))', combined)
        if net_match:
            sig = DiagnosticSignature(
                category=ErrorCategory.NETWORK_TIMEOUT,
                exception_type="NetworkError",
                summary="網路連線逾時或端點無回應",
                matched_text=net_match.group(0),
                suggested_action="檢查本機微服務 (8647/8080/9377) 狀態，或啟用本機快取降級機制。"
            )
            sig.signature_hash = "NET:TIMEOUT"
            return sig

        # 7. Generic Python Exception with Traceback
        py_exc_match = re.search(
            r'File [\'"]([^\'"]+)[\'"], line (\d+)(?:, in (\w+))?.*?\n.*?(?:([a-zA-Z]+Error|Exception):\s*(.*))',
            combined,
            re.DOTALL
        )
        if py_exc_match:
            fpath, lno, func, exc_type, msg = py_exc_match.groups()
            sig = DiagnosticSignature(
                category=ErrorCategory.TYPE_OR_VALUE_ERROR,
                exception_type=exc_type or "PythonException",
                summary=f"{exc_type}: {msg.strip() if msg else '執行期異常'}",
                file_path=fpath,
                line_number=int(lno) if lno else None,
                function_name=func,
                matched_text=f"{exc_type}: {msg.strip() if msg else ''}",
                suggested_action="依據行號與例外類型檢查變數型別、索引長度或邊界條件。"
            )
            sig.signature_hash = f"PYEXC:{fpath}:{lno}:{exc_type}"
            return sig

        # 8. Fallback Unknown Error (Fail-Closed)
        snippet = combined[:150].strip() if combined else f"Exit Code {exit_code}"
        sig = DiagnosticSignature(
            category=ErrorCategory.UNKNOWN_ERROR,
            exception_type=f"ExitCode_{exit_code}",
            summary=f"未分類執行錯誤 (Exit Code {exit_code})",
            matched_text=snippet,
            suggested_action="調閱完整 Log 並遵循六階段診斷 SOP 進行假設驗證，嚴禁盲目重試。"
        )
        sig.signature_hash = f"UNKNOWN:{exit_code}:{snippet[:20]}"
        return sig

    def generate_recovery_directive(self, signature: DiagnosticSignature) -> Dict[str, Any]:
        """
        Generate structured, actionable recovery directives for the model.
        """
        history = self.repair_history.get(signature.signature_hash, [])
        attempt = len(history) + 1

        is_escalated = attempt > self.MAX_REPAIR_ATTEMPTS

        directive_md = f"""### 🚨 錯誤自癒診斷提示 (Attempt {attempt}/{self.MAX_REPAIR_ATTEMPTS})
- **錯誤分類**：`{signature.category.value}`
- **例外類型**：`{signature.exception_type}`
- **根因摘要**：{signature.summary}
- **涉及位置**：`{signature.file_path or 'N/A'}` (行號: `{signature.line_number or 'N/A'}`)
- **建議修復方針**：{signature.suggested_action}
- **🚫 禁忌守則**：嚴禁重複發動相同失敗指令；若修復超過 {self.MAX_REPAIR_ATTEMPTS} 次將強制停止並呈報。"""

        return {
            "attempt": attempt,
            "max_attempts": self.MAX_REPAIR_ATTEMPTS,
            "is_escalated": is_escalated,
            "signature": signature.to_dict(),
            "directive_markdown": directive_md
        }

    def record_repair_attempt(self, signature_hash: str, repair_action: str) -> None:
        """Record an attempted repair action for a signature."""
        if signature_hash not in self.repair_history:
            self.repair_history[signature_hash] = []
        self.repair_history[signature_hash].append({
            "timestamp": time.time(),
            "action": repair_action
        })
