"""
Hermes Agent Hybrid Architecture — Fast Path & Command Side-Effect Engine (Phase 1.7)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Implements Command Side-Effect & Chain Analysis:
- Action Kinds: READ, WRITE, DELETE, MOVE_COPY, PERMISSION, SYSTEM_MUTATION, EXECUTE, UNKNOWN
- Shell Chaining (&&, ||, ;, |): Any segment with mutation voids L0/L1
- Redirection (>, >>, tee): Detected as WRITE mutations
- Routing Matrix:
  * Pure conversational / Q&A -> L0 (tools=[])
  * General File READ / Safe Core READ -> L1 (max 1 turn, no human approval required)
  * General File WRITE / DELETE / Multi-step -> L2 (Standard Path -> Verifier)
  * HAOS Core WRITE / DELETE / PERMISSION / System Mutation -> L3 (Risk Gate -> Human Approval)
  * UNKNOWN -> L2 (Never downgraded to safe L0/L1)
"""

from __future__ import annotations

import logging
import re
import shlex
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class FastPathTier(str, Enum):
    """Task Execution Tiers according to complexity and risk."""
    L0_DIRECT_LLM = "L0"       # Plain text, zero tools, direct to main LLM
    L1_READONLY_TOOL = "L1"    # Single explicit read-only tool (max 1 turn)
    L2_STANDARD = "L2"         # Standard multi-step / file edit / code execution
    L3_HIGH_RISK = "L3"        # High risk / system change / critical core protection


class ActionKind(str, Enum):
    """Classified side-effect nature of an operation."""
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    MOVE_COPY = "MOVE_COPY"
    PERMISSION = "PERMISSION"
    SYSTEM_MUTATION = "SYSTEM_MUTATION"
    EXECUTE = "EXECUTE"
    CONVERSATION = "CONVERSATION"
    UNKNOWN = "UNKNOWN"


# Canonical read-only / non-mutating tool names permitted in L1 tier
READONLY_TOOL_NAMES: frozenset[str] = frozenset({
    "read_file",
    "view_file",
    "read_code",
    "grep",
    "find",
    "skills_list",
    "skill_view",
    "session_search",
    "clarify",
    "todo",
    "web_search",
    "web_extract",
    "read_terminal",
    "open_preview",
    "x_search",
    "browser_view",
    "read_extract",
})

# Mutating tool patterns/prefixes that must be strictly excluded from L1
MUTATING_TOOL_PATTERNS: tuple[str, ...] = (
    "write_",
    "patch_",
    "delete_",
    "create_",
    "edit_",
    "terminal",
    "execute_",
    "install",
    "cron",
    "send_",
    "computer_use",
    "desktop_ui",
    "close_terminal",
    "skill_manager",
    "memory_write",
    "homeassistant",
    "discord",
)


def is_tool_allowed_in_tier(tool_name: str, tier: FastPathTier) -> bool:
    """Determine if a specific tool is permitted in the given execution tier."""
    name = (tool_name or "").strip().lower()
    if tier == FastPathTier.L0_DIRECT_LLM:
        return False
    if tier == FastPathTier.L1_READONLY_TOOL:
        # Check explicit read-only whitelist
        if name in READONLY_TOOL_NAMES:
            return True
        # Check if matches any known mutating prefix/pattern
        for pat in MUTATING_TOOL_PATTERNS:
            if name.startswith(pat) or pat in name:
                return False
        # If unknown tool, default to safe exclusion in L1
        return False
    # L2 and L3 allow all registered tools to be exposed (L3 is gated at execution time by Approval Gate)
    return True


def filter_tools_for_tier(
    tools: Optional[List[Dict[str, Any]]],
    tier: FastPathTier,
) -> List[Dict[str, Any]]:
    """Filter the tool definitions list based on the FastPathTier.
    
    - L0_DIRECT_LLM: Returns [] (tools completely suppressed for pure LLM speed & zero noise)
    - L1_READONLY_TOOL: Returns ONLY read-only tools (mutating tools physically removed from schema)
    - L2_STANDARD: Returns full tools list intact
    - L3_HIGH_RISK: Returns full tools list (runtime execution gated by L3 Safety Gate)
    """
    if not tools:
        return []
    if tier == FastPathTier.L0_DIRECT_LLM:
        return []
    if tier == FastPathTier.L1_READONLY_TOOL:
        filtered: List[Dict[str, Any]] = []
        for t in tools:
            name = ""
            if isinstance(t, dict):
                if t.get("type") == "function" and isinstance(t.get("function"), dict):
                    name = t["function"].get("name", "")
                else:
                    name = t.get("name", "")
            if is_tool_allowed_in_tier(name, tier):
                filtered.append(t)
        return filtered
    return list(tools)


# Core and protected paths in HAOS & Hermes
_CORE_PATH_PATTERNS = (
    r"/haos/0[0-9]_.*\.md",
    r"00_Constitution\.md",
    r"01_Core\.md",
    r"02_Policy\.md",
    r"19_Config\.md",
    r"20_SecurityFilter\.md",
    r"27_SafetyPermission\.md",
    r"/etc/",
    r"\.ssh/",
    r"config\.yaml",
    r"SOUL\.md",
    r"haos-guardian",
)
_CORE_PATH_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in _CORE_PATH_PATTERNS)

# System-level critical commands (Always L3)
_ALWAYS_CRITICAL_COMMANDS = (
    r"\brm\s+-[rfRF]{1,4}\b",
    r"\bsudo\b",
    r"\bchattr\b",
    r"\bmkfs\b",
    r"\bchmod\s+777\b",
    r"\bkill\s+-9\b",
    r"\bdd\s+if=",
    r"\bformat\b",
)
_ALWAYS_CRITICAL_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in _ALWAYS_CRITICAL_COMMANDS)

# Regex for shell chaining separators
_SHELL_CHAIN_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")

# Shell redirection write operators (>, >>, 1>, 2>, &>, etc.)
_SHELL_REDIRECT_WRITE_RE = re.compile(r"(?:[0-9&]?>{1,2})\s*([^\s;&|]+)")

# Pre-compiled Segment Action Analyzers (Linear-time ReDoS Safe)
_TEE_RE = re.compile(r"\btee\s+(?:-a\s+)?([^\s;&|]+)")
_SED_I_RE = re.compile(r"\bsed\s+-i\b")
_DELETE_CMD_RE = re.compile(r"\b(?:rm|unlink|delete|clear|purge)\b", re.IGNORECASE)
_WRITE_CMD_RE = re.compile(r"\b(?:write|patch|edit|overwrite|modify|update|truncate)\b", re.IGNORECASE)
_CP_MV_RE = re.compile(r"\b(?:cp|mv)\b")
_PERM_CMD_RE = re.compile(r"\b(?:chmod|chown|chgrp|chattr)\b")
_CHINESE_MUTATION_WORDS = (
    "修改", "改動", "寫入", "補寫", "補充", "更新", "刪除", "覆寫",
    "建立新檔", "變更", "重構", "替換", "清空", "追加", "新增", "登記",
    "備份", "修正", "調整", "填入", "補上", "加上", "放進", "寫進",
)
_CHECK_STATUS_RE = re.compile(r"(?:確認|檢查)\s*(?:內容|狀態|檔案|日誌|進度|紀錄|單據)")

# Python file mutation patterns
_PYTHON_MUTATION_RE = re.compile(
    r"""(?:\bopen\s*\(\s*['"][^'"]+['"]\s*,\s*['"][rwa+]*(?:w|a|\+)[rwa+]*['"]\s*\)|"""
    r"""\bwrite_text\b|\bwrite_bytes\b|\bos\.remove\b|\bshutil\.rmtree\b)"""
)

# Common conversational / pure Q&A phrases (L0)
_PURE_TEXT_PATTERNS = (
    r"^(?:你好|您好|哈囉|hi\b|hello\b|hey\b|早安|午安|晚安|嗨)",
    r"(?:你是誰|介紹一下你自己|what is your name|who are you)",
    r"(?:請解釋|說明一下|什麼是|什麼意思|為何|為什麼|how does|what is|explain)",
    r"(?:翻譯|translate|總結|摘要|改寫|潤飾)",
    r"(?:寫一篇|寫一首|寫一段|講個笑話|發想)",
)
_PURE_TEXT_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in _PURE_TEXT_PATTERNS)

# Explicit Read-Only intent trigger phrases (L1) - Non-backtracking bounded regex
_READONLY_VERBS = (
    r"^(?:查看|讀取|檢視|查閱|看下|讀一下|cat\b|view\b|read\b|grep\b|find\b|search\b|search_files\b|view_file\b|read_file\b|read_code\b|list_dir\b|inspect\b|check\b|查詢)",
    r"^檔案\s+[^\r\n]{0,100}?(?:內容|長怎樣|寫什麼)",
    r"(?:搜尋|查一下|找一下|查詢|search)\s+[^\r\n]{0,100}?(?:關鍵字|紀錄|日誌|log|歷史|檔案|file)",
    r"^(?:grep|find|cat|head|tail|ls|search_files|view_file|read_file)\b",
)
_READONLY_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in _READONLY_VERBS)

# Highly sensitive files that require approval even on read
_SENSITIVE_READ_PATTERNS = (
    r"\.ssh/id_[a-zA-Z0-9]+",
    r"/etc/shadow",
    r"/etc/sudoers",
    r"\.aws/credentials",
    r"\.gnupg/secring",
)
_SENSITIVE_READ_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in _SENSITIVE_READ_PATTERNS)


def is_sensitive_read_target(path_or_text: str) -> bool:
    """Check if target path contains high-security credentials requiring approval even for reading."""
    text = str(path_or_text or "")
    for pat in _SENSITIVE_READ_COMPILED:
        if pat.search(text):
            return True
    return False


def get_tool_side_effect(tool_name: str) -> ActionKind:
    """Classify intrinsic side-effect profile of a tool by name."""
    name = (tool_name or "").strip().lower()
    if name in READONLY_TOOL_NAMES or name in ("read_file", "view_file", "search_files", "read_code", "grep", "find", "list_dir"):
        return ActionKind.READ
    if name in ("write_file", "create_file", "patch", "patch_file_op", "edit_file"):
        return ActionKind.WRITE
    if name in ("delete_file", "remove_file"):
        return ActionKind.DELETE
    if name in ("terminal", "bash", "execute_code"):
        return ActionKind.EXECUTE
    return ActionKind.UNKNOWN


class CommandSideEffectAnalyzer:
    """Detailed structural analyzer for command side-effects and target paths."""

    @classmethod
    def touches_core_path(cls, text: str) -> Tuple[bool, str]:
        """Determine if text/path references a HAOS Core protected resource."""
        for idx, pat in enumerate(_CORE_PATH_COMPILED):
            if pat.search(text):
                return True, _CORE_PATH_PATTERNS[idx]
        return False, ""

    @classmethod
    def analyze_segment(cls, segment: str) -> Tuple[Set[ActionKind], Set[str]]:
        """Analyze an individual command segment for side-effects and target files."""
        actions: Set[ActionKind] = set()
        targets: Set[str] = set()
        seg = segment.strip()
        if not seg:
            return actions, targets

        # 1. Check for Shell Redirections (>, >>, 1>, 2>, &>)
        redirect_matches = _SHELL_REDIRECT_WRITE_RE.findall(seg)
        if redirect_matches:
            actions.add(ActionKind.WRITE)
            for tgt in redirect_matches:
                targets.add(tgt.strip())

        # 2. Check for Piping into Modifying Utilities (tee, tee -a, sed -i)
        tee_match = _TEE_RE.search(seg)
        if tee_match:
            actions.add(ActionKind.WRITE)
            targets.add(tee_match.group(1).strip())

        if _SED_I_RE.search(seg):
            actions.add(ActionKind.WRITE)

        # 3. Check for File Deletion
        if _DELETE_CMD_RE.search(seg):
            actions.add(ActionKind.DELETE)

        # 4. Check for File Write / Mutation / Patching
        if _WRITE_CMD_RE.search(seg):
            actions.add(ActionKind.WRITE)

        # 5. Check for Move / Copy
        if _CP_MV_RE.search(seg):
            actions.add(ActionKind.MOVE_COPY)

        # 6. Check for Permission Changes
        if _PERM_CMD_RE.search(seg):
            actions.add(ActionKind.PERMISSION)

        # 7. Check for Python Code Execution Mutation
        if _PYTHON_MUTATION_RE.search(seg):
            actions.add(ActionKind.WRITE)

        # 8. Check for System-level Critical Commands
        for pat in _ALWAYS_CRITICAL_COMPILED:
            if pat.search(seg):
                actions.add(ActionKind.SYSTEM_MUTATION)

        # 9. Check for Chinese Mutation Action Words (Linear-time O(N) substring match, zero ReDoS)
        if any(w in seg for w in _CHINESE_MUTATION_WORDS):
            actions.add(ActionKind.WRITE)

        # 10. Check for Explicit Read Verbs
        if not (actions & {ActionKind.WRITE, ActionKind.DELETE, ActionKind.MOVE_COPY, ActionKind.PERMISSION, ActionKind.SYSTEM_MUTATION}):
            for rpat in _READONLY_COMPILED:
                if rpat.search(seg):
                    actions.add(ActionKind.READ)
                    break

        # If no specific action identified but command looks like execution
        if not actions:
            actions.add(ActionKind.EXECUTE)

        return actions, targets

    @classmethod
    def analyze_full_query(cls, query: str) -> Tuple[Set[ActionKind], bool, str]:
        """Analyze full query possibly containing chained shell commands."""
        q = (query or "").strip()
        if not q:
            return {ActionKind.CONVERSATION}, False, ""

        all_actions: Set[ActionKind] = set()
        touches_core, core_match = cls.touches_core_path(q)

        # Split into segments by shell chaining operators (&&, ||, ;, |)
        segments = _SHELL_CHAIN_SPLIT.split(q)
        for seg in segments:
            seg_actions, _ = cls.analyze_segment(seg)
            all_actions.update(seg_actions)

        return all_actions, touches_core, core_match


class FastPathClassifier:
    """Classifies user turn intent into L0, L1, L2, or L3 based on Side-Effect Analysis."""

    @classmethod
    def is_critical_escalation(cls, query: str) -> Tuple[bool, str]:
        """Determine if a query requires L3 Escalation (Risk Gate)."""
        actions, touches_core, core_pat = CommandSideEffectAnalyzer.analyze_full_query(query)

        # 1. System mutation / inherently critical
        if ActionKind.SYSTEM_MUTATION in actions:
            return True, "System-level critical command detected"

        # 2. HAOS Core touched with ANY mutation / write / delete / move / permission
        mutation_actions = {ActionKind.WRITE, ActionKind.DELETE, ActionKind.MOVE_COPY, ActionKind.PERMISSION}
        if touches_core and (actions & mutation_actions):
            return True, f"Mutation action ({[a.value for a in (actions & mutation_actions)]}) on protected core ({core_pat})"

        return False, ""

    @classmethod
    def classify(cls, user_message: str, toolsets_available: Optional[List[str]] = None) -> FastPathTier:
        """Classify incoming user message into the appropriate Fast Path tier."""
        if not isinstance(user_message, str):
            return FastPathTier.L0_DIRECT_LLM
        msg = user_message.strip()
        if not msg:
            return FastPathTier.L0_DIRECT_LLM

        # 1. Critical Escalation Check (L3)
        is_crit, _ = cls.is_critical_escalation(msg)
        if is_crit:
            return FastPathTier.L3_HIGH_RISK

        # Side-effect analysis
        actions, touches_core, _ = CommandSideEffectAnalyzer.analyze_full_query(msg)
        mutation_actions = {ActionKind.WRITE, ActionKind.DELETE, ActionKind.MOVE_COPY, ActionKind.PERMISSION, ActionKind.SYSTEM_MUTATION}

        # 1.5 Explicit File Attachment / Push request -> must be L2 (needs terminal to run request_file_attachment.py)
        if any(k in msg for k in ("發給我", "傳給我", "傳這張", "傳送檔案", "推送到聊天室", "傳送附件", "傳照片", "傳檔案", "發這篇", "發文章", "傳這篇", "傳送這張", "傳送這份")):
            return FastPathTier.L2_STANDARD

        # 1.6 Archive Fast-Path: If archive search or auto-archive report was already pre-injected in background, force L0 (0-Tool direct answer)
        is_pre_injected_search = "[系統提示：歸檔檢索引擎已在後台完成快速檢索" in msg or "--- 歸檔檢索結果 ---" in msg
        is_pre_injected_auto_archive = "[系統提示：使用者已上傳一張" in msg and "系統已在後台 0 秒自動完成" in msg
        if is_pre_injected_search or is_pre_injected_auto_archive:
            logger.info("FastPathClassifier: Detected pre-injected archive search or auto-archive completion -> Routing to L0_DIRECT_LLM (0-tool)")
            return FastPathTier.L0_DIRECT_LLM

        # 2. Check for single explicit read-only inquiry (L1)
        # Condition: ALL actions are READ (or pure inspection), zero mutations
        if not (actions & mutation_actions):
            if any(k in msg for k in ("讀取", "查閱", "查看", "檢視", "git log", "git status", "比對")):
                return FastPathTier.L1_READONLY_TOOL
            if _CHECK_STATUS_RE.search(msg):
                return FastPathTier.L1_READONLY_TOOL
            for pat in _READONLY_COMPILED:
                if pat.search(msg):
                    return FastPathTier.L1_READONLY_TOOL

        # 3. Check for pure conversational / conceptual Q&A (L0)
        # Condition: must match pure text patterns AND have zero mutation or execution actions AND no file/git read request
        if not (actions & mutation_actions) and not touches_core:
            if not any(k in msg for k in ("檔案", "目錄", "文章", "git", "log", "技術知識庫", "程式", "模組")):
                for pat in _PURE_TEXT_COMPILED:
                    if pat.search(msg):
                        if not any(k in msg for k in ("修改", "寫入", "更新", "刪除", "執行", "build", "test", "patch", "install", "terminal", "run", "cat", "grep", "ls")):
                            return FastPathTier.L0_DIRECT_LLM

        # 4. If touches core: ONLY explicit pure READ is allowed as L1
        if touches_core:
            if actions == {ActionKind.READ}:
                return FastPathTier.L1_READONLY_TOOL
            return FastPathTier.L3_HIGH_RISK

        # 5. Default to Standard Path (L2) for code modifications, multi-step tasks, scripts, or UNKNOWN
        return FastPathTier.L2_STANDARD

    @classmethod
    def should_start_planner(cls, tier: FastPathTier, subtask_count: int = 1) -> bool:
        """Only L2 with multiple steps or L3 need explicit planning."""
        if tier in (FastPathTier.L0_DIRECT_LLM, FastPathTier.L1_READONLY_TOOL):
            return False
        return subtask_count > 1 or tier == FastPathTier.L3_HIGH_RISK

    @classmethod
    def should_start_reviewer(cls, tier: FastPathTier, has_mutation: bool = False, verifier_failed: bool = False) -> bool:
        """Conditional Reviewer: only on high risk, mutation with uncertainty, or verifier failure."""
        if tier == FastPathTier.L0_DIRECT_LLM:
            return False
        if tier == FastPathTier.L1_READONLY_TOOL and not verifier_failed:
            return False
        if tier == FastPathTier.L3_HIGH_RISK or verifier_failed:
            return True
        return False

    @classmethod
    def should_run_verifier(cls, tier: FastPathTier, had_mutations: bool = False) -> bool:
        """Only MEDIUM/HIGH risk tasks or mutations strictly require objective verification."""
        if tier == FastPathTier.L0_DIRECT_LLM:
            return False
        if tier == FastPathTier.L1_READONLY_TOOL:
            return False
        return True
