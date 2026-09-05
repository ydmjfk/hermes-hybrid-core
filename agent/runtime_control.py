"""
Hermes Agent Runtime Control v2 — AIRE (Autonomous Infinite-Run Engine)
Provides activity-driven keep-alive tracking, multi-dimensional budgets,
zero-lock tool churning detection, proactive output compaction,
and seamless zero-touch auto-continuation handover.
"""

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from agent.fast_path import FastPathTier
except ImportError:
    from fast_path import FastPathTier

try:
    from agent.planner import Plan, StepStatus
except ImportError:
    Plan = Any
    StepStatus = None

logger = logging.getLogger(__name__)

# Default budget constraints per Fast Path tier
TIER_BUDGET_DEFAULTS = {
    FastPathTier.L0_DIRECT_LLM: {"max_seconds": 30.0, "max_tool_calls": 0, "max_iterations": 2},
    FastPathTier.L1_READONLY_TOOL: {"max_seconds": 180.0, "max_tool_calls": 6, "max_iterations": 12},
    FastPathTier.L2_STANDARD: {"max_seconds": 400.0, "max_tool_calls": 24, "max_iterations": 24},
    FastPathTier.L3_HIGH_RISK: {"max_seconds": 360.0, "max_tool_calls": 24, "max_iterations": 16},
}


@dataclass
class RuntimeBudgetTracker:
    """
    AIRE (Autonomous Infinite-Run Engine) Budget Tracker.
    Tracks active progress, inactivity stall timeouts, tool calls, and iteration limits.
    """
    task_id: str
    tier: FastPathTier = FastPathTier.L2_STANDARD
    start_time: float = field(default_factory=time.time)
    last_activity_time: float = field(default_factory=time.time)
    max_inactivity_seconds: float = 120.0  # Deadlock stall detection limit
    max_seconds: Optional[float] = None
    max_tool_calls: Optional[int] = None
    max_iterations: Optional[int] = None
    tool_call_count: int = 0
    iteration_count: int = 0
    auto_continue: bool = True

    def __post_init__(self):
        defaults = TIER_BUDGET_DEFAULTS.get(self.tier, TIER_BUDGET_DEFAULTS[FastPathTier.L2_STANDARD])
        if self.max_seconds is None:
            self.max_seconds = float(defaults["max_seconds"])
        if self.max_tool_calls is None:
            self.max_tool_calls = int(defaults["max_tool_calls"])
        if self.max_iterations is None:
            self.max_iterations = int(defaults["max_iterations"])
        self.last_activity_time = self.start_time

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def inactive_seconds(self) -> float:
        return time.time() - self.last_activity_time

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed_seconds)

    def touch_activity(self, reason: str = "active") -> None:
        """Refreshes the activity timestamp whenever active progress (tool, LLM, file) occurs."""
        self.last_activity_time = time.time()
        logger.debug("AIRE Activity Refreshed (%s): last_activity_time=%.2f", reason, self.last_activity_time)

    def record_tool_call(self) -> None:
        self.tool_call_count += 1
        self.touch_activity("tool_call")

    def record_iteration(self) -> None:
        self.iteration_count += 1
        self.touch_activity("iteration")

    def is_stalled(self) -> bool:
        """True if no forward activity has occurred for >= max_inactivity_seconds (120s true deadlock)."""
        return self.inactive_seconds >= self.max_inactivity_seconds

    def is_time_exhausted(self) -> bool:
        """
        In AIRE architecture:
        - If stalled without activity for 120s -> return True (Deadlock protection).
        - If elapsed time exceeds single-burst threshold -> return True (to yield smooth handover / auto-continuation).
        """
        if self.is_stalled():
            return True
        return self.elapsed_seconds >= self.max_seconds

    def is_tool_budget_exhausted(self) -> bool:
        if self.tier == FastPathTier.L0_DIRECT_LLM:
            return self.tool_call_count > 0
        return self.tool_call_count >= self.max_tool_calls

    def is_iteration_exhausted(self) -> bool:
        return self.iteration_count >= self.max_iterations

    def is_near_exhaustion(self, threshold: float = 0.92) -> bool:
        """True if any hard budget has consumed >= threshold."""
        if self.tier == FastPathTier.L0_DIRECT_LLM:
            return False
        time_ratio = self.elapsed_seconds / max(1.0, self.max_seconds)
        tool_ratio = self.tool_call_count / max(1, self.max_tool_calls)
        iter_ratio = (self.iteration_count) / max(1, self.max_iterations)
        return (time_ratio >= threshold or tool_ratio >= threshold or iter_ratio >= threshold)

    def get_exhaustion_reason(self) -> Optional[str]:
        if self.is_stalled():
            return f"Inactivity stall detected (No forward progress for {self.inactive_seconds:.1f}s >= {self.max_inactivity_seconds:.1f}s)"
        if self.is_time_exhausted():
            return f"Time budget exhausted ({self.elapsed_seconds:.1f}s / {self.max_seconds:.1f}s)"
        if self.is_tool_budget_exhausted():
            return f"Tool call budget exhausted ({self.tool_call_count} / {self.max_tool_calls})"
        if self.is_iteration_exhausted():
            return f"Iteration budget exhausted ({self.iteration_count} / {self.max_iterations})"
        return None


class ToolLoopDetector:
    """Detects repeated tool calls, zero-progress loops, and broad unbounded scans."""

    def __init__(self, history_window: int = 12):
        self.history_window = history_window
        self.call_history: List[Tuple[str, str]] = []  # List of (tool_name, args_hash)
        self.blocked_counts: Dict[Tuple[str, str], int] = {}
        self.suppressed_tools: Set[str] = set()
        self.hard_tripped: bool = False
        self.tool_call_counts: Dict[str, int] = {}
        self.broad_scan_patterns = [
            re.compile(r"grep\s+.*(?:/home/\w+|/home|/root|/var|/usr|/etc)\s*$", re.IGNORECASE),
            re.compile(r"find\s+(?:/home/\w+|/home|/root|/)\s+(?:-name|-type)", re.IGNORECASE),
        ]

    def is_hard_tripped(self) -> bool:
        """True if any tool repeatedly violated loop guard and tripped breaker."""
        return self.hard_tripped

    def _hash_args(self, args: Any) -> str:
        if isinstance(args, dict):
            normalized = json.dumps(args, sort_keys=True, default=str)
        else:
            normalized = str(args)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    def inspect_tool_call(self, tool_name: str, args: Any) -> Tuple[bool, Optional[str]]:
        """
        Check if tool call indicates an unhealthy loop or dangerous broad scan.
        Returns (is_loop_or_blocked, warning_or_reason).
        """
        # If tool was already suppressed due to repeated loop
        if tool_name in self.suppressed_tools:
            return True, (
                f"[RUNTIME CONTROL BLOCKED]: Tool '{tool_name}' has been temporarily disabled "
                "for this turn due to repeated duplicate attempts. "
                "Do NOT attempt to call this tool again. Output your response directly to the user."
            )

        # Search convergence protection: max 3 calls for session_search in a single turn
        self.tool_call_counts[tool_name] = self.tool_call_counts.get(tool_name, 0) + 1
        if tool_name in ("session_search",) and self.tool_call_counts[tool_name] > 3:
            self.suppressed_tools.add(tool_name)
            self.hard_tripped = True
            return True, (
                f"[SEARCH CONVERGENCE BREAKER]: Tool '{tool_name}' has been executed {self.tool_call_counts[tool_name]} times in this turn. "
                "Repeated queries without target hit confirm that the requested historical record does NOT exist in the database. "
                "Further searching is halted to prevent infinite loops and context explosion. "
                "Please output your final answer directly now, stating clearly based on existing records or noting that no user confirmation was found."
            )

        args_hash = self._hash_args(args)
        raw_cmd = ""
        if isinstance(args, dict):
            raw_cmd = str(args.get("command") or args.get("cmd") or args.get("path") or "")
        elif isinstance(args, str):
            raw_cmd = args

        # 1. Broad unconstrained scan check
        for pat in self.broad_scan_patterns:
            if pat.search(raw_cmd.strip()):
                return True, (
                    f"Broad unbounded search detected: '{raw_cmd[:60]}...'. "
                    "Target path is too broad. Please narrow the target directory (e.g. ./tests or ./agent)."
                )

        # 2. Exact repeated tool call in recent history
        signature = (tool_name, args_hash)
        recent_matches = sum(1 for item in self.call_history[-self.history_window:] if item == signature)
        if recent_matches >= 2:
            self.blocked_counts[signature] = self.blocked_counts.get(signature, 0) + 1
            consecutive_blocks = self.blocked_counts[signature]

            # If the model repeats the blocked tool again despite warning
            if consecutive_blocks >= 2:
                self.suppressed_tools.add(tool_name)
                self.hard_tripped = True
                return True, (
                    f"[CIRCUIT BREAKER ACTIVATED]: Tool '{tool_name}' has been blocked {consecutive_blocks + 1} times "
                    "for repeated identical execution without progress. Tool calling is immediately halted. "
                    "Please provide your final answer or summary based on existing findings now."
                )

            # Context-specific guidance
            guidance = "【自癒引導】：請勿以相同參數重複調用！請立即切換策略：1. 放寬/調整關鍵字 2. 改用備援工具或搜尋結果摘要 3. 彙整現有資訊輸出。"
            if tool_name == "todo":
                guidance = "【任務清單循環防護】：你已連續多次重複讀取/更新任務清單，但未執行實質動作。嚴禁再次調用 'todo'！請立即開始執行任務清單中的下一個具體動作，或直接向使用者總結。"
            elif tool_name == "skill_view":
                guidance = "【技能查詢循環防護】：該技能可能不存在或內容已在對話歷史中。嚴禁重複調用 'skill_view'！請改用通用工具或現有資訊執行任務。"

            return True, (
                f"Repeated tool call detected ({tool_name} called {recent_matches + 1} times with identical arguments). "
                f"Execution halted to avoid infinite loop. {guidance}"
            )

        # Record into history
        self.call_history.append(signature)
        if len(self.call_history) > 50:
            self.call_history.pop(0)

        return False, None


class ToolOutputCompactor:
    """Proactively truncates huge tool outputs to protect KV Cache and inference speed."""

    @staticmethod
    def compact_output(output_text: str, max_bytes: int = 4096, keep_head_lines: int = 15, keep_tail_lines: int = 15) -> str:
        if not output_text:
            return output_text

        encoded = output_text.encode("utf-8", errors="replace")
        if len(encoded) <= max_bytes:
            return output_text

        lines = output_text.splitlines()
        if len(lines) <= (keep_head_lines + keep_tail_lines):
            return encoded[:max_bytes].decode("utf-8", errors="ignore") + "\n... [TRUNCATED DUE TO SIZE] ..."

        head = lines[:keep_head_lines]
        tail = lines[-keep_tail_lines:]
        omitted_line_count = len(lines) - (keep_head_lines + keep_tail_lines)
        omitted_bytes = len(encoded) - (len("\n".join(head).encode()) + len("\n".join(tail).encode()))

        separator = f"\n\n... [RUNTIME CONTROL: {omitted_line_count} lines ({omitted_bytes} bytes) omitted to protect KV Cache] ...\n\n"
        compacted = "\n".join(head) + separator + "\n".join(tail)
        return compacted


class GracefulHandoverManager:
    """Formats accumulated evidence ledger and plan status into a clean handover report."""

    @staticmethod
    def render_handover_report(
        agent: Any,
        task_id: str,
        reason: str,
        plan: Optional[Any] = None,
        is_auto_continuation: bool = False,
    ) -> str:
        lines = [
            "## 🛑【RUNTIME BUDGET REACHED — GRACEFUL HANDOVER】",
            f"**任務終止原因**：`{reason}`",
            "",
            "### 📊 任務進度與客觀證據匯總",
        ]

        if plan and hasattr(plan, "steps"):
            completed_count = sum(1 for s in plan.steps if getattr(s, "status", None) and getattr(s.status, "value", "") == "COMPLETED")
            lines.append(f"**目標**：{getattr(plan, 'goal', '')}")
            lines.append(f"**狀態**：`{getattr(plan.status, 'value', '')}` (已完成 {completed_count}/{len(plan.steps)} 步驟)")
            lines.append("")
            lines.append("| 步驟 ID | 步驟名稱 | 狀態 | 客觀證據 |")
            lines.append("|---|---|---|---|")
            for step in plan.steps:
                evidence = (getattr(step, "evidence_summary", "") or "無").replace("\n", " ")[:60]
                status_val = getattr(getattr(step, "status", None), "value", "PENDING")
                lines.append(f"| `{getattr(step, 'id', '')}` | {getattr(step, 'title', '')} | `{status_val}` | {evidence} |")
            lines.append("")
        else:
            lines.append("*(無多步驟計劃，單次執行任務)*")
            lines.append("")

        # Inspect evidence ledger if available
        ledger = getattr(agent, "_evidence_ledger", [])
        if ledger:
            lines.append("### 🔍 已記錄之實體證據清單 (Evidence Ledger)")
            for idx, item in enumerate(ledger[-5:], 1):
                tool = item.get("tool", "unknown")
                target = item.get("target", "")
                verdict = item.get("verdict", "UNKNOWN")
                lines.append(f"{idx}. **[{verdict}]** `{tool}`: `{target}`")
            lines.append("")

        lines.append("---")
        if is_auto_continuation:
            lines.append("⚡ **AIRE 自主無感續航**：系統已自動存檔進度，正在無縫接力執行下一步...")
        else:
            lines.append("💡 **處置建議**：系統已在達到預算上限時安全存檔並優雅交付。您可回覆「繼續」並指定後續步驟，或直接採納當前已驗證之部分成果。")
        return "\n".join(lines)
