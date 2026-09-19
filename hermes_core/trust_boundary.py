#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hermes_core/trust_boundary.py — Enterprise Canonical Trust Boundary Engine (HAOS vNext)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Architecture Baseline:
1. S-1/S-2 Execution Boundary:
   - guard_background_command: Enforces Background-Foreground Parity. Mutation commands (L2+)
     are strictly blocked in background unless wrapped in a verified sandbox.
   - fail_closed_sandbox_result: Exception handling strictly fails closed (UNKNOWN = FAIL).
2. S-4 Persistent Memory Antivirus & Taint Gate:
   - verify_memory_content_safety: Filters prompt injection jailbreaks, malicious shell
     payloads, and tampering with immutable constitutional anchors.
   - verify_memory_taint_provenance: Enforces taint origin gates (Web/Untrusted inputs blocked
     from directly writing persistent memory without explicit human approval).
   - check_protected_file_paths: Blocks generic file write/patch tools from directly modifying
     persistent memory files or authorization whitelists (Strict Fail-Closed).
3. S-6 Task Authorization & Anti-Chaining:
   - has_command_chaining: Tokenizer/parser detecting unquoted chaining operators (;, &&, |, ||).
   - verify_task_authorization: Per-Job identity & whitelist verification (exact & prefix match,
     path normalization, decoupled dry-run simulation mode).
"""

import os
import re
import shlex
import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Set, Union

logger = logging.getLogger("hermes_core.trust_boundary")

# Immutable anchors protected from modification or deletion
IMMUTABLE_ANCHORS: Set[str] = {
    "IMMUTABLE ANCHOR",
    "系統不可動搖演進憲法",
    "CONSTITUTIONAL ANCHOR",
}

# Prompt injection and adversarial jailbreak signatures
PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b"),
    re.compile(r"(?i)\bsystem\s+override\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+in\s+developer\s+mode\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?safety\s+guidelines\b"),
    re.compile(r"(?i)\bnew\s+system\s+prompt\b"),
]

# High-risk shell backdoor payloads
MALICIOUS_SHELL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bcurl\s+[^|\n]+?\|\s*(?:ba)?sh\b"),
    re.compile(r"\bwget\s+[^|\n]+?\|\s*(?:ba)?sh\b"),
    re.compile(r"\brm\s+-[rR]f\s+/\b"),
    re.compile(r"\bchmod\s+(?:-R\s+)?777\s+/\b"),
    re.compile(r"\b(?:nc|ncat|netcat)\s+-[lvpne]+\b"),
    re.compile(r"\bbase64\s+-d\s*\|\s*(?:ba)?sh\b"),
    re.compile(r"\bdev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
]

# Sensitive persistent files protected from generic file mutation tools
PROTECTED_FILE_SUFFIXES: Tuple[str, ...] = (
    "/MEMORY.md",
    "/USER.md",
    "/SOUL.md",
    "/command_whitelist.json",
)


class TaintTag(str, Enum):
    """Provenance Taint Level for S-4 Persistent Memory Gate"""
    SYSTEM_INTERNAL = "SYSTEM_INTERNAL"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    AGENT_SYNTHESIZED = "AGENT_SYNTHESIZED"
    UNTRUSTED_WEB = "UNTRUSTED_WEB"
    EXTERNAL_INPUT = "EXTERNAL_INPUT"


def has_command_chaining(command: str) -> bool:
    """
    Detect unquoted shell command chaining operators (;, &&, |, ||).
    Respects single and double quotes and escaped characters.
    """
    if not command:
        return False
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if c == "\\":
            escaped = True
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if not in_single and not in_double:
            if c == ";":
                return True
            if c == "&" and i + 1 < n and command[i + 1] == "&":
                return True
            if c == "|":
                return True
        i += 1
    return False


def fail_closed_sandbox_result(
    command: str,
    error: Union[Exception, str],
    task_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    S-2 Sandbox Fail-Closed Guard (UNKNOWN = FAIL):
    Standard fail-closed handler when sandbox fails to start, crashes, or encounters an exception.
    Under NO circumstances may execution fall back to host unconfined.
    """
    err_msg = str(error)
    logger.critical(
        f"[Security Gate Fail-Closed S-2] Sandbox container failure for task {task_id!r}, "
        f"command: {command[:60]!r} — Error: {err_msg}"
    )
    return {
        "status": "BLOCKED",
        "exit_code": -1,
        "stdout": "",
        "stderr": f"Security Gate Blocked (S-2 Fail-Closed): Sandbox container failed: {err_msg}. Fallback to host is prohibited.",
        "sandboxed": True,
        "fail_closed": True,
    }


def verify_memory_content_safety(
    action: str,
    target: str,
    content: Optional[str] = None,
    old_text: Optional[str] = None,
) -> Optional[str]:
    """
    S-4 Memory Antivirus:
    Verifies payload safety before mutating persistent memory.
    Returns None if safe, or an error string if blocked.
    """
    act = (action or "").lower().strip()
    cnt = content or ""
    old = old_text or ""

    # S-4.3 Immutable Anchor Protection
    if act in {"remove", "replace"}:
        for anchor in IMMUTABLE_ANCHORS:
            if anchor in old:
                return (
                    f"Security Gate Blocked (S-4 Protection): Modifying or removing '{anchor}' "
                    "in persistent memory is strictly prohibited under Immutable Constitution."
                )

    if act in {"add", "replace"}:
        # S-4.2 Anti-Injection Filter
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(cnt):
                return (
                    "Security Gate Blocked (S-4 Anti-Injection): Adversarial prompt injection "
                    "pattern detected in persistent memory payload. Operation denied."
                )
        # S-4.2 Shell Malware Filter
        for pattern in MALICIOUS_SHELL_PATTERNS:
            if pattern.search(cnt):
                return (
                    "Security Gate Blocked (S-4 Shell Defense): High-risk shell backdoor "
                    "payload detected in persistent memory payload. Operation denied."
                )

    return None


def verify_memory_taint_provenance(
    action: str,
    taint: Union[TaintTag, str],
    content: Optional[str] = None,
) -> Optional[str]:
    """
    S-4.1 Memory Taint & Provenance Gate:
    Enforces that unvetted external sources (web scraping, untrusted prompt injections)
    cannot directly modify persistent memory without explicit human approval.
    """
    act = (action or "").lower().strip()
    if act not in {"add", "replace"}:
        return None

    taint_str = str(taint.value if isinstance(taint, TaintTag) else taint).upper()
    untrusted_tags = {
        TaintTag.UNTRUSTED_WEB.value,
        TaintTag.EXTERNAL_INPUT.value,
        "UNTRUSTED",
        "EXTERNAL",
    }

    if taint_str in untrusted_tags:
        logger.warning(f"[Security Gate Blocked S-4 Taint] Attempted memory mutation with untrusted taint: {taint_str}")
        return (
            f"Security Gate Blocked (S-4 Taint Gate): Persistent memory write with untrusted taint '{taint_str}' "
            "is strictly prohibited. External or web-derived knowledge requires human approval before persistence."
        )

    return None


def check_protected_file_paths(target_path: Optional[str]) -> Optional[str]:
    """
    S-4.4 / S-6.2 Protected File Guard (Strict Fail-Closed):
    Blocks generic file write/patch tools from mutating protected memory or whitelist files.
    Enforces UNKNOWN = FAIL: Any exception during resolution blocks access.
    """
    if not target_path:
        return None
    try:
        raw_str = str(target_path).strip()
        if not raw_str:
            return None
        norm = os.path.normpath(os.path.expanduser(raw_str))
        if "/.hermes/memories" in norm or norm.endswith(("/MEMORY.md", "/USER.md", "/SOUL.md")):
            return (
                "Security Gate Blocked (S-4 Protection): Direct write or patch to persistent memory "
                "files via generic file tools is strictly denied. Memory operations MUST use "
                "the dedicated memory tool with S-4 safety gate."
            )
        if norm.endswith("/command_whitelist.json") or norm.endswith("command_whitelist.json"):
            return (
                "Security Gate Blocked (S-6 Protection): Direct write or patch to task command "
                "whitelist via generic file tools is strictly denied (Anti-Self-Authorization). "
                "Whitelist modifications require human CAS approval."
            )
        return None
    except Exception as e:
        logger.error(f"[Security Gate S-4 Fail-Closed] Path normalization failed for {target_path!r}: {e}")
        return (
            f"Security Gate Blocked (S-4 Protection): Path check failed on {target_path!r} (UNKNOWN = FAIL). "
            "Operation denied for fail-closed security."
        )


def guard_background_command(
    command: str,
    in_sandbox: bool = False,
    is_background: bool = False,
    sandbox_verified: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    S-1 Background-Foreground Parity:
    Blocks mutating commands in background execution unless explicitly sandboxed and verified.
    Inspects full command structure including interpreters (python3, bash, sh, node) to prevent bypass.
    """
    if not is_background:
        return None

    # Defense against caller-forged in_sandbox without verified token
    if in_sandbox and not sandbox_verified:
        logger.warning(
            f"[Security Gate S-1 Warning] Caller declared in_sandbox=True without verified token for: {command[:60]}"
        )

    cmd = (command or "").strip()
    if not cmd:
        return None

    mutating_binaries = {
        "mkdir", "rm", "git", "chmod", "chown", "mv", "cp", "touch", "curl", "wget",
        "dd", "truncate", "tee", "kill", "pkill", "sed", "awk", "perl", "ruby"
    }

    try:
        tokens = shlex.split(cmd)
    except Exception:
        tokens = cmd.split()

    if not tokens:
        return None

    first_binary = os.path.basename(tokens[0])

    # Direct mutating binary call
    if first_binary in mutating_binaries and not (in_sandbox and sandbox_verified):
        logger.warning(f"[Security Gate Blocked S-1] Background mutating command without verified sandbox: {cmd[:60]}")
        return {
            "status": "BLOCKED",
            "exit_code": -1,
            "error": (
                f"Security Gate Blocked (S-1 Parity): Mutating command '{first_binary}' cannot be executed "
                "in background without an isolated, verified sandbox container. Fallback to host is prohibited."
            ),
        }

    # Interpreter inspection: python3 -c, bash -c, sh -c, etc.
    interpreters = {"python", "python3", "bash", "sh", "zsh", "node"}
    if first_binary in interpreters and not (in_sandbox and sandbox_verified):
        # Scan arguments for inline code or mutation flags
        has_eval_flag = any(t in {"-c", "-e"} for t in tokens[1:3])
        if has_eval_flag:
            logger.warning(f"[Security Gate Blocked S-1] Background interpreter eval without verified sandbox: {cmd[:60]}")
            return {
                "status": "BLOCKED",
                "exit_code": -1,
                "error": (
                    f"Security Gate Blocked (S-1 Parity): Interpreter '{first_binary} {tokens[1]}' cannot execute "
                    "inline commands in background without an isolated, verified sandbox container."
                ),
            }

    return None


def verify_task_authorization(
    command: str,
    task_id: str,
    whitelist_config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    S-6 Task Whitelist Authorization:
    Verifies that command execution matches the task's registered allowlist.
    Supports exact matching, prefix matching with traversal protection, and decoupled dry-run mode.
    
    CRITICAL INVARIANT (Gap 7):
    'approved' indicates actual execution permission.
    In dry-run mode for denied commands, 'approved' MUST BE False, with 'dry_run_mode': True
    and 'action': 'LOG_ONLY' to prevent upper execution layers from confusing simulation with approval.
    """
    cmd = (command or "").strip()
    active_task_id = (task_id or "").strip()

    sec_model = whitelist_config.get("_meta", {}).get("security_model", {})
    dry_run = bool(sec_model.get("dry_run", False))

    jobs_list = whitelist_config.get("jobs", [])
    jobs_dict = {j.get("job_id"): j for j in jobs_list if isinstance(j, dict) and j.get("job_id")}

    def _make_deny_decision(msg: str) -> Dict[str, Any]:
        if dry_run:
            return {
                "approved": False,
                "dry_run_mode": True,
                "action": "LOG_ONLY",
                "message": f"[DRY-RUN SIMULATION] {msg}",
            }
        return {
            "approved": False,
            "dry_run_mode": False,
            "action": "BLOCKED",
            "message": msg,
        }

    if not active_task_id or active_task_id not in jobs_dict:
        return _make_deny_decision(
            f"Security Gate Blocked (S-6 Protection): Task identity {active_task_id!r} not in whitelist. UNKNOWN = FAIL."
        )

    job_entry = jobs_dict[active_task_id]
    job_name = job_entry.get("name", active_task_id)

    if not job_entry.get("enabled", True):
        return _make_deny_decision(
            f"Security Gate Blocked (S-6 Protection): Task {active_task_id!r} ({job_name}) is DISABLED."
        )

    # S-6.3 Anti-Chaining Check
    if has_command_chaining(cmd):
        return _make_deny_decision(
            f"Security Gate Blocked (S-6 Protection): Multi-command chaining (;, &&, |) "
            f"detected for task {active_task_id!r}. Operation denied."
        )

    allowed_cmds = job_entry.get("allowed_commands") or []
    allowed_prefixes = job_entry.get("allowed_prefixes") or []

    # 1. Exact match
    if cmd in allowed_cmds:
        return {
            "approved": True,
            "dry_run_mode": dry_run,
            "action": "EXECUTE",
            "message": "AUTHORIZED_EXACT",
        }

    # 2. Path normalization
    parts = cmd.split(maxsplit=1)
    if parts and len(parts) > 1 and parts[0] in {"python", "python3", "bash", "sh"}:
        subparts = parts[1].split(maxsplit=1)
        target_script = subparts[0]
        rest_args = " " + subparts[1] if len(subparts) > 1 else ""
        if not os.path.isabs(target_script):
            norm_cmd = f"{parts[0]} {os.path.abspath(target_script)}{rest_args}"
            if norm_cmd in allowed_cmds:
                return {
                    "approved": True,
                    "dry_run_mode": dry_run,
                    "action": "EXECUTE",
                    "message": "AUTHORIZED_EXACT_NORMALIZED",
                }

    # 3. Prefix match with traversal defense (Gap 8)
    for prefix in allowed_prefixes:
        if prefix and cmd.startswith(prefix):
            # Check for path traversal in prefix arguments
            remainder = cmd[len(prefix):]
            if ".." in remainder:
                return _make_deny_decision(
                    f"Security Gate Blocked (S-6 Protection): Path traversal '..' detected in command remainder "
                    f"under prefix {prefix!r} for task {active_task_id!r}."
                )
            return {
                "approved": True,
                "dry_run_mode": dry_run,
                "action": "EXECUTE",
                "message": "AUTHORIZED_PREFIX",
            }

    # Not allowed
    return _make_deny_decision(
        f"Security Gate Blocked (S-6 Protection): Command {cmd!r} is not in authorized whitelist "
        f"for task {active_task_id!r} ({job_name})."
    )
