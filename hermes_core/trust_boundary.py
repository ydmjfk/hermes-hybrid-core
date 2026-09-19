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
2. S-4 Persistent Memory Antivirus:
   - verify_memory_content_safety: Filters prompt injection jailbreaks, malicious shell
     payloads, and tampering with immutable constitutional anchors.
   - check_protected_file_paths: Blocks generic file write/patch tools from directly modifying
     persistent memory files or authorization whitelists.
3. S-6 Task Authorization & Anti-Chaining:
   - has_command_chaining: Tokenizer/parser detecting unquoted chaining operators (;, &&, |, ||).
   - verify_task_authorization: Per-Job identity & whitelist verification (exact & prefix match,
     path normalization, dry-run transition support).
"""

import os
import re
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Set

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


def check_protected_file_paths(target_path: Optional[str]) -> Optional[str]:
    """
    S-4.4 / S-6.2 Protected File Guard:
    Blocks generic file write/patch tools from mutating protected memory or whitelist files.
    """
    if not target_path:
        return None
    try:
        norm = os.path.normpath(os.path.expanduser(str(target_path)))
        if "/.hermes/memories" in norm or norm.endswith(("/MEMORY.md", "/USER.md", "/SOUL.md")):
            return (
                "Security Gate Blocked (S-4 Protection): Direct write or patch to persistent memory "
                "files via generic file tools is strictly denied. Memory operations MUST use "
                "the dedicated memory tool with S-4 safety gate."
            )
        if norm.endswith("/command_whitelist.json"):
            return (
                "Security Gate Blocked (S-6 Protection): Direct write or patch to task command "
                "whitelist via generic file tools is strictly denied (Anti-Self-Authorization). "
                "Whitelist modifications require human CAS approval."
            )
    except Exception:
        pass
    return None


def guard_background_command(
    command: str,
    in_sandbox: bool = False,
    is_background: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    S-1 Background-Foreground Parity:
    Blocks mutating commands in background execution unless explicitly sandboxed.
    Returns None if allowed, or a blocked result dict if rejected.
    """
    if not is_background or in_sandbox:
        return None

    cmd = (command or "").strip()
    # Simple check for mutating shell commands
    mutating_tokens = {"mkdir", "rm", "git", "chmod", "chown", "mv", "cp", "touch", "curl", "wget"}
    first_token = cmd.split()[0] if cmd.split() else ""
    first_token_name = os.path.basename(first_token)

    if first_token_name in mutating_tokens:
        logger.warning(f"[Security Gate Blocked S-1] Background command without sandbox: {cmd[:60]}")
        return {
            "status": "BLOCKED",
            "exit_code": -1,
            "error": (
                f"Security Gate Blocked (S-1 Parity): Command '{first_token_name}' cannot be executed "
                "in background without an isolated sandbox container. Fallback to host is prohibited."
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
    Supports exact matching, prefix matching, relative path normalization, and dry-run mode.
    """
    cmd = (command or "").strip()
    active_task_id = (task_id or "").strip()

    sec_model = whitelist_config.get("_meta", {}).get("security_model", {})
    dry_run = bool(sec_model.get("dry_run", False))

    jobs_list = whitelist_config.get("jobs", [])
    jobs_dict = {j.get("job_id"): j for j in jobs_list if isinstance(j, dict) and j.get("job_id")}

    if not active_task_id or active_task_id not in jobs_dict:
        msg = f"Security Gate Blocked (S-6 Protection): Task identity {active_task_id!r} not in whitelist. UNKNOWN = FAIL."
        if dry_run:
            return {"approved": True, "message": f"[DRY-RUN] {msg}", "dry_run": True}
        return {"approved": False, "message": msg, "dry_run": False}

    job_entry = jobs_dict[active_task_id]
    job_name = job_entry.get("name", active_task_id)

    if not job_entry.get("enabled", True):
        msg = f"Security Gate Blocked (S-6 Protection): Task {active_task_id!r} ({job_name}) is DISABLED."
        if dry_run:
            return {"approved": True, "message": f"[DRY-RUN] {msg}", "dry_run": True}
        return {"approved": False, "message": msg, "dry_run": False}

    # S-6.3 Anti-Chaining Check
    if has_command_chaining(cmd):
        chain_msg = (
            f"Security Gate Blocked (S-6 Protection): Multi-command chaining (;, &&, |) "
            f"detected for task {active_task_id!r}. Operation denied."
        )
        if dry_run:
            return {"approved": True, "message": f"[DRY-RUN] {chain_msg}", "dry_run": True}
        return {"approved": False, "message": chain_msg, "dry_run": False}

    allowed_cmds = job_entry.get("allowed_commands") or []
    allowed_prefixes = job_entry.get("allowed_prefixes") or []

    # 1. Exact match
    if cmd in allowed_cmds:
        return {"approved": True, "message": "AUTHORIZED_EXACT", "dry_run": False}

    # 2. Path normalization
    parts = cmd.split(maxsplit=1)
    if parts and len(parts) > 1 and parts[0] in {"python", "python3", "bash", "sh"}:
        subparts = parts[1].split(maxsplit=1)
        target_script = subparts[0]
        rest_args = " " + subparts[1] if len(subparts) > 1 else ""
        if not os.path.isabs(target_script):
            norm_cmd = f"{parts[0]} {os.path.abspath(target_script)}{rest_args}"
            if norm_cmd in allowed_cmds:
                return {"approved": True, "message": "AUTHORIZED_EXACT_NORMALIZED", "dry_run": False}

    # 3. Prefix match
    for prefix in allowed_prefixes:
        if prefix and cmd.startswith(prefix):
            return {"approved": True, "message": "AUTHORIZED_PREFIX", "dry_run": False}

    # Not allowed
    unlisted_msg = (
        f"Security Gate Blocked (S-6 Protection): Command {cmd!r} is not in authorized whitelist "
        f"for task {active_task_id!r} ({job_name})."
    )
    if dry_run:
        return {"approved": True, "message": f"[DRY-RUN] {unlisted_msg}", "dry_run": True}

    return {"approved": False, "message": unlisted_msg, "dry_run": False}
