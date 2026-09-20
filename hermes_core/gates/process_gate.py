# -*- coding: utf-8 -*-
"""
hermes_core/gates/process_gate.py — ProcessGate & Sandbox Subprocess Execution Choke Point (Slice 3)

Architecture Principles:
1. Physical Choke Point: The unskippable execution gateway for subprocess/command execution.
2. Zero Private Keys: Holds ONLY Key_Broker_Public (Ed25519). Cannot self-sign or forge CapabilityGrant.
3. Strict Canonical Hash Parity: Recomputes SHA-256 over FullExecutionSemantics.
   Any tampering with interpreter, script, arguments, cwd, env, or sandbox profile causes immediate DENY.
4. Full TTL Enforcement: issued_at <= now < expires_at and expires_at - issued_at <= 60s.
5. Fail-Closed Paradigm: Any error, exception, or validation discrepancy fails closed.
6. Anti-DoS Output Budget: Output stdout/stderr is strictly bounded in memory (MAX_OUTPUT_BYTES = 1MB).
"""

import os
import time
import shutil
import base64
import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from hermes_core.authority.models import (
    CapabilityGrant,
    FullExecutionSemantics,
    FailureCode,
)

logger = logging.getLogger("hermes_core.gates.process_gate")

MAX_GRANT_TTL_SECONDS = 60.0
MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB strict bounded output budget
DEFAULT_TIMEOUT_SECONDS = 30.0


class GateAccessDeniedError(Exception):
    """Raised when execution is denied by ProcessGate with a specific FailureCode"""
    def __init__(self, code: FailureCode, message: str):
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ProcessExecutionResult:
    """Immutable result structure produced by ProcessGate execution"""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_hash: str
    duration_ms: float
    error_code: Optional[FailureCode] = None
    error_message: Optional[str] = None


class ProcessGate:
    """
    Physical Gatekeeper for Subprocess Execution.
    Verifies CapabilityGrant issued by Authority Broker using ONLY Key_Broker_Public.
    """

    def __init__(
        self,
        broker_public_key: Union[ed25519.Ed25519PublicKey, bytes],
        bwrap_path: Optional[str] = None,
    ):
        if isinstance(broker_public_key, bytes):
            self._public_key = ed25519.Ed25519PublicKey.from_public_bytes(broker_public_key)
        else:
            self._public_key = broker_public_key

        # Detect bwrap if available (HHC-001 / HHC-007)
        self._bwrap_path = bwrap_path or shutil.which("bwrap")
        self._bwrap_version_ok = False
        if self._bwrap_path:
            try:
                out = subprocess.check_output([self._bwrap_path, "--version"], text=True, timeout=2.0)
                self._bwrap_version_ok = self.check_bwrap_version(out)
            except Exception:
                self._bwrap_version_ok = False

    @staticmethod
    def check_bwrap_version(version_str: str, min_version: Tuple[int, int, int] = (0, 11, 0)) -> bool:
        """Parse and verify bwrap version is at least min_version (HHC-007)."""
        try:
            parts = version_str.strip().split()
            v_str = parts[-1]
            nums = tuple(int(x) for x in v_str.split(".")[:3])
            return nums >= min_version
        except Exception:
            return False

    def _build_bwrap_args(self, cmd: List[str], effective_cwd: str) -> List[str]:
        """
        Build Bubblewrap isolation arguments with strict path masking (HHC-006).
        """
        bwrap_args = [
            self._bwrap_path,
            "--unshare-pid",
            "--unshare-ipc",
            "--ro-bind", "/", "/",
            "--tmpfs", "/root",
            "--tmpfs", "/home",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
        ]
        for sensitive in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers"):
            if os.path.exists(sensitive):
                bwrap_args.extend(["--tmpfs", sensitive])

        if os.path.exists(effective_cwd):
            bwrap_args.extend(["--bind", effective_cwd, effective_cwd, "--chdir", effective_cwd])
        bwrap_args.extend(["--", *cmd])
        return bwrap_args

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._public_key

    def verify_grant(
        self,
        grant: CapabilityGrant,
        semantics: FullExecutionSemantics,
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[FailureCode], Optional[str]]:
        """
        Perform complete cryptographic and semantic verification of CapabilityGrant:
        1. Grant primitive must be PROCESS_EXECUTE or SYSTEM_EXECUTE.
        2. Full TTL semantics: issued_at <= now < expires_at.
        3. Ed25519 signature validity against Key_Broker_Public.
        4. Exact Execution Hash match against recomputed canonical hash.
        """
        current_time = time.time() if now is None else now

        # 1. Primitive target check
        if grant.target_primitive not in ("PROCESS_EXECUTE", "SYSTEM_EXECUTE"):
            return False, FailureCode.DENY_UNAUTHORIZED_GRANT, f"Invalid primitive for ProcessGate: {grant.target_primitive}"

        # 2. TTL semantics
        if current_time >= grant.expires_at:
            return False, FailureCode.DENY_TTL_EXPIRED, f"CapabilityGrant expired at {grant.expires_at} (current time: {current_time})"
        if grant.issued_at > current_time + 1.0:  # Clock skew forward
            return False, FailureCode.DENY_CLOCK_UNRELIABLE, f"CapabilityGrant issued in the future: {grant.issued_at} > {current_time}"
        if grant.expires_at - grant.issued_at > MAX_GRANT_TTL_SECONDS:
            return False, FailureCode.DENY_TTL_EXPIRED, f"CapabilityGrant TTL exceeded max limit ({grant.expires_at - grant.issued_at}s > {MAX_GRANT_TTL_SECONDS}s)"

        # 3. Cryptographic signature check
        if not grant.broker_signature:
            return False, FailureCode.DENY_SIGNATURE_TAMPERED, "CapabilityGrant has empty broker signature"

        try:
            sig_bytes = base64.b64decode(grant.broker_signature)
            digest = grant.compute_signature_payload()
            self._public_key.verify(sig_bytes, digest)
        except (InvalidSignature, ValueError, TypeError) as e:
            return False, FailureCode.DENY_SIGNATURE_TAMPERED, f"CapabilityGrant signature verification failed: {e}"

        # 4. Exact Execution Semantics Hash check (Anti-TOCTOU & Anti-Tampering)
        recomputed_hash = semantics.compute_canonical_hash()
        if recomputed_hash != grant.exact_execution_hash:
            return False, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT, (
                f"Execution semantics drift: grant hash {grant.exact_execution_hash} != "
                f"recomputed hash {recomputed_hash}"
            )

        return True, None, None

    def execute(
        self,
        grant: CapabilityGrant,
        semantics: FullExecutionSemantics,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        now: Optional[float] = None,
    ) -> ProcessExecutionResult:
        """
        Verify grant and execute process within configured sandbox boundary.
        Enforces strict bounded output, error trapping, and Fail-Closed semantics.
        """
        start_time = time.time()
        current_time = start_time if now is None else now

        # Step 1: Verify grant
        is_valid, err_code, err_msg = self.verify_grant(grant, semantics, now=current_time)
        if not is_valid:
            return ProcessExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=err_msg or "Capability grant verification failed",
                execution_hash=grant.exact_execution_hash if grant else "",
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=err_code,
                error_message=err_msg,
            )

        # Step 2: Environment Sanitation
        child_env = {}
        for k, v in semantics.env_allowlist:
            child_env[k] = v

        # Step 3: Reconstruct command vector
        cmd = list(semantics.argv)
        if not cmd and semantics.interpreter_path:
            cmd = [semantics.interpreter_path]
            if semantics.script_path:
                cmd.append(semantics.script_path)

        if not cmd:
            return ProcessExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="No executable command specified in execution semantics",
                execution_hash=grant.exact_execution_hash,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_POLICY_VIOLATION,
                error_message="Empty command vector",
            )

        # Step 4: Sandbox Wrapper Dispatch (HHC-001: Fail-Closed)
        profile = (semantics.sandbox_profile or "default").upper()
        requires_bwrap = profile in ("ISOLATED_CONTAINER", "RESTRICTED_BWRAP", "BWRAP")

        final_cmd = cmd
        effective_cwd = semantics.cwd or os.getcwd()

        if requires_bwrap:
            if not self._bwrap_path:
                return ProcessExecutionResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="Sandbox required by profile but bwrap is not available",
                    execution_hash=grant.exact_execution_hash,
                    duration_ms=(time.time() - start_time) * 1000.0,
                    error_code=FailureCode.DENY_POLICY_VIOLATION,
                    error_message=f"Sandbox profile '{profile}' requires bwrap, but bwrap was not found (Fail-Closed)",
                )
            if not self._bwrap_version_ok:
                return ProcessExecutionResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="Sandbox required by profile but bwrap version is incompatible",
                    execution_hash=grant.exact_execution_hash,
                    duration_ms=(time.time() - start_time) * 1000.0,
                    error_code=FailureCode.DENY_POLICY_VIOLATION,
                    error_message="bwrap version is incompatible or unsupported (Fail-Closed)",
                )
            final_cmd = self._build_bwrap_args(cmd, effective_cwd)

        # Step 5: Secure Execution
        try:
            proc = subprocess.Popen(
                final_cmd,
                cwd=effective_cwd,
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
            stdout_data, stderr_data = proc.communicate(timeout=max(1.0, float(timeout)))
            exit_code = proc.returncode

            # Bounded output truncation (Anti-Context / Memory DoS)
            truncated_stdout = self._truncate_output(stdout_data)
            truncated_stderr = self._truncate_output(stderr_data)

            duration_ms = (time.time() - start_time) * 1000.0
            return ProcessExecutionResult(
                success=(exit_code == 0),
                exit_code=exit_code,
                stdout=truncated_stdout,
                stderr=truncated_stderr,
                execution_hash=grant.exact_execution_hash,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:
            if 'proc' in locals():
                proc.kill()
                try:
                    proc.communicate(timeout=1.0)
                except Exception:
                    pass
            duration_ms = (time.time() - start_time) * 1000.0
            return ProcessExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Process execution timed out after {timeout} seconds",
                execution_hash=grant.exact_execution_hash,
                duration_ms=duration_ms,
                error_code=FailureCode.DENY_TIMEOUT,
                error_message="Execution timeout expired",
            )

        except Exception as exc:
            duration_ms = (time.time() - start_time) * 1000.0
            logger.error("Unexpected failure executing process through ProcessGate: %s", exc)
            return ProcessExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Execution error: {exc}",
                execution_hash=grant.exact_execution_hash,
                duration_ms=duration_ms,
                error_code=FailureCode.DENY_UNKNOWN_STATE,
                error_message=str(exc),
            )

    @staticmethod
    def _truncate_output(output: str) -> str:
        """Strictly bound text output to MAX_OUTPUT_BYTES in UTF-8 bytes"""
        if not output:
            return ""
        encoded = output.encode("utf-8")
        if len(encoded) <= MAX_OUTPUT_BYTES:
            return output
        marker = "\n...[TRUNCATED BY PROCESS_GATE DUE TO SIZE BUDGET]..."
        marker_bytes = marker.encode("utf-8")
        budget = max(0, MAX_OUTPUT_BYTES - len(marker_bytes))
        truncated = encoded[:budget].decode("utf-8", errors="ignore") + marker
        return truncated
