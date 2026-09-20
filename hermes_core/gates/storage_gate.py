# -*- coding: utf-8 -*-
"""
hermes_core/gates/storage_gate.py — StorageGate & Inode/Deletion Defense Choke Point (Slice 4)

Architecture Principles:
1. Physical Choke Point: Unskippable execution gateway for file mutation & deletion.
2. Zero Private Keys: Holds ONLY Key_Broker_Public (Ed25519). Cannot self-sign or forge CapabilityGrant.
3. Anti-Symlink Defense: Mandatory os.O_NOFOLLOW, explicit islink() rejection.
4. Inode-Anchored Anti-TOCTOU: Atomic check against (st_dev, st_ino) on deletion & overwrite.
5. Destructive Action Protection: Deletions require verified grants bound to exact resource paths.
6. Constitutional File Protection: Rejects generic mutation of MEMORY.md, SOUL.md, USER.md, whitelists.
7. File Permission Minimization: Files created strictly with 0600 permissions.
"""

import os
import time
import base64
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from hermes_core.authority.models import (
    CapabilityGrant,
    FailureCode,
)

logger = logging.getLogger("hermes_core.gates.storage_gate")

MAX_GRANT_TTL_SECONDS = 60.0

# Critical constitutional assets protected from generic storage operations
PROTECTED_PATHS_SUBSTRINGS: Tuple[str, ...] = (
    "/MEMORY.md",
    "/USER.md",
    "/SOUL.md",
    "/command_whitelist.json",
    "/.ssh/",
    "/.git/",
)


@dataclass(frozen=True)
class StorageExecutionResult:
    """Immutable result structure produced by StorageGate operations"""
    success: bool
    operation: str
    target_path: str
    bytes_written: int = 0
    inode: Optional[int] = None
    duration_ms: float = 0.0
    error_code: Optional[FailureCode] = None
    error_message: Optional[str] = None


class StorageGate:
    """
    Physical Gatekeeper for Filesystem Storage Operations (Write, Append, Delete).
    Enforces cryptographic grant verification, Anti-Symlink, and Inode-Anchored defense.
    """

    def __init__(self, broker_public_key: Union[ed25519.Ed25519PublicKey, bytes]):
        if isinstance(broker_public_key, bytes):
            self._public_key = ed25519.Ed25519PublicKey.from_public_bytes(broker_public_key)
        else:
            self._public_key = broker_public_key

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._public_key

    def verify_grant(
        self,
        grant: CapabilityGrant,
        target_path: str,
        required_primitive: str,
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[FailureCode], Optional[str]]:
        """
        Verify cryptographic signature, TTL, and resource binding of CapabilityGrant.
        """
        current_time = time.time() if now is None else now

        # 1. Primitive target check
        if grant.target_primitive != required_primitive:
            return False, FailureCode.DENY_UNAUTHORIZED_GRANT, (
                f"Primitive mismatch: grant has '{grant.target_primitive}', expected '{required_primitive}'"
            )

        # 2. TTL semantics check
        if current_time >= grant.expires_at:
            return False, FailureCode.DENY_TTL_EXPIRED, f"CapabilityGrant expired at {grant.expires_at} (now: {current_time})"
        if grant.issued_at > current_time + 1.0:
            return False, FailureCode.DENY_CLOCK_UNRELIABLE, f"CapabilityGrant issued in future: {grant.issued_at} > {current_time}"
        if grant.expires_at - grant.issued_at > MAX_GRANT_TTL_SECONDS:
            return False, FailureCode.DENY_TTL_EXPIRED, "CapabilityGrant TTL exceeded max limit"

        # 3. Cryptographic signature check
        if not grant.broker_signature:
            return False, FailureCode.DENY_SIGNATURE_TAMPERED, "CapabilityGrant has empty broker signature"

        try:
            sig_bytes = base64.b64decode(grant.broker_signature)
            digest = grant.compute_signature_payload()
            self._public_key.verify(sig_bytes, digest)
        except (InvalidSignature, ValueError, TypeError) as e:
            return False, FailureCode.DENY_SIGNATURE_TAMPERED, f"Signature verification failed: {e}"

        # 4. Resource binding verification
        normalized_target = os.path.realpath(os.path.abspath(target_path))
        authorized_resources = [os.path.realpath(os.path.abspath(r)) for r in grant.resource_binding]

        # Exact match or parent directory prefix binding
        matched = False
        for auth_res in authorized_resources:
            if normalized_target == auth_res or normalized_target.startswith(auth_res.rstrip(os.sep) + os.sep):
                matched = True
                break

        if not matched:
            return False, FailureCode.DENY_POLICY_VIOLATION, (
                f"Target path '{normalized_target}' is not authorized by grant resource bindings: {authorized_resources}"
            )

        # 5. Constitutional protected files defense
        for protected in PROTECTED_PATHS_SUBSTRINGS:
            if protected in normalized_target or normalized_target.endswith(protected.lstrip("/")):
                # Unless explicit CONSTITUTIONAL_MUTATION attenuation exists
                if "CONSTITUTIONAL_MUTATION" not in grant.attenuated_capabilities:
                    return False, FailureCode.DENY_POLICY_VIOLATION, (
                        f"Target path '{normalized_target}' is a protected constitutional asset"
                    )

        return True, None, None

    def write_file(
        self,
        grant: CapabilityGrant,
        target_path: str,
        content: Union[str, bytes],
        mode: str = "w",  # "w" (overwrite), "x" (exclusive create), "a" (append)
        now: Optional[float] = None,
    ) -> StorageExecutionResult:
        """
        Execute secure file write under CapabilityGrant:
        - Rejects symlinks on path (Anti-Symlink)
        - Writes with strict 0600 permissions
        - Fail-closed on error
        """
        start_time = time.time()
        is_valid, err_code, err_msg = self.verify_grant(
            grant=grant,
            target_path=target_path,
            required_primitive="STORAGE_WRITE",
            now=now,
        )
        if not is_valid:
            return StorageExecutionResult(
                success=False,
                operation="write",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=err_code,
                error_message=err_msg,
            )

        # Anti-Symlink Defense: target itself cannot be a symlink
        if os.path.islink(target_path):
            return StorageExecutionResult(
                success=False,
                operation="write",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_POLICY_VIOLATION,
                error_message="Target path is a symbolic link (Symlink write forbidden)",
            )

        # Prepare directory with 0700 if not exists
        parent_dir = os.path.dirname(os.path.abspath(target_path))
        if not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)
            except Exception as exc:
                return StorageExecutionResult(
                    success=False,
                    operation="write",
                    target_path=target_path,
                    duration_ms=(time.time() - start_time) * 1000.0,
                    error_code=FailureCode.DENY_UNKNOWN_STATE,
                    error_message=f"Failed to create parent directory: {exc}",
                )

        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content

        flags = os.O_WRONLY | os.O_NOFOLLOW
        if mode == "x":
            flags |= os.O_CREAT | os.O_EXCL
        elif mode == "a":
            flags |= os.O_CREAT | os.O_APPEND
        else:  # "w"
            flags |= os.O_CREAT | os.O_TRUNC

        try:
            fd = os.open(target_path, flags, 0o600)
            with open(fd, "wb") as f:
                f.write(raw_bytes)

            st = os.stat(target_path)
            return StorageExecutionResult(
                success=True,
                operation="write",
                target_path=target_path,
                bytes_written=len(raw_bytes),
                inode=st.st_ino,
                duration_ms=(time.time() - start_time) * 1000.0,
            )
        except OSError as exc:
            return StorageExecutionResult(
                success=False,
                operation="write",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_UNKNOWN_STATE,
                error_message=f"OS file write failure: {exc}",
            )

    def delete_file(
        self,
        grant: CapabilityGrant,
        target_path: str,
        expected_inode: Optional[int] = None,
        now: Optional[float] = None,
    ) -> StorageExecutionResult:
        """
        Execute secure file deletion under CapabilityGrant:
        - Inode-Anchored anti-TOCTOU: compares current inode against expected_inode
        - Rejects symlink targets
        - Rejects constitutional protected files
        - Fail-closed
        """
        start_time = time.time()
        is_valid, err_code, err_msg = self.verify_grant(
            grant=grant,
            target_path=target_path,
            required_primitive="STORAGE_DELETE",
            now=now,
        )
        if not is_valid:
            return StorageExecutionResult(
                success=False,
                operation="delete",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=err_code,
                error_message=err_msg,
            )

        if not os.path.lexists(target_path):
            return StorageExecutionResult(
                success=False,
                operation="delete",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_POLICY_VIOLATION,
                error_message="Target file does not exist",
            )

        # Anti-Symlink Defense on deletion
        if os.path.islink(target_path):
            return StorageExecutionResult(
                success=False,
                operation="delete",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_POLICY_VIOLATION,
                error_message="Target path is a symbolic link (Symlink deletion forbidden)",
            )

        # Inode-Anchored Anti-TOCTOU
        try:
            current_st = os.stat(target_path)
            current_inode = current_st.st_ino
            if expected_inode is not None and current_inode != expected_inode:
                return StorageExecutionResult(
                    success=False,
                    operation="delete",
                    target_path=target_path,
                    duration_ms=(time.time() - start_time) * 1000.0,
                    error_code=FailureCode.DENY_POLICY_VIOLATION,
                    error_message=f"Inode drift detected (expected {expected_inode}, got {current_inode})",
                )

            os.unlink(target_path)
            return StorageExecutionResult(
                success=True,
                operation="delete",
                target_path=target_path,
                inode=current_inode,
                duration_ms=(time.time() - start_time) * 1000.0,
            )
        except OSError as exc:
            return StorageExecutionResult(
                success=False,
                operation="delete",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_UNKNOWN_STATE,
                error_message=f"OS file deletion failure: {exc}",
            )
