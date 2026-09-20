# -*- coding: utf-8 -*-
"""
hermes_core/authority/models.py — Data Models for Authority Broker & Capability Grants (Slice 1)
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class FailureCode(str, Enum):
    """Failure reason codes adhering to Fail-Closed paradigm"""
    DENY_UNKNOWN_STATE = "DENY_UNKNOWN_STATE"
    DENY_TIMEOUT = "DENY_TIMEOUT"
    DENY_BROKER_OFFLINE = "DENY_BROKER_OFFLINE"
    DENY_SIGNATURE_TAMPERED = "DENY_SIGNATURE_TAMPERED"
    DENY_CLOCK_UNRELIABLE = "DENY_CLOCK_UNRELIABLE"
    DENY_TTL_EXPIRED = "DENY_TTL_EXPIRED"
    DENY_REPLAY_ATTACK = "DENY_REPLAY_ATTACK"
    DENY_UNAUTHORIZED_PEER = "DENY_UNAUTHORIZED_PEER"
    DENY_EXECUTION_SEMANTICS_DRIFT = "DENY_EXECUTION_SEMANTICS_DRIFT"
    DENY_UNAUTHORIZED_GRANT = "DENY_UNAUTHORIZED_GRANT"
    DENY_INVALID_MANIFEST = "DENY_INVALID_MANIFEST"
    DENY_POLICY_VIOLATION = "DENY_POLICY_VIOLATION"
    DENY_NONCE_STORE_SATURATED = "DENY_NONCE_STORE_SATURATED"


class AuthorityError(Exception):
    """Base exception for authority domain"""
    pass


class BrokerUnavailableError(AuthorityError):
    """Raised when Broker is unreachable, offline, or times out (Fail-Closed)"""
    pass


class CapabilityDeniedError(AuthorityError):
    """Raised when Broker denies capability request with specific failure code"""
    def __init__(self, code: FailureCode, message: str):
        super().__init__(f"[{code.value}] {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ProvenanceContext:
    """Provenance tracking context for requests"""
    caller_id: str
    origin_source: str
    taint_tag: str  # e.g., EXTERNAL_UNTRUSTED, SYSTEM_INTERNAL
    ingress_signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProvenanceContext":
        return cls(
            caller_id=str(data.get("caller_id", "")),
            origin_source=str(data.get("origin_source", "")),
            taint_tag=str(data.get("taint_tag", "EXTERNAL_UNTRUSTED")),
            ingress_signature=str(data.get("ingress_signature", "")),
        )


@dataclass(frozen=True)
class TaskManifest:
    """Immutable task manifest describing permitted primitives and resource scope"""
    manifest_id: str
    allowed_primitives: Tuple[str, ...]
    allowed_resources: Tuple[str, ...]
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "allowed_primitives": list(self.allowed_primitives),
            "allowed_resources": list(self.allowed_resources),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskManifest":
        return cls(
            manifest_id=str(data.get("manifest_id", "")),
            allowed_primitives=tuple(data.get("allowed_primitives", ())),
            allowed_resources=tuple(data.get("allowed_resources", ())),
            signature=str(data.get("signature", "")),
        )


@dataclass(frozen=True)
class FullExecutionSemantics:
    """Complete execution semantics used for deterministic canonical hashing"""
    interpreter_path: str
    interpreter_hash: str
    script_path: str
    script_hash: str
    argv: Tuple[str, ...]
    cwd: str
    env_allowlist: Tuple[Tuple[str, str], ...]  # Key-Value pairs
    sandbox_profile: str
    network_policy: str

    def compute_canonical_hash(self) -> str:
        """
        Produce deterministic SHA-256 hash over canonical representation.
        Broker canonicalizes and computes this; client claims are not trusted.
        """
        canonical_dict = {
            "interpreter_path": self.interpreter_path,
            "interpreter_hash": self.interpreter_hash,
            "script_path": self.script_path,
            "script_hash": self.script_hash,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env_allowlist": sorted(list(self.env_allowlist)),
            "sandbox_profile": self.sandbox_profile,
            "network_policy": self.network_policy,
        }
        raw_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interpreter_path": self.interpreter_path,
            "interpreter_hash": self.interpreter_hash,
            "script_path": self.script_path,
            "script_hash": self.script_hash,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "env_allowlist": list(self.env_allowlist),
            "sandbox_profile": self.sandbox_profile,
            "network_policy": self.network_policy,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FullExecutionSemantics":
        raw_env = data.get("env_allowlist", [])
        if isinstance(raw_env, dict):
            env_pairs = tuple(sorted((str(k), str(v)) for k, v in raw_env.items()))
        else:
            env_pairs = tuple((str(k), str(v)) for k, v in raw_env)
        return cls(
            interpreter_path=str(data.get("interpreter_path", "")),
            interpreter_hash=str(data.get("interpreter_hash", "")),
            script_path=str(data.get("script_path", "")),
            script_hash=str(data.get("script_hash", "")),
            argv=tuple(str(arg) for arg in data.get("argv", ())),
            cwd=str(data.get("cwd", "")),
            env_allowlist=env_pairs,
            sandbox_profile=str(data.get("sandbox_profile", "default")),
            network_policy=str(data.get("network_policy", "deny_all")),
        )


@dataclass(frozen=True)
class HumanApprovalProof:
    """External cryptographic proof of explicit human approval from CAS/Synology"""
    token_id: str
    approver_id: str
    approver_sig: str
    issued_at: float
    valid_until: float
    token_nonce: str
    exact_execution_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HumanApprovalProof":
        return cls(
            token_id=str(data.get("token_id", "")),
            approver_id=str(data.get("approver_id", "")),
            approver_sig=str(data.get("approver_sig", "")),
            issued_at=float(data.get("issued_at", 0.0)),
            valid_until=float(data.get("valid_until", 0.0)),
            token_nonce=str(data.get("token_nonce", "")),
            exact_execution_hash=str(data.get("exact_execution_hash", "")),
        )


@dataclass(frozen=True)
class CapabilityRequest:
    """Request sent by Agent across UDS IPC to Authority Broker"""
    request_id: str
    task_id: str
    requested_primitive: str
    provenance: ProvenanceContext
    untrusted_semantics: FullExecutionSemantics
    human_approval: Optional[HumanApprovalProof] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "task_id": self.task_id,
            "requested_primitive": self.requested_primitive,
            "provenance": self.provenance.to_dict(),
            "untrusted_semantics": self.untrusted_semantics.to_dict(),
            "human_approval": self.human_approval.to_dict() if self.human_approval else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityRequest":
        ha_raw = data.get("human_approval")
        return cls(
            request_id=str(data.get("request_id", "")),
            task_id=str(data.get("task_id", "")),
            requested_primitive=str(data.get("requested_primitive", "")),
            provenance=ProvenanceContext.from_dict(data.get("provenance", {})),
            untrusted_semantics=FullExecutionSemantics.from_dict(data.get("untrusted_semantics", {})),
            human_approval=HumanApprovalProof.from_dict(ha_raw) if ha_raw else None,
        )


@dataclass(frozen=True)
class CapabilityGrant:
    """Cryptographically signed capability voucher issued exclusively by Authority Broker"""
    grant_id: str
    issued_at: float
    expires_at: float
    single_use_nonce: str
    subject_uid: int
    target_primitive: str
    exact_execution_hash: str
    attenuated_capabilities: Tuple[str, ...]
    broker_signature: str
    task_id: str = ""
    resource_binding: Tuple[str, ...] = ()

    def compute_signature_payload(self) -> bytes:
        """Deterministic serialization for signing and verifying the grant"""
        payload = {
            "grant_id": self.grant_id,
            "issued_at": round(self.issued_at, 4),
            "expires_at": round(self.expires_at, 4),
            "single_use_nonce": self.single_use_nonce,
            "subject_uid": self.subject_uid,
            "target_primitive": self.target_primitive,
            "exact_execution_hash": self.exact_execution_hash,
            "attenuated_capabilities": sorted(list(self.attenuated_capabilities)),
            "task_id": self.task_id,
            "resource_binding": sorted(list(self.resource_binding)),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "single_use_nonce": self.single_use_nonce,
            "subject_uid": self.subject_uid,
            "target_primitive": self.target_primitive,
            "exact_execution_hash": self.exact_execution_hash,
            "attenuated_capabilities": list(self.attenuated_capabilities),
            "task_id": self.task_id,
            "resource_binding": list(self.resource_binding),
            "broker_signature": self.broker_signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityGrant":
        return cls(
            grant_id=str(data.get("grant_id", "")),
            issued_at=float(data.get("issued_at", 0.0)),
            expires_at=float(data.get("expires_at", 0.0)),
            single_use_nonce=str(data.get("single_use_nonce", "")),
            subject_uid=int(data.get("subject_uid", 0)),
            target_primitive=str(data.get("target_primitive", "")),
            exact_execution_hash=str(data.get("exact_execution_hash", "")),
            attenuated_capabilities=tuple(data.get("attenuated_capabilities", ())),
            task_id=str(data.get("task_id", "")),
            resource_binding=tuple(str(r) for r in data.get("resource_binding", ())),
            broker_signature=str(data.get("broker_signature", "")),
        )
