# -*- coding: utf-8 -*-
"""
hermes_core/approval/service.py — CAS Human Approval Service & Token Verifier (Slice 2)
"""

import time
import json
import uuid
import base64
import hashlib
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from hermes_core.authority.models import HumanApprovalProof

# Maximum allowed TTL for human approval tokens (120 seconds)
MAX_APPROVAL_TTL_SECONDS = 120.0
DEFAULT_APPROVAL_TTL_SECONDS = 60.0


def compute_approval_digest(
    token_id: str,
    approver_id: str,
    issued_at: float,
    valid_until: float,
    token_nonce: str,
    exact_execution_hash: str,
) -> bytes:
    """
    Compute deterministic canonical digest for human approval token authentication.
    """
    canonical_dict = {
        "token_id": token_id.strip(),
        "approver_id": approver_id.strip(),
        "issued_at": round(issued_at, 4),
        "valid_until": round(valid_until, 4),
        "token_nonce": token_nonce.strip(),
        "exact_execution_hash": exact_execution_hash.strip(),
    }
    raw_bytes = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw_bytes).digest()


class HumanApprovalService:
    """
    Independent Human Approval Service (CAS / Synology Approval backend).
    Holds Key_Approval (Ed25519 private key) in an isolated process/boundary.
    Agent runtime NEVER possesses this key.
    """

    def __init__(self, private_key: Optional[Union[ed25519.Ed25519PrivateKey, bytes]] = None):
        if private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        elif isinstance(private_key, bytes):
            if len(private_key) == 32:
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            else:
                seed = hashlib.sha256(private_key).digest()
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        else:
            self._private_key = private_key

        self._public_key = self._private_key.public_key()

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._public_key

    def get_public_key(self) -> bytes:
        """Return raw 32 bytes public key for verifiers"""
        return self._public_key.public_bytes_raw()

    def issue_approval(
        self,
        approver_id: str,
        exact_execution_hash: str,
        ttl_seconds: float = DEFAULT_APPROVAL_TTL_SECONDS,
        now: Optional[float] = None,
    ) -> HumanApprovalProof:
        """
        Issue a cryptographically signed HumanApprovalProof bound to the exact execution hash.
        """
        current_time = time.time() if now is None else now
        clamped_ttl = min(max(1.0, float(ttl_seconds)), MAX_APPROVAL_TTL_SECONDS)
        valid_until = current_time + clamped_ttl

        token_id = str(uuid.uuid4())
        token_nonce = uuid.uuid4().hex

        digest = compute_approval_digest(
            token_id=token_id,
            approver_id=approver_id,
            issued_at=current_time,
            valid_until=valid_until,
            token_nonce=token_nonce,
            exact_execution_hash=exact_execution_hash,
        )

        sig_bytes = self._private_key.sign(digest)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        return HumanApprovalProof(
            token_id=token_id,
            approver_id=approver_id,
            approver_sig=sig_b64,
            issued_at=current_time,
            valid_until=valid_until,
            token_nonce=token_nonce,
            exact_execution_hash=exact_execution_hash,
        )


class ApprovalTokenVerifier:
    """
    Offline verification component holding ONLY Key_Approval_Public.
    Used by Authority Broker to verify human approval tokens without possessing private keys.
    """

    def __init__(self, public_key: Union[ed25519.Ed25519PublicKey, bytes]):
        if isinstance(public_key, bytes):
            self._public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        else:
            self._public_key = public_key

    def verify_approval(
        self,
        proof: HumanApprovalProof,
        expected_hash: Optional[str] = None,
        now: Optional[float] = None,
    ) -> bool:
        """
        Verify that the HumanApprovalProof:
        1. Has a valid Ed25519 signature from the approval authority.
        2. Has not expired (now <= valid_until) and issued_at <= now + 1.0 (clock skew guard).
        3. Respects MAX_APPROVAL_TTL_SECONDS.
        4. Matches expected_hash if provided.
        """
        current_time = time.time() if now is None else now

        # Full time semantics check
        if current_time > proof.valid_until:
            return False
        if proof.issued_at > current_time + 1.0:  # Clock skew forward
            return False
        if proof.valid_until - proof.issued_at > MAX_APPROVAL_TTL_SECONDS:
            return False

        # Hash matching check
        if expected_hash is not None and proof.exact_execution_hash != expected_hash:
            return False

        if not proof.approver_sig:
            return False

        try:
            sig_bytes = base64.b64decode(proof.approver_sig)
            digest = compute_approval_digest(
                token_id=proof.token_id,
                approver_id=proof.approver_id,
                issued_at=proof.issued_at,
                valid_until=proof.valid_until,
                token_nonce=proof.token_nonce,
                exact_execution_hash=proof.exact_execution_hash,
            )
            self._public_key.verify(sig_bytes, digest)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
