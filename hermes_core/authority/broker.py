# -*- coding: utf-8 -*-
"""
hermes_core/authority/broker.py — Authority Broker Daemon Implementation (Slice 1)
"""

import os
import sys
import time
import json
import base64
import hashlib
import stat
import uuid
import struct
import socket
import logging
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .models import (
    ProvenanceContext,
    TaskManifest,
    FullExecutionSemantics,
    CapabilityRequest,
    HumanApprovalProof,
    CapabilityGrant,
    FailureCode,
    AuthorityError,
    BrokerUnavailableError,
    CapabilityDeniedError,
)
from hermes_core.provenance.signer import ProvenanceVerifier
from hermes_core.approval.service import ApprovalTokenVerifier

logger = logging.getLogger("hermes_core.authority.broker")

# Maximum permitted grant TTL in seconds
MAX_GRANT_TTL_SECONDS = 60.0
DEFAULT_GRANT_TTL_SECONDS = 30.0

# S1-PATCH P1: Nonce retention window (time-based GC).
# A consumed nonce must remain in the replay ledger at least as long as any
# token that could carry it remains valid: approval tokens (<= 60s) and
# issued grants (<= 60s). 2 * MAX_GRANT_TTL_SECONDS covers both windows.
NONCE_RETENTION_SECONDS = MAX_GRANT_TTL_SECONDS * 2

# S1-PATCH P1: Hard memory bound for the nonce ledger. The ledger is bounded
# by time-based GC (only expired entries are removed); this cap is a
# fail-closed backstop so memory can never grow unbounded. When the cap is
# reached and no entry has expired, the broker DENIES (fail-closed) instead
# of evicting a live (not-yet-expired) nonce.
MAX_NONCE_LEDGER_ENTRIES = 100_000

# High-risk primitives requiring explicit HumanApprovalProof by default
HIGH_RISK_PRIMITIVES: Set[str] = {
    "process_execution",
    "destructive_storage",
    "arbitrary_network",
    "agent_spawn",
}


class AuthorityBroker:
    """
    Independent Authority Broker Service running behind a UNIX Domain Socket.
    Evaluates requests, enforces policy, validates provenance, and issues CapabilityGrants.
    """

    def __init__(
        self,
        socket_path: str,
        broker_secret: bytes,
        manifest_store: Optional[Dict[str, TaskManifest]] = None,
        allowed_uids: Optional[Set[int]] = None,
        allowed_gids: Optional[Set[int]] = None,
        max_nonce_ledger_entries: int = MAX_NONCE_LEDGER_ENTRIES,
        provenance_public_key: Optional[Any] = None,
        approval_public_key: Optional[Any] = None,
    ):
        self.socket_path = os.path.abspath(socket_path)
        # S1-PATCH P2: The broker is the SOLE holder of the Ed25519 private
        # (signing) key. The key is derived from broker_secret via SHA-256 so
        # the broker_secret itself is never used as a symmetric signing secret.
        # Agents / Domain Gates never receive the private key; they only ever
        # need the public key (see get_public_key()).
        signing_seed = hashlib.sha256(
            b"hermes-authority-broker-ed25519-v2|" + broker_secret
        ).digest()
        self._signing_key: ed25519.Ed25519PrivateKey = ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed)
        self._signing_public_key: ed25519.Ed25519PublicKey = self._signing_key.public_key()
        self.manifest_store: Dict[str, TaskManifest] = manifest_store or {}
        self.allowed_uids: Set[int] = allowed_uids if allowed_uids is not None else {os.getuid()}
        self.allowed_gids: Set[int] = allowed_gids if allowed_gids is not None else {os.getgid()}

        # S2: Ingress Provenance & CAS Human Approval Verifiers
        self.provenance_verifier: Optional[ProvenanceVerifier] = (
            ProvenanceVerifier(provenance_public_key) if provenance_public_key else None
        )
        self.approval_verifier: Optional[ApprovalTokenVerifier] = (
            ApprovalTokenVerifier(approval_public_key) if approval_public_key else None
        )

        self._lock = threading.Lock()
        # S1-PATCH P1: Time-based nonce ledger. Maps nonce -> expires_at (epoch
        # seconds). Only entries with now >= expires_at may be garbage-collected;
        # a not-yet-expired nonce is NEVER evicted regardless of ledger size.
        self._nonce_ledger: Dict[str, float] = {}
        self._max_nonce_ledger_entries = max(1, int(max_nonce_ledger_entries))

        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def get_public_key(self) -> bytes:
        """
        S1-PATCH P2: Expose ONLY the Ed25519 public key (raw 32 bytes).
        Future Domain Gates verify CapabilityGrant signatures with this key
        and never share the broker's signing secret.
        """
        return self._signing_public_key.public_bytes_raw()

    def register_manifest(self, manifest: TaskManifest) -> None:
        """Register a trusted TaskManifest into the broker's protected store"""
        with self._lock:
            self.manifest_store[manifest.manifest_id] = manifest

    def start(self) -> None:
        """Start the UDS listener in a dedicated background thread"""
        with self._lock:
            if self._running:
                return

            socket_dir = os.path.dirname(self.socket_path)
            if not os.path.exists(socket_dir):
                os.makedirs(socket_dir, mode=0o770, exist_ok=True)
            else:
                try:
                    os.chmod(socket_dir, 0o770)
                except OSError:
                    pass

            if os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError as e:
                    raise BrokerUnavailableError(f"Failed to remove stale socket: {e}")

            self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server_sock.bind(self.socket_path)
            
            # Enforce 0660 file permission on UDS socket
            try:
                os.chmod(self.socket_path, 0o660)
            except OSError as e:
                self._server_sock.close()
                raise BrokerUnavailableError(f"Failed to set 0660 on UDS socket: {e}")

            self._server_sock.listen(128)
            self._server_sock.settimeout(0.2)
            self._running = True

            self._thread = threading.Thread(target=self._serve_loop, daemon=True, name="AuthorityBrokerListener")
            self._thread.start()
            logger.info("Authority Broker listening on %s (permissions 0660)", self.socket_path)

    def stop(self) -> None:
        """Stop the UDS listener and clean up socket file"""
        with self._lock:
            if not self._running:
                return
            self._running = False
            sock = self._server_sock
            self._server_sock = None

        if sock:
            try:
                sock.close()
            except OSError:
                pass

        if self._thread and threading.current_thread() != self._thread:
            self._thread.join(timeout=1.0)

        with self._lock:
            if os.path.exists(self.socket_path):
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass

    def _serve_loop(self) -> None:
        """Main accept loop for incoming IPC client connections"""
        while self._running:
            try:
                if not self._server_sock:
                    break
                conn, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except (OSError, ValueError):
                break

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(conn,),
                daemon=True,
                name="AuthorityBrokerClientHandler",
            )
            client_thread.start()

    def _extract_peer_cred(self, conn: socket.socket) -> Tuple[int, int, int]:
        """
        Extract peer credentials (pid, uid, gid) using Linux SO_PEERCRED.
        """
        if hasattr(socket, "SO_PEERCRED"):
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", cred)
            return pid, uid, gid
        return -1, os.getuid(), os.getgid()

    def _handle_client(self, conn: socket.socket) -> None:
        """Handle individual client request with fail-closed safety"""
        try:
            conn.settimeout(3.0)
            pid, uid, gid = self._extract_peer_cred(conn)

            # V-01: Peer Authentication via SO_PEERCRED
            if uid not in self.allowed_uids and (gid not in self.allowed_gids):
                logger.warning("Denied unauthorized peer uid=%d gid=%d pid=%d", uid, gid, pid)
                self._send_error_and_close(conn, FailureCode.DENY_UNAUTHORIZED_PEER, "Peer UID/GID not authorized")
                return

            raw_data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                raw_data += chunk
                if b"\n" in chunk:
                    break

            if not raw_data:
                self._send_error_and_close(conn, FailureCode.DENY_UNKNOWN_STATE, "Empty request payload")
                return

            payload_str = raw_data.strip().decode("utf-8")
            req_dict = json.loads(payload_str)
            request = CapabilityRequest.from_dict(req_dict)

            grant = self.evaluate_request(request, subject_uid=uid)
            response_payload = {
                "status": "GRANTED",
                "grant": grant.to_dict(),
            }
            conn.sendall(json.dumps(response_payload).encode("utf-8") + b"\n")

        except CapabilityDeniedError as cde:
            self._send_error_and_close(conn, cde.code, cde.message)
        except json.JSONDecodeError:
            self._send_error_and_close(conn, FailureCode.DENY_UNKNOWN_STATE, "Malformed JSON request")
        except socket.timeout:
            self._send_error_and_close(conn, FailureCode.DENY_TIMEOUT, "Request processing timed out")
        except Exception as e:
            logger.exception("Unexpected error in broker client handler: %s", e)
            self._send_error_and_close(conn, FailureCode.DENY_UNKNOWN_STATE, f"Internal broker error: {type(e).__name__}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _send_error_and_close(self, conn: socket.socket, code: FailureCode, message: str) -> None:
        try:
            err_dict = {
                "status": "DENIED",
                "code": code.value,
                "message": message,
            }
            conn.sendall(json.dumps(err_dict).encode("utf-8") + b"\n")
        except OSError:
            pass

    def evaluate_request(self, request: CapabilityRequest, subject_uid: int) -> CapabilityGrant:
        """
        Full verification pipeline according to Implementation Contract R1:
        V-01: Peer Authenticated (passed from caller)
        V-02: Manifest Anchor verification
        V-03: Provenance Ingress & Anti-Self-Trust
        V-04: Capability Policy evaluation
        V-05: Human Approval Proof check
        V-06: Canonical Execution Semantics hashing
        V-07: Full TTL validation & clock check
        V-08: Atomic Nonce Check-and-Consume
        """
        now = time.time()

        # V-02: Manifest Integrity Anchor
        with self._lock:
            manifest = self.manifest_store.get(request.task_id)
        if not manifest:
            raise CapabilityDeniedError(
                FailureCode.DENY_INVALID_MANIFEST,
                f"TaskManifest for task_id '{request.task_id}' not found in trusted store",
            )

        if request.requested_primitive not in manifest.allowed_primitives:
            raise CapabilityDeniedError(
                FailureCode.DENY_POLICY_VIOLATION,
                f"Primitive '{request.requested_primitive}' not permitted by manifest '{manifest.manifest_id}'",
            )

        # V-03: Provenance Ingress & Anti-Self-Trust
        taint = request.provenance.taint_tag
        if self.provenance_verifier:
            if request.provenance.ingress_signature:
                if not self.provenance_verifier.verify_provenance(request.provenance):
                    raise CapabilityDeniedError(
                        FailureCode.DENY_SIGNATURE_TAMPERED,
                        "Ingress provenance signature is invalid, forged, or tampered",
                    )
            elif taint in ("HUMAN_CONFIRMED", "SYSTEM_INTERNAL"):
                taint = "EXTERNAL_UNTRUSTED"
        elif taint in ("HUMAN_CONFIRMED", "SYSTEM_INTERNAL"):
            if not request.provenance.ingress_signature:
                taint = "EXTERNAL_UNTRUSTED"

        # V-06: Broker-side Canonicalization & Exact Execution Hash
        canonical_semantics = FullExecutionSemantics(
            interpreter_path=request.untrusted_semantics.interpreter_path,
            interpreter_hash=request.untrusted_semantics.interpreter_hash,
            script_path=request.untrusted_semantics.script_path,
            script_hash=request.untrusted_semantics.script_hash,
            argv=request.untrusted_semantics.argv,
            cwd=request.untrusted_semantics.cwd,
            env_allowlist=request.untrusted_semantics.env_allowlist,
            sandbox_profile=request.untrusted_semantics.sandbox_profile,
            network_policy=request.untrusted_semantics.network_policy,
        )
        canonical_hash = canonical_semantics.compute_canonical_hash()

        # V-04 & V-05: Capability Policy & Human Approval Check
        is_high_risk = request.requested_primitive in HIGH_RISK_PRIMITIVES
        if is_high_risk or taint == "EXTERNAL_UNTRUSTED":
            if not request.human_approval:
                raise CapabilityDeniedError(
                    FailureCode.DENY_UNAUTHORIZED_GRANT,
                    f"Primitive '{request.requested_primitive}' with taint '{taint}' requires HumanApprovalProof",
                )

            proof = request.human_approval

            # V-05 Cryptographic Verification of Human Approval Proof
            if self.approval_verifier:
                if not self.approval_verifier.verify_approval(proof, expected_hash=canonical_hash, now=now):
                    if proof.valid_until < now:
                        raise CapabilityDeniedError(
                            FailureCode.DENY_TTL_EXPIRED,
                            f"Human approval token expired at {proof.valid_until} (current: {now})",
                        )
                    elif proof.exact_execution_hash != canonical_hash:
                        raise CapabilityDeniedError(
                            FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT,
                            f"Human approval hash '{proof.exact_execution_hash[:16]}...' does not match canonical hash '{canonical_hash[:16]}...'",
                        )
                    else:
                        raise CapabilityDeniedError(
                            FailureCode.DENY_SIGNATURE_TAMPERED,
                            "Human approval token signature is invalid, forged, or tampered",
                        )
            else:
                # Baseline validation when approval_verifier is not configured
                if proof.exact_execution_hash != canonical_hash:
                    raise CapabilityDeniedError(
                        FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT,
                        f"Human approval hash '{proof.exact_execution_hash[:16]}...' does not match canonical hash '{canonical_hash[:16]}...'",
                    )
                if proof.valid_until < now:
                    raise CapabilityDeniedError(
                        FailureCode.DENY_TTL_EXPIRED,
                        f"Human approval token expired at {proof.valid_until} (current: {now})",
                    )

            # V-08 Atomic Nonce Check-and-Consume for approval token
            # S1-PATCH P1: retention window = approval token's own valid_until
            self._atomic_consume_nonce(proof.token_nonce, expires_at=proof.valid_until)

        # V-07: Full TTL Semantics for newly issued Grant
        issued_at = now
        expires_at = issued_at + DEFAULT_GRANT_TTL_SECONDS
        if expires_at - issued_at > MAX_GRANT_TTL_SECONDS:
            raise CapabilityDeniedError(
                FailureCode.DENY_TTL_EXPIRED,
                f"Requested TTL exceeds maximum limit of {MAX_GRANT_TTL_SECONDS}s",
            )

        # Clock skew / backward check
        if issued_at > expires_at or issued_at < now - 1.0:
            raise CapabilityDeniedError(
                FailureCode.DENY_CLOCK_UNRELIABLE,
                "System clock error or time backward drift detected",
            )

        # Single-use nonce generation & atomic consume
        # S1-PATCH P1: retention window = the grant's own expiry
        grant_nonce = uuid.uuid4().hex
        self._atomic_consume_nonce(grant_nonce, expires_at=expires_at)

        # Issue CapabilityGrant
        grant_id = str(uuid.uuid4())
        attenuated_caps = (request.requested_primitive,)

        grant = CapabilityGrant(
            grant_id=grant_id,
            issued_at=issued_at,
            expires_at=expires_at,
            single_use_nonce=grant_nonce,
            subject_uid=subject_uid,
            target_primitive=request.requested_primitive,
            exact_execution_hash=canonical_hash,
            attenuated_capabilities=attenuated_caps,
            broker_signature="",
            task_id=request.task_id,
            resource_binding=tuple(manifest.allowed_resources),
        )

        # S1-PATCH P2: Broker signs the FULL grant security semantics
        # (grant identity, subject/task, capability, resource binding,
        # execution semantics hash, expiry, nonce) with its Ed25519 private key.
        # The signature is base64-encoded raw 64 bytes.
        sig_bytes = self._signing_key.sign(grant.compute_signature_payload())
        signed_grant = CapabilityGrant(
            grant_id=grant.grant_id,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use_nonce=grant.single_use_nonce,
            subject_uid=grant.subject_uid,
            target_primitive=grant.target_primitive,
            exact_execution_hash=grant.exact_execution_hash,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=base64.b64encode(sig_bytes).decode("ascii"),
            task_id=grant.task_id,
            resource_binding=grant.resource_binding,
        )

        return signed_grant

    def verify_grant(self, grant: CapabilityGrant, expected_uid: int, expected_hash: str) -> bool:
        """
        Verify the validity and integrity of a CapabilityGrant.
        Used by execution gates during subsequent slices.

        S1-PATCH P2: Signature verification uses the broker's Ed25519 public key.
        Any tampered field (including task_id / resource_binding) invalidates the
        signature and returns False (fail-closed).
        """
        now = time.time()
        # Full TTL check
        if not (grant.issued_at <= now < grant.expires_at):
            return False
        if grant.expires_at - grant.issued_at > MAX_GRANT_TTL_SECONDS:
            return False
        if grant.subject_uid != expected_uid:
            return False
        if grant.exact_execution_hash != expected_hash:
            return False

        # Verify Ed25519 signature over the full grant security semantics
        try:
            sig_bytes = base64.b64decode(grant.broker_signature)
            self._signing_public_key.verify(sig_bytes, grant.compute_signature_payload())
        except (InvalidSignature, ValueError, TypeError):
            return False

        return True

    def _atomic_consume_nonce(self, nonce: str, expires_at: Optional[float] = None) -> None:
        """
        S1-PATCH P1: Atomically check and consume a single-use nonce within mutex.
        Raises CapabilityDeniedError if nonce was already used (replay attack).

        Time-based GC semantics:
        - Only entries with now >= expires_at are garbage-collected.
        - A not-yet-expired nonce is NEVER evicted, regardless of ledger size.
        - The ledger is bounded by MAX_NONCE_LEDGER_ENTRIES as a fail-closed
          backstop: if the cap is reached and nothing has expired, the broker
          DENIES (DENY_NONCE_STORE_SATURATED) instead of evicting a live nonce.
        """
        if not nonce or not str(nonce).strip():
            raise CapabilityDeniedError(FailureCode.DENY_REPLAY_ATTACK, "Empty or whitespace-only nonce rejected")

        now = time.time()
        if expires_at is None:
            expires_at = now + NONCE_RETENTION_SECONDS

        with self._lock:
            if nonce in self._nonce_ledger:
                raise CapabilityDeniedError(
                    FailureCode.DENY_REPLAY_ATTACK,
                    f"Nonce '{nonce}' was already consumed (Replay Attack detected)",
                )

            # Time-based GC: remove only expired entries (now >= expires_at).
            expired = [n for n, exp in self._nonce_ledger.items() if now >= exp]
            for n in expired:
                del self._nonce_ledger[n]

            # Fail-closed backstop: bounded memory, never evict a live nonce.
            if len(self._nonce_ledger) >= self._max_nonce_ledger_entries:
                raise CapabilityDeniedError(
                    FailureCode.DENY_NONCE_STORE_SATURATED,
                    "Nonce ledger saturated with live (not-yet-expired) entries; "
                    "failing closed to protect replay protection",
                )

            self._nonce_ledger[nonce] = expires_at
