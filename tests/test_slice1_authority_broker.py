#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_slice1_authority_broker.py — Verification Suite for Slice 1: Authority Broker & IPC Backbone
Strictly implemented with standard library unittest for fast, deterministic, fail-closed execution.
Includes S1-PATCH verification:
- Nonce time-based GC & atomic replay protection (N-01 ~ N-06)
- Ed25519 asymmetric signature & zero-key custody (E-01 ~ E-08)
"""

import os
import stat
import time
import uuid
import base64
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from hermes_core.authority.models import (
    ProvenanceContext,
    TaskManifest,
    FullExecutionSemantics,
    CapabilityRequest,
    HumanApprovalProof,
    CapabilityGrant,
    FailureCode,
    BrokerUnavailableError,
    CapabilityDeniedError,
)
from hermes_core.authority.broker import (
    AuthorityBroker,
    MAX_GRANT_TTL_SECONDS,
    NONCE_RETENTION_SECONDS,
)
from hermes_core.authority.client import AgentAuthorityClient


class TestSlice1AuthorityBroker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="hermes_broker_test_")
        self.sock_path = os.path.join(self.temp_dir, "broker.sock")
        self.secret = b"test_secret_authority_broker_key_32b!"

        self.manifest = TaskManifest(
            manifest_id="task_calc_pi",
            allowed_primitives=("process_execution", "read_storage"),
            allowed_resources=("/tmp",),
            signature="manifest_sig_valid",
        )

        self.broker = AuthorityBroker(
            socket_path=self.sock_path,
            broker_secret=self.secret,
            manifest_store={"task_calc_pi": self.manifest},
        )
        self.broker.start()
        self.client = AgentAuthorityClient(socket_path=self.sock_path)

    def tearDown(self):
        self.broker.stop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────────
    # Existing Baseline Tests (test_01 ~ test_08)
    # ──────────────────────────────────────────────────────────────────────────

    def test_01_uds_socket_permissions_and_lifecycle(self):
        """Test that UDS socket has strict 0660 permissions and parent dir has 0770"""
        self.assertTrue(os.path.exists(self.sock_path))
        sock_mode = stat.S_IMODE(os.stat(self.sock_path).st_mode)
        self.assertEqual(sock_mode & 0o007, 0, f"Other permissions must be 0, got {oct(sock_mode)}")
        self.assertEqual(sock_mode & 0o660, 0o660, f"Owner/group must have rw permissions, got {oct(sock_mode)}")

        parent_dir = os.path.dirname(self.sock_path)
        dir_mode = stat.S_IMODE(os.stat(parent_dir).st_mode)
        self.assertEqual(dir_mode & 0o007, 0, f"Directory other permissions must be 0, got {oct(dir_mode)}")

    def test_02_manifest_integrity_anchor(self):
        """Test that requests with unapproved task_id or primitive are rejected (Fail-Closed)"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="hash_py3",
            script_path="/tmp/script.py",
            script_hash="hash_script",
            argv=("--arg1",),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )

        req_unknown = CapabilityRequest(
            request_id="req_1",
            task_id="non_existent_task",
            requested_primitive="read_storage",
            provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="SYSTEM_INTERNAL", ingress_signature="sig"),
            untrusted_semantics=semantics,
        )
        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req_unknown)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_INVALID_MANIFEST)

        req_bad_prim = CapabilityRequest(
            request_id="req_2",
            task_id="task_calc_pi",
            requested_primitive="unregistered_dangerous_primitive",
            provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="SYSTEM_INTERNAL", ingress_signature="sig"),
            untrusted_semantics=semantics,
        )
        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req_bad_prim)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_POLICY_VIOLATION)

    def test_03_anti_self_trust_agent_claimed_human_denial(self):
        """Test that Agent claiming HUMAN_CONFIRMED without valid ingress signature is demoted and blocked"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="hash_py3",
            script_path="/tmp/script.py",
            script_hash="hash_script",
            argv=(),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )

        req = CapabilityRequest(
            request_id="req_self_trust",
            task_id="task_calc_pi",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(
                caller_id="agent_self",
                origin_source="chat",
                taint_tag="HUMAN_CONFIRMED",
                ingress_signature="",
            ),
            untrusted_semantics=semantics,
            human_approval=None,
        )

        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_UNAUTHORIZED_GRANT)

    def test_04_execution_semantics_drift_detection(self):
        """Test that if HumanApprovalProof hash does not match broker canonical hash, it is denied"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="hash_py3",
            script_path="/tmp/script.py",
            script_hash="hash_script",
            argv=("-v",),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )

        tampered_approval = HumanApprovalProof(
            token_id="tok_1",
            approver_id="chang",
            approver_sig="sig_chang",
            issued_at=time.time(),
            valid_until=time.time() + 60,
            token_nonce="nonce_123",
            exact_execution_hash="0000000000000000000000000000000000000000000000000000000000000000",
        )

        req = CapabilityRequest(
            request_id="req_drift",
            task_id="task_calc_pi",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(caller_id="agent", origin_source="chat", taint_tag="EXTERNAL_UNTRUSTED"),
            untrusted_semantics=semantics,
            human_approval=tampered_approval,
        )

        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_05_successful_grant_issuance_and_verification(self):
        """Test end-to-end happy path: valid manifest, matching approval -> CapabilityGrant issued and verified"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="hash_py3",
            script_path="/tmp/script.py",
            script_hash="hash_script",
            argv=("--batch", "100"),
            cwd="/tmp",
            env_allowlist=(("APP_ENV", "prod"),),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        valid_approval = HumanApprovalProof(
            token_id="tok_ok",
            approver_id="chang",
            approver_sig="sig_ok",
            issued_at=time.time() - 5,
            valid_until=time.time() + 60,
            token_nonce="nonce_unique_1",
            exact_execution_hash=canonical_hash,
        )

        req = CapabilityRequest(
            request_id="req_ok",
            task_id="task_calc_pi",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(caller_id="agent", origin_source="chat", taint_tag="EXTERNAL_UNTRUSTED"),
            untrusted_semantics=semantics,
            human_approval=valid_approval,
        )

        grant = self.client.request_capability(req)
        self.assertIsInstance(grant, CapabilityGrant)
        self.assertEqual(grant.target_primitive, "process_execution")
        self.assertEqual(grant.exact_execution_hash, canonical_hash)
        self.assertEqual(grant.subject_uid, os.getuid())
        self.assertLessEqual(grant.expires_at - grant.issued_at, MAX_GRANT_TTL_SECONDS)

        is_valid = self.broker.verify_grant(grant, expected_uid=os.getuid(), expected_hash=canonical_hash)
        self.assertTrue(is_valid)

        self.assertFalse(self.broker.verify_grant(grant, expected_uid=os.getuid(), expected_hash="tampered_hash"))

    def test_06_concurrent_atomic_nonce_check_and_consume(self):
        """
        Test that submitting the exact same Nonce concurrently results in:
        Exactly 1 success and N-1 failures with DENY_REPLAY_ATTACK (Atomic Check-and-Consume).
        """
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/s.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        shared_nonce = f"shared_replay_nonce_{uuid.uuid4().hex}"
        num_threads = 10

        def submit_request(thread_id: int):
            thread_client = AgentAuthorityClient(socket_path=self.sock_path)
            approval = HumanApprovalProof(
                token_id=f"tok_{thread_id}",
                approver_id="chang",
                approver_sig="sig",
                issued_at=time.time(),
                valid_until=time.time() + 60,
                token_nonce=shared_nonce,
                exact_execution_hash=canonical_hash,
            )
            req = CapabilityRequest(
                request_id=f"req_thread_{thread_id}",
                task_id="task_calc_pi",
                requested_primitive="process_execution",
                provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="EXTERNAL_UNTRUSTED"),
                untrusted_semantics=semantics,
                human_approval=approval,
            )
            try:
                grant = thread_client.request_capability(req)
                return ("SUCCESS", grant)
            except CapabilityDeniedError as e:
                return ("DENIED", e.code)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(submit_request, i) for i in range(num_threads)]
            results = [f.result() for f in futures]

        successes = [r for r in results if r[0] == "SUCCESS"]
        denied_replays = [r for r in results if r[0] == "DENIED" and r[1] == FailureCode.DENY_REPLAY_ATTACK]

        self.assertEqual(len(successes), 1, f"Expected exactly 1 atomic success, got {len(successes)}")
        self.assertEqual(len(denied_replays), num_threads - 1, f"Expected {num_threads - 1} replay denials, got {len(denied_replays)}")

    def test_07_ttl_expiration_rejection(self):
        """Test that expired approval tokens are rejected with DENY_TTL_EXPIRED"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/s.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        expired_approval = HumanApprovalProof(
            token_id="tok_exp",
            approver_id="chang",
            approver_sig="sig",
            issued_at=time.time() - 100,
            valid_until=time.time() - 10,
            token_nonce="nonce_expired",
            exact_execution_hash=canonical_hash,
        )

        req = CapabilityRequest(
            request_id="req_exp",
            task_id="task_calc_pi",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="EXTERNAL_UNTRUSTED"),
            untrusted_semantics=semantics,
            human_approval=expired_approval,
        )

        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_TTL_EXPIRED)

    def test_08_fail_closed_on_broker_offline(self):
        """Test that client strictly fails closed (raises BrokerUnavailableError) when broker is dead"""
        non_existent_sock = f"/tmp/hermes_dead_broker_{uuid.uuid4().hex}.sock"
        client = AgentAuthorityClient(socket_path=non_existent_sock, timeout=0.5)

        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/s.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )

        req = CapabilityRequest(
            request_id="req_offline",
            task_id="task_calc_pi",
            requested_primitive="read_storage",
            provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="SYSTEM_INTERNAL", ingress_signature="sig"),
            untrusted_semantics=semantics,
        )

        with self.assertRaises(BrokerUnavailableError):
            client.request_capability(req)

    # ──────────────────────────────────────────────────────────────────────────
    # S1-PATCH P1 Tests: Nonce Time-based GC & Replay Defense (N-01 ~ N-06)
    # ──────────────────────────────────────────────────────────────────────────

    def test_N01_time_based_gc_unexpired_nonce_not_evicted(self):
        """N-01: A live, not-yet-expired nonce is NEVER evicted regardless of insertion volume"""
        target_nonce = "live_nonce_must_survive"
        # Consume target_nonce with 60s future expiry
        future_exp = time.time() + 60.0
        self.broker._atomic_consume_nonce(target_nonce, expires_at=future_exp)

        # Inject 1500 other nonces; none should evict target_nonce because target is not expired
        for i in range(1500):
            other_nonce = f"flood_nonce_{i}"
            self.broker._atomic_consume_nonce(other_nonce, expires_at=future_exp)

        # Replaying target_nonce must STILL be blocked with DENY_REPLAY_ATTACK
        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.broker._atomic_consume_nonce(target_nonce, expires_at=future_exp)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_REPLAY_ATTACK)

    def test_N02_expired_nonce_purged_by_gc(self):
        """N-02: Nonces with now >= expires_at are purged during time-based GC and do not leak memory"""
        now = time.time()
        # Seed 10 expired nonces (expired in the past)
        with self.broker._lock:
            for i in range(10):
                self.broker._nonce_ledger[f"past_nonce_{i}"] = now - 10.0

        # Ledger now has past nonces
        self.assertTrue(any(k.startswith("past_nonce_") for k in self.broker._nonce_ledger))

        # Atomic consume of a new nonce triggers time-based GC
        self.broker._atomic_consume_nonce("fresh_nonce_trigger", expires_at=now + 30.0)

        # All 10 past nonces must be cleanly garbage-collected
        with self.broker._lock:
            for i in range(10):
                self.assertNotIn(f"past_nonce_{i}", self.broker._nonce_ledger)

    def test_N03_atomic_check_and_consume_under_high_concurrency(self):
        """N-03: High concurrency race test (20 workers racing exact same nonce)"""
        shared_nonce = f"race_nonce_{uuid.uuid4().hex}"
        num_workers = 20
        results = []

        def worker_attempt():
            try:
                self.broker._atomic_consume_nonce(shared_nonce, expires_at=time.time() + 60.0)
                return "SUCCESS"
            except CapabilityDeniedError as e:
                return e.code

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_attempt) for _ in range(num_workers)]
            results = [f.result() for f in futures]

        success_count = sum(1 for r in results if r == "SUCCESS")
        replay_count = sum(1 for r in results if r == FailureCode.DENY_REPLAY_ATTACK)

        self.assertEqual(success_count, 1, "Exactly one thread must win the atomic nonce race")
        self.assertEqual(replay_count, num_workers - 1, "All other concurrent callers must be DENY_REPLAY_ATTACK")

    def test_N04_nonce_ttl_boundary_exact_match(self):
        """N-04: Nonce remains actively protected until strictly now >= expires_at"""
        target_nonce = "boundary_nonce_test"
        now = time.time()
        expiry = now + 0.3  # Expires in 300ms

        self.broker._atomic_consume_nonce(target_nonce, expires_at=expiry)

        # Before expiry: replay is strictly denied
        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.broker._atomic_consume_nonce(target_nonce, expires_at=expiry)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_REPLAY_ATTACK)

        # Wait until strictly past expiry
        time.sleep(0.35)

        # After expiry: can be consumed or purged without false positive deadlock
        fresh_nonce = "boundary_nonce_post_expiry"
        self.broker._atomic_consume_nonce(fresh_nonce, expires_at=time.time() + 30.0)
        with self.broker._lock:
            self.assertNotIn(target_nonce, self.broker._nonce_ledger)

    def test_N05_bounded_memory_saturation_fail_closed(self):
        """N-05: When ledger reaches capacity with unexpired live entries, broker fails closed"""
        # Create broker with small capacity (cap=5)
        small_broker = AuthorityBroker(
            socket_path=os.path.join(self.temp_dir, "small_broker.sock"),
            broker_secret=self.secret,
            max_nonce_ledger_entries=5,
        )
        now = time.time()
        future_exp = now + 100.0

        # Fill with 5 live entries
        for i in range(5):
            small_broker._atomic_consume_nonce(f"live_slot_{i}", expires_at=future_exp)

        # Attempting to add a 6th live entry must FAIL-CLOSED (not evict a live entry)
        with self.assertRaises(CapabilityDeniedError) as ctx:
            small_broker._atomic_consume_nonce("overflow_nonce", expires_at=future_exp)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_NONCE_STORE_SATURATED)

        # Verify all 5 original entries were NEVER evicted
        with small_broker._lock:
            for i in range(5):
                self.assertIn(f"live_slot_{i}", small_broker._nonce_ledger)

    def test_N06_empty_or_malformed_nonce_rejected(self):
        """N-06: Empty, whitespace-only, or None nonces are rejected immediately"""
        for invalid_nonce in ("", "   ", None):
            with self.assertRaises(CapabilityDeniedError) as ctx:
                self.broker._atomic_consume_nonce(invalid_nonce)
            self.assertEqual(ctx.exception.code, FailureCode.DENY_REPLAY_ATTACK)

    # ──────────────────────────────────────────────────────────────────────────
    # S1-PATCH P2 Tests: Ed25519 Asymmetric Signature & Custody (E-01 ~ E-08)
    # ──────────────────────────────────────────────────────────────────────────

    def test_E01_broker_holds_private_key_client_has_none(self):
        """E-01: Broker holds Ed25519 private key; Agent Client holds 0 private keys and 0 secrets"""
        # Broker has signing key
        self.assertIsInstance(self.broker._signing_key, ed25519.Ed25519PrivateKey)
        self.assertIsInstance(self.broker._signing_public_key, ed25519.Ed25519PublicKey)

        # Client has no private key, no secret, only socket path
        self.assertFalse(hasattr(self.client, "_signing_key"))
        self.assertFalse(hasattr(self.client, "broker_secret"))
        self.assertFalse(hasattr(self.client, "private_key"))
        self.assertTrue(hasattr(self.client, "socket_path"))

    def test_E02_public_key_verification_by_third_party(self):
        """E-02: Third-party Domain Gate can verify grant using ONLY Broker's Ed25519 public key"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h_py",
            script_path="/tmp/s.py",
            script_hash="h_sc",
            argv=("--dry-run",),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        approval = HumanApprovalProof(
            token_id="tok_e02",
            approver_id="chang",
            approver_sig="sig",
            issued_at=time.time() - 1,
            valid_until=time.time() + 60,
            token_nonce="nonce_e02",
            exact_execution_hash=canonical_hash,
        )
        req = CapabilityRequest(
            request_id="req_e02",
            task_id="task_calc_pi",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="EXTERNAL_UNTRUSTED"),
            untrusted_semantics=semantics,
            human_approval=approval,
        )

        grant = self.client.request_capability(req)

        # Independent Gate obtains ONLY public key bytes (32 bytes raw)
        pubkey_bytes = self.broker.get_public_key()
        self.assertEqual(len(pubkey_bytes), 32)
        gate_public_key = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)

        # Gate independently verifies signature without holding broker's private key
        sig_bytes = base64.b64decode(grant.broker_signature)
        gate_public_key.verify(sig_bytes, grant.compute_signature_payload())

    def test_E03_tamper_grant_id_fails_signature(self):
        """E-03: Tampering with grant_id invalidates Ed25519 signature"""
        grant = self._issue_sample_grant("tok_e03", "nonce_e03")
        tampered_grant = CapabilityGrant(
            grant_id="tampered_grant_id_hacked",
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use_nonce=grant.single_use_nonce,
            subject_uid=grant.subject_uid,
            target_primitive=grant.target_primitive,
            exact_execution_hash=grant.exact_execution_hash,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=grant.broker_signature,
            task_id=grant.task_id,
            resource_binding=grant.resource_binding,
        )
        self.assertFalse(self.broker.verify_grant(tampered_grant, grant.subject_uid, grant.exact_execution_hash))

    def test_E04_tamper_subject_uid_fails_signature(self):
        """E-04: Tampering with subject_uid (privilege escalation) invalidates verification"""
        grant = self._issue_sample_grant("tok_e04", "nonce_e04")
        tampered_grant = CapabilityGrant(
            grant_id=grant.grant_id,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use_nonce=grant.single_use_nonce,
            subject_uid=0,  # Escalated to root (UID 0)
            target_primitive=grant.target_primitive,
            exact_execution_hash=grant.exact_execution_hash,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=grant.broker_signature,
            task_id=grant.task_id,
            resource_binding=grant.resource_binding,
        )
        self.assertFalse(self.broker.verify_grant(tampered_grant, 0, grant.exact_execution_hash))

    def test_E05_tamper_execution_hash_fails_signature(self):
        """E-05: Tampering with exact_execution_hash invalidates signature"""
        grant = self._issue_sample_grant("tok_e05", "nonce_e05")
        tampered_grant = CapabilityGrant(
            grant_id=grant.grant_id,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use_nonce=grant.single_use_nonce,
            subject_uid=grant.subject_uid,
            target_primitive=grant.target_primitive,
            exact_execution_hash="bad_hash" * 8,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=grant.broker_signature,
            task_id=grant.task_id,
            resource_binding=grant.resource_binding,
        )
        self.assertFalse(self.broker.verify_grant(tampered_grant, grant.subject_uid, "bad_hash" * 8))

    def test_E06_tamper_target_primitive_fails_signature(self):
        """E-06: Tampering with target_primitive invalidates signature"""
        grant = self._issue_sample_grant("tok_e06", "nonce_e06")
        tampered_grant = CapabilityGrant(
            grant_id=grant.grant_id,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use_nonce=grant.single_use_nonce,
            subject_uid=grant.subject_uid,
            target_primitive="destructive_storage",  # Swapped primitive
            exact_execution_hash=grant.exact_execution_hash,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=grant.broker_signature,
            task_id=grant.task_id,
            resource_binding=grant.resource_binding,
        )
        self.assertFalse(self.broker.verify_grant(tampered_grant, grant.subject_uid, grant.exact_execution_hash))

    def test_E07_tamper_expiry_time_fails_signature(self):
        """E-07: Tampering with expires_at (extending TTL) invalidates signature"""
        grant = self._issue_sample_grant("tok_e07", "nonce_e07")
        tampered_grant = CapabilityGrant(
            grant_id=grant.grant_id,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at + 3600.0,  # Extended by 1 hour
            single_use_nonce=grant.single_use_nonce,
            subject_uid=grant.subject_uid,
            target_primitive=grant.target_primitive,
            exact_execution_hash=grant.exact_execution_hash,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=grant.broker_signature,
            task_id=grant.task_id,
            resource_binding=grant.resource_binding,
        )
        self.assertFalse(self.broker.verify_grant(tampered_grant, grant.subject_uid, grant.exact_execution_hash))

    def test_E08_tamper_resource_binding_or_task_id_fails_signature(self):
        """E-08: Tampering with resource_binding or task_id invalidates signature"""
        grant = self._issue_sample_grant("tok_e08", "nonce_e08")
        tampered_grant = CapabilityGrant(
            grant_id=grant.grant_id,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            single_use_nonce=grant.single_use_nonce,
            subject_uid=grant.subject_uid,
            target_primitive=grant.target_primitive,
            exact_execution_hash=grant.exact_execution_hash,
            attenuated_capabilities=grant.attenuated_capabilities,
            broker_signature=grant.broker_signature,
            task_id="unauthorized_task_swap",
            resource_binding=("/etc/shadow",),  # Swapped resource scope
        )
        self.assertFalse(self.broker.verify_grant(tampered_grant, grant.subject_uid, grant.exact_execution_hash))

    def _issue_sample_grant(self, token_id: str, nonce: str) -> CapabilityGrant:
        """Helper to obtain a signed grant for testing tamper resistance"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/s.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()
        approval = HumanApprovalProof(
            token_id=token_id,
            approver_id="chang",
            approver_sig="sig",
            issued_at=time.time() - 1,
            valid_until=time.time() + 60,
            token_nonce=nonce,
            exact_execution_hash=canonical_hash,
        )
        req = CapabilityRequest(
            request_id=f"req_{token_id}",
            task_id="task_calc_pi",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(caller_id="agent", origin_source="test", taint_tag="EXTERNAL_UNTRUSTED"),
            untrusted_semantics=semantics,
            human_approval=approval,
        )
        return self.client.request_capability(req)


if __name__ == "__main__":
    unittest.main()
