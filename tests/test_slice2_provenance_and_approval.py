#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_slice2_provenance_and_approval.py — Verification Suite for Slice 2:
Ingress Provenance & CAS Human Approval Engine.
"""

import os
import time
import uuid
import shutil
import tempfile
import unittest

from hermes_core.authority.models import (
    ProvenanceContext,
    TaskManifest,
    FullExecutionSemantics,
    CapabilityRequest,
    HumanApprovalProof,
    CapabilityGrant,
    FailureCode,
    CapabilityDeniedError,
)
from hermes_core.authority.broker import AuthorityBroker
from hermes_core.authority.client import AgentAuthorityClient
from hermes_core.provenance.signer import IngressProvenanceSigner, ProvenanceVerifier
from hermes_core.approval.service import (
    HumanApprovalService,
    ApprovalTokenVerifier,
    MAX_APPROVAL_TTL_SECONDS,
)


class TestSlice2ProvenanceAndApproval(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="hermes_s2_test_")
        self.sock_path = os.path.join(self.temp_dir, "broker_s2.sock")
        self.broker_secret = b"test_broker_ed25519_secret_32bytes!"

        # Create Ingress Provenance Signer & Verifier
        self.ingress_signer = IngressProvenanceSigner()
        self.provenance_pubkey = self.ingress_signer.get_public_key()
        self.provenance_verifier = ProvenanceVerifier(self.provenance_pubkey)

        # Create CAS Human Approval Service & Verifier
        self.approval_service = HumanApprovalService()
        self.approval_pubkey = self.approval_service.get_public_key()
        self.approval_verifier = ApprovalTokenVerifier(self.approval_pubkey)

        # Standard Manifest
        self.manifest = TaskManifest(
            manifest_id="task_hmi_diagnostics",
            allowed_primitives=("process_execution", "read_storage"),
            allowed_resources=("/tmp/hmi",),
            signature="sig_manifest_s2",
        )

        # Initialize Broker with verifier public keys
        self.broker = AuthorityBroker(
            socket_path=self.sock_path,
            broker_secret=self.broker_secret,
            manifest_store={"task_hmi_diagnostics": self.manifest},
            provenance_public_key=self.provenance_pubkey,
            approval_public_key=self.approval_pubkey,
        )
        self.broker.start()
        self.client = AgentAuthorityClient(socket_path=self.sock_path)

    def tearDown(self):
        self.broker.stop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ──────────────────────────────────────────────────────────────────────────
    # Component 1: Ingress Provenance Unit Tests (P-01 ~ P-05)
    # ──────────────────────────────────────────────────────────────────────────

    def test_P01_ingress_provenance_signing_and_verification(self):
        """P-01: Ingress gateway signs provenance; verifier confirms authentic signature"""
        prov = self.ingress_signer.sign_provenance(
            caller_id="synology_user_chang",
            origin_source="synology_chat",
            taint_tag="EXTERNAL_UNTRUSTED",
        )
        self.assertTrue(prov.ingress_signature)
        self.assertTrue(self.provenance_verifier.verify_provenance(prov))

    def test_P02_tampered_caller_id_fails_provenance(self):
        """P-02: Tampering with caller_id invalidates ingress signature"""
        prov = self.ingress_signer.sign_provenance(
            caller_id="user_alice",
            origin_source="cli",
            taint_tag="EXTERNAL_UNTRUSTED",
        )
        tampered_prov = ProvenanceContext(
            caller_id="user_root_impersonator",
            origin_source=prov.origin_source,
            taint_tag=prov.taint_tag,
            ingress_signature=prov.ingress_signature,
        )
        self.assertFalse(self.provenance_verifier.verify_provenance(tampered_prov))

    def test_P03_tampered_origin_source_fails_provenance(self):
        """P-03: Tampering with origin_source invalidates ingress signature"""
        prov = self.ingress_signer.sign_provenance(
            caller_id="system_daemon",
            origin_source="synology_chat",
            taint_tag="EXTERNAL_UNTRUSTED",
        )
        tampered_prov = ProvenanceContext(
            caller_id=prov.caller_id,
            origin_source="system_internal_cron",  # Spoofed origin
            taint_tag=prov.taint_tag,
            ingress_signature=prov.ingress_signature,
        )
        self.assertFalse(self.provenance_verifier.verify_provenance(tampered_prov))

    def test_P04_tampered_taint_tag_fails_provenance(self):
        """P-04: Tampering with taint_tag (self-elevation) invalidates ingress signature"""
        prov = self.ingress_signer.sign_provenance(
            caller_id="external_webhook",
            origin_source="webhook",
            taint_tag="EXTERNAL_UNTRUSTED",
        )
        tampered_prov = ProvenanceContext(
            caller_id=prov.caller_id,
            origin_source=prov.origin_source,
            taint_tag="INTERNAL_TRUSTED",  # Maliciously elevated taint
            ingress_signature=prov.ingress_signature,
        )
        self.assertFalse(self.provenance_verifier.verify_provenance(tampered_prov))

    def test_P05_agent_unverified_human_claim_gets_demoted(self):
        """P-05: Agent submitting unsigned claim of HUMAN_CONFIRMED is demoted to EXTERNAL_UNTRUSTED"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/hmi/script.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp/hmi",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        # Agent creates request with unsigned claim of HUMAN_CONFIRMED
        req = CapabilityRequest(
            request_id="req_self_elevate",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(
                caller_id="agent_self",
                origin_source="chat",
                taint_tag="HUMAN_CONFIRMED",
                ingress_signature="",  # Unsigned!
            ),
            untrusted_semantics=semantics,
            human_approval=None,
        )
        # High-risk primitive with demoted EXTERNAL_UNTRUSTED requires human approval proof
        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_UNAUTHORIZED_GRANT)

    # ──────────────────────────────────────────────────────────────────────────
    # Component 2: CAS Human Approval Unit Tests (A-01 ~ A-07)
    # ──────────────────────────────────────────────────────────────────────────

    def test_A01_human_approval_issuance_and_verification(self):
        """A-01: CAS service issues approval proof; verifier confirms valid signature"""
        target_hash = "deadbeef" * 8
        proof = self.approval_service.issue_approval(
            approver_id="chang",
            exact_execution_hash=target_hash,
            ttl_seconds=60.0,
        )
        self.assertEqual(proof.approver_id, "chang")
        self.assertEqual(proof.exact_execution_hash, target_hash)
        self.assertTrue(proof.approver_sig)
        self.assertTrue(self.approval_verifier.verify_approval(proof, expected_hash=target_hash))

    def test_A02_tampered_approver_id_fails_approval(self):
        """A-02: Tampering with approver_id invalidates approval signature"""
        target_hash = "cafebabe" * 8
        proof = self.approval_service.issue_approval("chang", target_hash)
        tampered_proof = HumanApprovalProof(
            token_id=proof.token_id,
            approver_id="fake_approver",
            approver_sig=proof.approver_sig,
            issued_at=proof.issued_at,
            valid_until=proof.valid_until,
            token_nonce=proof.token_nonce,
            exact_execution_hash=proof.exact_execution_hash,
        )
        self.assertFalse(self.approval_verifier.verify_approval(tampered_proof, expected_hash=target_hash))

    def test_A03_tampered_execution_hash_fails_approval(self):
        """A-03: Tampering with exact_execution_hash invalidates signature or expected_hash check"""
        target_hash = "11112222" * 8
        proof = self.approval_service.issue_approval("chang", target_hash)
        tampered_proof = HumanApprovalProof(
            token_id=proof.token_id,
            approver_id=proof.approver_id,
            approver_sig=proof.approver_sig,
            issued_at=proof.issued_at,
            valid_until=proof.valid_until,
            token_nonce=proof.token_nonce,
            exact_execution_hash="33334444" * 8,  # Altered hash
        )
        self.assertFalse(self.approval_verifier.verify_approval(tampered_proof, expected_hash=target_hash))

    def test_A04_tampered_nonce_fails_approval(self):
        """A-04: Tampering with token_nonce invalidates approval signature"""
        target_hash = "55556666" * 8
        proof = self.approval_service.issue_approval("chang", target_hash)
        tampered_proof = HumanApprovalProof(
            token_id=proof.token_id,
            approver_id=proof.approver_id,
            approver_sig=proof.approver_sig,
            issued_at=proof.issued_at,
            valid_until=proof.valid_until,
            token_nonce="altered_nonce_hacked",
            exact_execution_hash=proof.exact_execution_hash,
        )
        self.assertFalse(self.approval_verifier.verify_approval(tampered_proof, expected_hash=target_hash))

    def test_A05_tampered_valid_until_fails_approval(self):
        """A-05: Tampering with valid_until (extending token lifetime) invalidates signature"""
        target_hash = "77778888" * 8
        proof = self.approval_service.issue_approval("chang", target_hash)
        tampered_proof = HumanApprovalProof(
            token_id=proof.token_id,
            approver_id=proof.approver_id,
            approver_sig=proof.approver_sig,
            issued_at=proof.issued_at,
            valid_until=proof.valid_until + 3600.0,
            token_nonce=proof.token_nonce,
            exact_execution_hash=proof.exact_execution_hash,
        )
        self.assertFalse(self.approval_verifier.verify_approval(tampered_proof, expected_hash=target_hash))

    def test_A06_expired_approval_rejected(self):
        """A-06: Approval token past valid_until fails verification"""
        target_hash = "99990000" * 8
        now = time.time()
        proof = self.approval_service.issue_approval("chang", target_hash, ttl_seconds=10.0, now=now - 20.0)
        # Evaluated at current time (token is 10 seconds expired)
        self.assertFalse(self.approval_verifier.verify_approval(proof, expected_hash=target_hash, now=now))

    def test_A07_approval_ttl_clamped_to_max(self):
        """A-07: Requested approval TTL exceeding 120s is clamped to MAX_APPROVAL_TTL_SECONDS"""
        target_hash = "aaaaabbb" * 8
        now = time.time()
        proof = self.approval_service.issue_approval("chang", target_hash, ttl_seconds=99999.0, now=now)
        self.assertLessEqual(proof.valid_until - proof.issued_at, MAX_APPROVAL_TTL_SECONDS)

    # ──────────────────────────────────────────────────────────────────────────
    # Component 3: End-to-End Broker Integration Tests (B-01 ~ B-05)
    # ──────────────────────────────────────────────────────────────────────────

    def test_B01_broker_accepts_valid_ingress_and_valid_approval(self):
        """B-01: End-to-end happy path: signed Ingress + CAS approval -> CapabilityGrant issued"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="py3_h",
            script_path="/tmp/hmi/diag.py",
            script_hash="diag_h",
            argv=("--scan",),
            cwd="/tmp/hmi",
            env_allowlist=(("SCAN_LEVEL", "full"),),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        # Step 1: Ingress Gateway signs incoming request
        prov = self.ingress_signer.sign_provenance(
            caller_id="chang",
            origin_source="synology_chat",
            taint_tag="EXTERNAL_UNTRUSTED",
        )

        # Step 2: CAS Human Approval Service issues signed token bound to canonical hash
        approval = self.approval_service.issue_approval(
            approver_id="chang",
            exact_execution_hash=canonical_hash,
            ttl_seconds=60.0,
        )

        # Step 3: Agent constructs request and calls Broker
        req = CapabilityRequest(
            request_id="req_b01",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=prov,
            untrusted_semantics=semantics,
            human_approval=approval,
        )

        grant = self.client.request_capability(req)
        self.assertIsInstance(grant, CapabilityGrant)
        self.assertEqual(grant.target_primitive, "process_execution")
        self.assertEqual(grant.exact_execution_hash, canonical_hash)

        # Verify issued grant with broker's public key
        self.assertTrue(self.broker.verify_grant(grant, os.getuid(), canonical_hash))

    def test_B02_broker_rejects_forged_ingress_signature(self):
        """B-02: Broker rejects request with forged or tampered ingress signature"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/hmi/diag.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp/hmi",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        approval = self.approval_service.issue_approval("chang", canonical_hash)

        forged_prov = ProvenanceContext(
            caller_id="attacker",
            origin_source="spoofed_source",
            taint_tag="INTERNAL_TRUSTED",
            ingress_signature="A" * 88,  # Bogus signature
        )

        req = CapabilityRequest(
            request_id="req_b02",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=forged_prov,
            untrusted_semantics=semantics,
            human_approval=approval,
        )

        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_SIGNATURE_TAMPERED)

    def test_B03_broker_rejects_forged_approval_signature(self):
        """B-03: Broker rejects request with forged CAS approval signature"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/hmi/diag.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp/hmi",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        prov = self.ingress_signer.sign_provenance("chang", "chat", "EXTERNAL_UNTRUSTED")

        # Approval has forged signature
        forged_approval = HumanApprovalProof(
            token_id="tok_forged",
            approver_id="chang",
            approver_sig="B" * 88,  # Bogus signature
            issued_at=time.time(),
            valid_until=time.time() + 60.0,
            token_nonce="nonce_forged",
            exact_execution_hash=canonical_hash,
        )

        req = CapabilityRequest(
            request_id="req_b03",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=prov,
            untrusted_semantics=semantics,
            human_approval=forged_approval,
        )

        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_SIGNATURE_TAMPERED)

    def test_B04_broker_rejects_approval_hash_drift(self):
        """B-04: Broker rejects request when approved execution hash differs from canonical semantics"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/hmi/diag.py",
            script_hash="h2",
            argv=("--param", "actual_exec"),
            cwd="/tmp/hmi",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        prov = self.ingress_signer.sign_provenance("chang", "chat", "EXTERNAL_UNTRUSTED")

        # CAS legitimately signed a DIFFERENT hash
        approval = self.approval_service.issue_approval("chang", exact_execution_hash="different_hash_" * 4)

        req = CapabilityRequest(
            request_id="req_b04",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=prov,
            untrusted_semantics=semantics,
            human_approval=approval,
        )

        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_B05_broker_atomic_nonce_replay_of_approval_token(self):
        """B-05: Replaying the exact same HumanApprovalProof token is atomically denied"""
        semantics = FullExecutionSemantics(
            interpreter_path="/usr/bin/python3",
            interpreter_hash="h1",
            script_path="/tmp/hmi/diag.py",
            script_hash="h2",
            argv=(),
            cwd="/tmp/hmi",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        canonical_hash = semantics.compute_canonical_hash()

        prov = self.ingress_signer.sign_provenance("chang", "chat", "EXTERNAL_UNTRUSTED")
        approval = self.approval_service.issue_approval("chang", canonical_hash)

        # First request succeeds
        req1 = CapabilityRequest(
            request_id="req_b05_1",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=prov,
            untrusted_semantics=semantics,
            human_approval=approval,
        )
        grant1 = self.client.request_capability(req1)
        self.assertIsInstance(grant1, CapabilityGrant)

        # Replaying identical approval proof (same token_nonce) MUST be denied
        req2 = CapabilityRequest(
            request_id="req_b05_2",
            task_id="task_hmi_diagnostics",
            requested_primitive="process_execution",
            provenance=prov,
            untrusted_semantics=semantics,
            human_approval=approval,
        )
        with self.assertRaises(CapabilityDeniedError) as ctx:
            self.client.request_capability(req2)
        self.assertEqual(ctx.exception.code, FailureCode.DENY_REPLAY_ATTACK)


if __name__ == "__main__":
    unittest.main()
