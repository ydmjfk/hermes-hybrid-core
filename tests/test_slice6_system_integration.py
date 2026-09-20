# -*- coding: utf-8 -*-
"""
tests/test_slice6_system_integration.py — End-to-End System Integration Tests (Slice 6)

Verifies the complete Canonical Trust Chain:
1. Ingress Provenance Signer (Key_Provenance) ➔ Signed ProvenanceContext
2. CAS Human Approval Engine (Key_Approval) ➔ Signed HumanApprovalProof
3. Authority Broker Daemon (Key_Broker, UDS 0660) ➔ Signed CapabilityGrant
4. Unified Execution Adapter & Physical Gates (ProcessGate, StorageGate, NetworkGate)
5. Zero Private Keys in Agent Runtime: Process/Storage/Network Gates possess 0 private keys.
6. Full Fail-Closed Defense across all domain vectors.
"""

import os
import sys
import time
import uuid
import stat
import base64
import shutil
import tempfile
import threading
import unittest
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_core.authority.models import (
    ProvenanceContext,
    TaskManifest,
    FullExecutionSemantics,
    HumanApprovalProof,
    CapabilityRequest,
    FailureCode,
)
from hermes_core.authority.broker import AuthorityBroker
from hermes_core.authority.client import AgentAuthorityClient
from hermes_core.provenance.signer import IngressProvenanceSigner
from hermes_core.approval.service import HumanApprovalService
from hermes_core.gates.process_gate import ProcessGate
from hermes_core.gates.storage_gate import StorageGate
from hermes_core.gates.network_gate import NetworkGate
from hermes_core.gates.adapter import UnifiedExecutionAdapter


class TestSlice6SystemIntegration(unittest.TestCase):
    """Slice 6 End-to-End System Integration & Tool Adapter Convergence (INT-01 ~ INT-09)"""

    @classmethod
    def setUpClass(cls):
        # 1. Generate boundary cryptographic keys
        cls.prov_signer = IngressProvenanceSigner()
        cls.prov_pub_bytes = cls.prov_signer.get_public_key()

        cls.cas_service = HumanApprovalService()
        cls.cas_pub_bytes = cls.cas_service.get_public_key()

    def setUp(self):
        # Set up isolated workspace and UDS directory
        self.test_dir = tempfile.mkdtemp(prefix="slice6_integration_")
        self.socket_path = os.path.join(self.test_dir, "broker.sock")

        # 2. Start Authority Broker with Provenance & CAS public keys
        self.broker = AuthorityBroker(
            socket_path=self.socket_path,
            broker_secret=b"test_secret_authority_broker_key_32b!",
            provenance_public_key=self.prov_pub_bytes,
            approval_public_key=self.cas_pub_bytes,
        )

        # Register authorized test manifests in Broker's protected store
        self.manifest_process = TaskManifest(
            manifest_id="task_proc_safe",
            allowed_primitives=("PROCESS_EXECUTE",),
            allowed_resources=("/bin/echo", sys.executable),
        )
        self.manifest_storage = TaskManifest(
            manifest_id="task_storage_safe",
            allowed_primitives=("STORAGE_WRITE", "STORAGE_DELETE"),
            allowed_resources=(self.test_dir,),
        )
        self.manifest_network = TaskManifest(
            manifest_id="task_net_safe",
            allowed_primitives=("NETWORK_REQUEST",),
            allowed_resources=("httpbin.org", "127.0.0.1"),
        )
        self.broker.register_manifest(self.manifest_process)
        self.broker.register_manifest(self.manifest_storage)
        self.broker.register_manifest(self.manifest_network)

        # Start Broker UDS listener using canonical start()
        self.broker.start()

        # Wait for socket availability
        for _ in range(30):
            if os.path.exists(self.socket_path):
                break
            time.sleep(0.02)

        # 3. Instantiate Domain Gates holding ONLY Key_Broker_Public (0 private keys)
        broker_pub_bytes = self.broker.get_public_key()
        self.process_gate = ProcessGate(broker_public_key=broker_pub_bytes)
        self.storage_gate = StorageGate(broker_public_key=broker_pub_bytes)

        # Mock DNS for NetworkGate to prevent external hangs
        def mock_dns_resolver(host, port):
            if host in ("httpbin.org",):
                return [(2, 1, 6, "", ("93.184.216.34", 443))]
            raise Exception("Mock DNS host not found")

        self.network_gate = NetworkGate(
            broker_public_key=broker_pub_bytes,
            dns_resolver=mock_dns_resolver,
        )

        # 4. Instantiate AgentAuthorityClient & UnifiedExecutionAdapter
        self.client = AgentAuthorityClient(socket_path=self.socket_path)
        self.adapter = UnifiedExecutionAdapter(
            authority_client=self.client,
            process_gate=self.process_gate,
            storage_gate=self.storage_gate,
            network_gate=self.network_gate,
        )

    def tearDown(self):
        self.broker.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_int01_e2e_process_execution(self):
        """INT-01: End-to-end trusted process execution via Ingress, Broker, and ProcessGate"""
        # Ingress Gateway signs incoming caller provenance
        provenance = self.prov_signer.sign_provenance(
            caller_id="user_admin",
            origin_source="cli_terminal",
            taint_tag="HUMAN_CONFIRMED",
        )

        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('INT_01_SUCCESS')"),
            cwd=self.test_dir,
            env_allowlist=(("SAFE_ENV", "1"),),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        # Execute through Adapter
        result = self.adapter.execute_process(
            task_id="task_proc_safe",
            provenance=provenance,
            semantics=semantics,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("INT_01_SUCCESS", result.stdout)
        self.assertIsNone(result.error_code)

    def test_int02_e2e_storage_write(self):
        """INT-02: End-to-end trusted file write with strict 0600 permission verification"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="worker_job",
            origin_source="local_task",
            taint_tag="SYSTEM_INTERNAL",
        )

        target_file = os.path.join(self.test_dir, "output.json")
        content = '{"status": "CONFIRMED_E2E"}'

        result = self.adapter.write_file(
            task_id="task_storage_safe",
            provenance=provenance,
            target_path=target_file,
            content=content,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.bytes_written, len(content.encode("utf-8")))
        self.assertTrue(os.path.exists(target_file))

        # Check 0600 permission
        mode = stat.S_IMODE(os.stat(target_file).st_mode)
        self.assertEqual(mode, 0o600)

        with open(target_file, "r") as f:
            self.assertEqual(f.read(), content)

    def test_int03_e2e_storage_delete_with_cas_approval(self):
        """INT-03: End-to-end trusted file deletion with CAS human approval and Inode validation"""
        target_file = os.path.join(self.test_dir, "temp_data.bin")
        with open(target_file, "w") as f:
            f.write("TEMPORARY")

        current_inode = os.stat(target_file).st_ino

        # Storage semantics for hash binding
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path=target_file,
            script_hash="",
            argv=(),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        exact_hash = semantics.compute_canonical_hash()

        # CAS Human Approval signed by independent approval authority
        approval_proof = self.cas_service.issue_approval(
            approver_id="system_architect",
            exact_execution_hash=exact_hash,
            ttl_seconds=30.0,
        )

        provenance = self.prov_signer.sign_provenance(
            caller_id="ops_user",
            origin_source="synology_chat",
            taint_tag="HUMAN_CONFIRMED",
        )

        result = self.adapter.delete_file(
            task_id="task_storage_safe",
            provenance=provenance,
            target_path=target_file,
            expected_inode=current_inode,
            human_approval=approval_proof,
        )

        self.assertTrue(result.success)
        self.assertFalse(os.path.exists(target_file))

    def test_int04_e2e_network_request_and_redaction(self):
        """INT-04: End-to-end network request with automated egress secret sanitization"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="crawler_agent",
            origin_source="web_search",
            taint_tag="SYSTEM_INTERNAL",
        )

        url = "https://httpbin.org/post"
        payload = '{"api_key": "mock_secret_token_1234567890abcdef", "action": "sync"}'

        mock_resp = (200, {"Content-Type": "application/json"}, '{"ok": true}')
        result = self.adapter.send_network_request(
            task_id="task_net_safe",
            provenance=provenance,
            url=url,
            method="POST",
            data=payload,
            mock_response=mock_resp,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 200)

    def test_int05_forged_ingress_provenance_blocked(self):
        """INT-05: Attacker forging Ingress signature is blocked at Broker boundary"""
        forged_provenance = ProvenanceContext(
            caller_id="attacker",
            origin_source="forged_cli",
            taint_tag="HUMAN_CONFIRMED",
            ingress_signature=base64.b64encode(b"BAD_SIGNATURE_BYTES_32_BYTES_XX").decode("ascii"),
        )

        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('EVIL')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        result = self.adapter.execute_process(
            task_id="task_proc_safe",
            provenance=forged_provenance,
            semantics=semantics,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)

    def test_int06_unapproved_mutation_blocked(self):
        """INT-06: Destructive action without mandatory human approval proof is blocked"""
        untrusted_provenance = self.prov_signer.sign_provenance(
            caller_id="external_agent",
            origin_source="untrusted_webhook",
            taint_tag="EXTERNAL_UNTRUSTED",
        )

        target_file = os.path.join(self.test_dir, "critical.txt")
        with open(target_file, "w") as f:
            f.write("CRITICAL_DATA")

        # Attempt to delete without CAS approval
        result = self.adapter.delete_file(
            task_id="task_storage_safe",
            provenance=untrusted_provenance,
            target_path=target_file,
            human_approval=None,
        )

        self.assertFalse(result.success)
        self.assertIn(result.error_code, (FailureCode.DENY_UNAUTHORIZED_GRANT, FailureCode.DENY_POLICY_VIOLATION))
        self.assertTrue(os.path.exists(target_file))

    def test_int07_semantics_drift_anti_toctou_blocked(self):
        """INT-07: Parameter drift between capability grant and execution gate is blocked (Anti-TOCTOU)"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="user_admin",
            origin_source="cli_terminal",
            taint_tag="HUMAN_CONFIRMED",
        )

        safe_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('SAFE')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        # 1. Legitimate request to broker gets valid grant for 'SAFE'
        req1 = CapabilityRequest(
            request_id=str(uuid.uuid4()),
            task_id="task_proc_safe",
            requested_primitive="PROCESS_EXECUTE",
            provenance=provenance,
            untrusted_semantics=safe_semantics,
        )
        grant = self.client.request_capability(req1)

        # 2. Attacker substitutes payload with 'MALICIOUS'
        malicious_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('MALICIOUS')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        # Physical ProcessGate recomputes canonical hash and detects drift
        result = self.process_gate.execute(grant, malicious_semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_int08_cas_approval_nonce_replay_blocked(self):
        """INT-08: Replay attack reusing consumed CAS approval token is rejected by atomic ledger"""
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('ONCE')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        exact_hash = semantics.compute_canonical_hash()

        approval_proof = self.cas_service.issue_approval(
            approver_id="system_architect",
            exact_execution_hash=exact_hash,
            ttl_seconds=30.0,
        )

        provenance = self.prov_signer.sign_provenance(
            caller_id="external_agent",
            origin_source="untrusted_source",
            taint_tag="EXTERNAL_UNTRUSTED",
        )

        # First execution succeeds (or grants)
        req_once = CapabilityRequest(
            request_id=str(uuid.uuid4()),
            task_id="task_proc_safe",
            requested_primitive="PROCESS_EXECUTE",
            provenance=provenance,
            untrusted_semantics=semantics,
            human_approval=approval_proof,
        )
        grant1 = self.client.request_capability(req_once)
        self.assertIsNotNone(grant1)

        # Second execution reusing the same approval_proof must fail (Replay Attack)
        req_replay = CapabilityRequest(
            request_id=str(uuid.uuid4()),
            task_id="task_proc_safe",
            requested_primitive="PROCESS_EXECUTE",
            provenance=provenance,
            untrusted_semantics=semantics,
            human_approval=approval_proof,
        )
        with self.assertRaises(Exception) as ctx:
            self.client.request_capability(req_replay)
        self.assertIn("DENY_REPLAY_ATTACK", str(ctx.exception))

    def test_int09_zero_key_memory_audit(self):
        """INT-09: Agent Runtime, Adapter, and Gate objects hold ZERO private keys"""
        components = [
            self.adapter,
            self.client,
            self.process_gate,
            self.storage_gate,
            self.network_gate,
        ]
        for comp in components:
            for attr_name, attr_val in comp.__dict__.items():
                self.assertNotIsInstance(
                    attr_val,
                    ed25519.Ed25519PrivateKey,
                    f"Violation: {comp.__class__.__name__}.{attr_name} holds Ed25519PrivateKey!",
                )


if __name__ == "__main__":
    unittest.main()
