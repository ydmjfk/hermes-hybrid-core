# -*- coding: utf-8 -*-
"""
tests/test_slice7_red_team_matrix.py — Red Team Adversarial Security Matrix (Slice 7)

Comprehensive adversarial verification covering AT-01 through AT-10:
AT-01: Direct Subprocess Bypass (Forged, expired, rogue-signed grants fail closed)
AT-02: Constitutional Overwrite (Protected assets like MEMORY.md, whitelist rejection)
AT-03: Symlink Hijack & Inode TOCTOU (Symlink rejection, atomic inode comparison)
AT-04: Memory Taint Injection (Untrusted caller taint rejected or blocked without approval)
AT-05: Cloud Metadata & SSRF (169.254.169.254, internal IPs, and DNS rebinding blocked)
AT-06: Egress Secret Leakage (Bearer tokens, API credentials redacted before egress)
AT-07: Cron Command Chaining (Argument injection and semantics hash mismatch defense)
AT-08: Concurrency Nonce Replay (Atomic single-use token consumption under race conditions)
AT-09: Semantics Drift Attack (Tampered argv, cwd, env, or sandbox profile blocked)
AT-10: Agent Zero-Key Memory Audit (Reflective proof of 0 private keys in Agent runtime)
"""

import os
import sys
import time
import uuid
import base64
import shutil
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_core.authority.models import (
    ProvenanceContext,
    TaskManifest,
    FullExecutionSemantics,
    HumanApprovalProof,
    CapabilityGrant,
    CapabilityRequest,
    FailureCode,
    CapabilityDeniedError,
)
from hermes_core.authority.broker import AuthorityBroker
from hermes_core.authority.client import AgentAuthorityClient
from hermes_core.provenance.signer import IngressProvenanceSigner
from hermes_core.approval.service import HumanApprovalService
from hermes_core.gates.process_gate import ProcessGate
from hermes_core.gates.storage_gate import StorageGate
from hermes_core.gates.network_gate import NetworkGate
from hermes_core.gates.adapter import UnifiedExecutionAdapter


class TestSlice7RedTeamMatrix(unittest.TestCase):
    """Red Team Adversarial Security Matrix & Final Acceptance (AT-01 ~ AT-10)"""

    @classmethod
    def setUpClass(cls):
        # 1. Generate boundary cryptographic keys
        cls.prov_signer = IngressProvenanceSigner()
        cls.prov_pub_bytes = cls.prov_signer.get_public_key()

        cls.cas_service = HumanApprovalService()
        cls.cas_pub_bytes = cls.cas_service.get_public_key()

    def setUp(self):
        # Create isolated test environment
        self.test_dir = tempfile.mkdtemp(prefix="slice7_red_team_")
        self.socket_path = os.path.join(self.test_dir, "broker.sock")

        # Start Authority Broker with Provenance & CAS public keys
        self.broker = AuthorityBroker(
            socket_path=self.socket_path,
            broker_secret=b"slice7_red_team_broker_secret_32b",
            provenance_public_key=self.prov_pub_bytes,
            approval_public_key=self.cas_pub_bytes,
        )

        # Register standard authorized manifests
        self.manifest_process = TaskManifest(
            manifest_id="task_proc_redteam",
            allowed_primitives=("PROCESS_EXECUTE",),
            allowed_resources=("/bin/echo", sys.executable),
        )
        self.manifest_storage = TaskManifest(
            manifest_id="task_storage_redteam",
            allowed_primitives=("STORAGE_WRITE", "STORAGE_DELETE"),
            allowed_resources=(self.test_dir,),
        )
        self.manifest_network = TaskManifest(
            manifest_id="task_net_redteam",
            allowed_primitives=("NETWORK_REQUEST",),
            allowed_resources=("example.com", "httpbin.org"),
        )
        self.broker.register_manifest(self.manifest_process)
        self.broker.register_manifest(self.manifest_storage)
        self.broker.register_manifest(self.manifest_network)

        self.broker.start()

        # Wait for socket
        for _ in range(30):
            if os.path.exists(self.socket_path):
                break
            time.sleep(0.02)

        broker_pub_bytes = self.broker.get_public_key()
        self.process_gate = ProcessGate(broker_public_key=broker_pub_bytes)
        self.storage_gate = StorageGate(broker_public_key=broker_pub_bytes)

        # Deterministic DNS resolver mock for NetworkGate
        def mock_dns_resolver(host, port):
            if host == "example.com":
                return [(2, 1, 6, "", ("93.184.216.34", 80))]
            elif host == "rebind-internal.attacker.com":
                # Simulated DNS rebinding resolving to local loopback
                return [(2, 1, 6, "", ("127.0.0.1", 80))]
            raise Exception(f"Host '{host}' not found in mock DNS")

        self.network_gate = NetworkGate(
            broker_public_key=broker_pub_bytes,
            dns_resolver=mock_dns_resolver,
        )

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

    def test_at01_direct_subprocess_bypass(self):
        """AT-01: Direct Subprocess Bypass - Forged, unsigned, expired, or rogue-signed grants fail closed"""
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('AT_01_BYPASS_ATTEMPT')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        canonical_hash = semantics.compute_canonical_hash()
        now = time.time()

        # 1. Unsigned / Empty signature grant
        forged_grant_1 = CapabilityGrant(
            grant_id=str(uuid.uuid4()),
            issued_at=now,
            expires_at=now + 30.0,
            single_use_nonce=uuid.uuid4().hex,
            subject_uid=os.getuid(),
            target_primitive="PROCESS_EXECUTE",
            exact_execution_hash=canonical_hash,
            attenuated_capabilities=("PROCESS_EXECUTE",),
            broker_signature="",
            task_id="task_proc_redteam",
            resource_binding=(sys.executable,),
        )
        res1 = self.process_gate.execute(forged_grant_1, semantics)
        self.assertFalse(res1.success)
        self.assertEqual(res1.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)

        # 2. Rogue private key signed grant
        rogue_key = ed25519.Ed25519PrivateKey.generate()
        sig_payload = forged_grant_1.compute_signature_payload()
        rogue_sig = base64.b64encode(rogue_key.sign(sig_payload)).decode("utf-8")

        forged_grant_2 = CapabilityGrant(
            grant_id=forged_grant_1.grant_id,
            issued_at=now,
            expires_at=now + 30.0,
            single_use_nonce=forged_grant_1.single_use_nonce,
            subject_uid=os.getuid(),
            target_primitive="PROCESS_EXECUTE",
            exact_execution_hash=canonical_hash,
            attenuated_capabilities=("PROCESS_EXECUTE",),
            broker_signature=rogue_sig,
            task_id="task_proc_redteam",
            resource_binding=(sys.executable,),
        )
        res2 = self.process_gate.execute(forged_grant_2, semantics)
        self.assertFalse(res2.success)
        self.assertEqual(res2.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)

        # 3. Expired grant
        expired_grant = CapabilityGrant(
            grant_id=str(uuid.uuid4()),
            issued_at=now - 120.0,
            expires_at=now - 60.0,
            single_use_nonce=uuid.uuid4().hex,
            subject_uid=os.getuid(),
            target_primitive="PROCESS_EXECUTE",
            exact_execution_hash=canonical_hash,
            attenuated_capabilities=("PROCESS_EXECUTE",),
            broker_signature=rogue_sig,
            task_id="task_proc_redteam",
            resource_binding=(sys.executable,),
        )
        res3 = self.process_gate.execute(expired_grant, semantics)
        self.assertFalse(res3.success)
        self.assertEqual(res3.error_code, FailureCode.DENY_TTL_EXPIRED)

    def test_at02_constitutional_overwrite_defense(self):
        """AT-02: Constitutional Overwrite - Mutation of protected system & governance files strictly blocked"""
        protected_targets = [
            "/home/user/MEMORY.md",
            "/home/user/USER.md",
            "/home/user/SOUL.md",
            "/home/user/command_whitelist.json",
            "/home/user/.ssh/id_rsa",
            "/home/user/.git/config",
        ]

        # Ingress provenance
        provenance = self.prov_signer.sign_provenance(
            caller_id="adversary_bot",
            origin_source="untrusted_input",
            taint_tag="HUMAN_CONFIRMED",
        )

        for p_target in protected_targets:
            # Attempt write via Adapter / StorageGate
            res = self.adapter.write_file(
                task_id="task_storage_redteam",
                provenance=provenance,
                target_path=p_target,
                content="MALICIOUS_OVERWRITE_PAYLOAD",
            )
            self.assertFalse(res.success)
            self.assertEqual(res.error_code, FailureCode.DENY_POLICY_VIOLATION)

            # Attempt deletion
            res_del = self.adapter.delete_file(
                task_id="task_storage_redteam",
                provenance=provenance,
                target_path=p_target,
            )
            self.assertFalse(res_del.success)
            self.assertEqual(res_del.error_code, FailureCode.DENY_POLICY_VIOLATION)

    def test_at03_symlink_hijack_and_toctou(self):
        """AT-03: Symlink Hijack & Inode TOCTOU - Symlink paths and inode race swaps rejected"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="tester",
            origin_source="system_internal",
            taint_tag="HUMAN_CONFIRMED",
        )

        # 1. Symlink Write Hijack Attempt
        real_target = os.path.join(self.test_dir, "victim_file.txt")
        with open(real_target, "w", encoding="utf-8") as f:
            f.write("ORIGINAL_SAFE_CONTENT")

        symlink_path = os.path.join(self.test_dir, "symlink_pointer")
        os.symlink(real_target, symlink_path)

        res_symlink_write = self.adapter.write_file(
            task_id="task_storage_redteam",
            provenance=provenance,
            target_path=symlink_path,
            content="CORRUPTED_BY_SYMLINK",
        )
        self.assertFalse(res_symlink_write.success)
        self.assertEqual(res_symlink_write.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("symbolic link", res_symlink_write.error_message)

        # Verify real target was unharmed
        with open(real_target, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "ORIGINAL_SAFE_CONTENT")

        # 2. Symlink Deletion Hijack Attempt
        res_symlink_del = self.adapter.delete_file(
            task_id="task_storage_redteam",
            provenance=provenance,
            target_path=symlink_path,
        )
        self.assertFalse(res_symlink_del.success)
        self.assertEqual(res_symlink_del.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("symbolic link", res_symlink_del.error_message)

        # 3. Inode TOCTOU Swap Attempt on Delete
        safe_file = os.path.join(self.test_dir, "file_to_swap.txt")
        with open(safe_file, "w", encoding="utf-8") as f:
            f.write("INODE_1")
        old_inode = os.stat(safe_file).st_ino

        # Simulate TOCTOU: File is removed and recreated, gaining a different inode
        os.unlink(safe_file)
        with open(safe_file, "w", encoding="utf-8") as f:
            f.write("INODE_2")
        new_inode = os.stat(safe_file).st_ino

        # Fabricate an outdated expected inode
        stale_expected_inode = old_inode if old_inode != new_inode else (new_inode + 9999)

        res_toctou = self.adapter.delete_file(
            task_id="task_storage_redteam",
            provenance=provenance,
            target_path=safe_file,
            expected_inode=stale_expected_inode,
        )
        self.assertFalse(res_toctou.success)
        self.assertEqual(res_toctou.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("Inode drift", res_toctou.error_message)
        self.assertTrue(os.path.exists(safe_file))

    def test_at04_memory_taint_injection(self):
        """AT-04: Memory Taint Injection - Untrusted caller taint blocked from privileged execution without CAS"""
        untrusted_provenance = self.prov_signer.sign_provenance(
            caller_id="prompt_injection_source",
            origin_source="untrusted_web",
            taint_tag="EXTERNAL_UNTRUSTED",
        )

        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "import os; print('TAINT_ESCALATION')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        # Privileged process execute request with untrusted taint and no approval
        res = self.adapter.execute_process(
            task_id="task_proc_redteam",
            provenance=untrusted_provenance,
            semantics=semantics,
            human_approval=None,
        )
        self.assertFalse(res.success)
        self.assertEqual(res.error_code, FailureCode.DENY_UNAUTHORIZED_GRANT)
        self.assertIn("HumanApprovalProof", res.error_message)

        # Forged HumanApprovalProof
        rogue_cas = HumanApprovalService()
        forged_proof = rogue_cas.issue_approval(
            approver_id="fake_admin",
            exact_execution_hash=semantics.compute_canonical_hash(),
            ttl_seconds=30.0,
        )

        res_forged = self.adapter.execute_process(
            task_id="task_proc_redteam",
            provenance=untrusted_provenance,
            semantics=semantics,
            human_approval=forged_proof,
        )
        self.assertFalse(res_forged.success)
        self.assertEqual(res_forged.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)

    def test_at05_cloud_metadata_and_ssrf(self):
        """AT-05: Cloud Metadata & Private SSRF - Block metadata endpoints, private subnets, and DNS rebinding"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="tester",
            origin_source="system_internal",
            taint_tag="HUMAN_CONFIRMED",
        )

        # 1. Cloud Metadata (169.254.169.254)
        metadata_ip = ".".join(["169", "254", "169", "254"])
        res_meta = self.adapter.send_network_request(
            task_id="task_net_redteam",
            provenance=provenance,
            url=f"http://{metadata_ip}/latest/meta-data/",
        )
        self.assertFalse(res_meta.success)
        self.assertEqual(res_meta.error_code, FailureCode.DENY_POLICY_VIOLATION)

        # 2. Private Subnet direct IP SSRF
        private_ip = ".".join(["10", "0", "0", "1"])
        res_priv = self.adapter.send_network_request(
            task_id="task_net_redteam",
            provenance=provenance,
            url=f"http://{private_ip}/admin_dashboard",
        )
        self.assertFalse(res_priv.success)
        self.assertEqual(res_priv.error_code, FailureCode.DENY_POLICY_VIOLATION)

        # 3. DNS Rebinding SSRF (Domain resolves to 127.0.0.1)
        res_rebind = self.adapter.send_network_request(
            task_id="task_net_redteam",
            provenance=provenance,
            url="http://rebind-internal.attacker.com/status",
        )
        self.assertFalse(res_rebind.success)
        self.assertEqual(res_rebind.error_code, FailureCode.DENY_POLICY_VIOLATION)

    def test_at06_egress_secret_leakage(self):
        """AT-06: Egress Secret Leakage - Authorization tokens and secret keys sanitized before transmission"""
        # Redaction test
        raw_payload = (
            '{"status": "report", "auth": "Bearer test_bearer_token_val_123456789", '
            '"api_key": "mock_secret_token_abcdef1234567890"}'
        )
        redacted = self.network_gate.redact_egress_data(raw_payload)
        self.assertNotIn("test_bearer_token_val_123456789", redacted)
        self.assertIn("[REDACTED_BY_NETWORK_GATE]", redacted)

        # E2E request test with mock HTTP response
        provenance = self.prov_signer.sign_provenance(
            caller_id="tester",
            origin_source="system_internal",
            taint_tag="HUMAN_CONFIRMED",
        )

        res = self.adapter.send_network_request(
            task_id="task_net_redteam",
            provenance=provenance,
            url="http://example.com/api/v1/telemetry",
            method="POST",
            headers={"Authorization": "Bearer test_bearer_token_val_123456789"},
            data=raw_payload,
            mock_response=(200, {"Content-Type": "application/json"}, '{"result": "ok"}'),
        )
        self.assertTrue(res.success)
        self.assertEqual(res.status_code, 200)

    def test_at07_cron_command_chaining_and_shell_injection(self):
        """AT-07: Cron Command Chaining - Argument-level command chaining & shell injection neutralized"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="tester",
            origin_source="system_internal",
            taint_tag="HUMAN_CONFIRMED",
        )

        # Baseline authorized semantics
        base_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('SAFE_CRON_TASK')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        # Request legitimate grant
        req = CapabilityRequest(
            request_id=str(uuid.uuid4()),
            task_id="task_proc_redteam",
            requested_primitive="PROCESS_EXECUTE",
            provenance=provenance,
            untrusted_semantics=base_semantics,
        )
        grant = self.client.request_capability(req)
        self.assertTrue(grant.broker_signature)

        # Attacker attempts to sneak shell operator chaining into argv
        chained_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('SAFE_CRON_TASK'); import os; os.system('echo MALICIOUS')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        res_chained = self.process_gate.execute(grant, chained_semantics)
        self.assertFalse(res_chained.success)
        self.assertEqual(res_chained.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_at08_concurrency_nonce_replay(self):
        """AT-08: Concurrency Nonce Replay - Atomic CAS single-use nonce prevents parallel replay races"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="external_user",
            origin_source="untrusted_input",
            taint_tag="EXTERNAL_UNTRUSTED",
        )

        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('RACE_NONCE')"),
            cwd=self.test_dir,
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        canonical_hash = semantics.compute_canonical_hash()

        # Single-use HumanApprovalProof
        single_use_approval = self.cas_service.issue_approval(
            approver_id="operator_chang",
            exact_execution_hash=canonical_hash,
            ttl_seconds=30.0,
        )

        def attempt_capability_request():
            client_conn = AgentAuthorityClient(socket_path=self.socket_path)
            req = CapabilityRequest(
                request_id=str(uuid.uuid4()),
                task_id="task_proc_redteam",
                requested_primitive="PROCESS_EXECUTE",
                provenance=provenance,
                untrusted_semantics=semantics,
                human_approval=single_use_approval,
            )
            try:
                grant = client_conn.request_capability(req)
                return True, "SUCCESS", grant
            except CapabilityDeniedError as cde:
                return False, cde.code, str(cde)
            except Exception as e:
                return False, "ERROR", str(e)

        concurrency_count = 10
        with ThreadPoolExecutor(max_workers=concurrency_count) as executor:
            futures = [executor.submit(attempt_capability_request) for _ in range(concurrency_count)]
            results = [f.result() for f in futures]

        success_count = sum(1 for r in results if r[0] is True)
        replay_denied_count = sum(1 for r in results if r[1] == FailureCode.DENY_REPLAY_ATTACK)

        # Exactly 1 request succeeds; remaining 9 must be rejected as REPLAY_ATTACK
        self.assertEqual(success_count, 1, f"Expected exactly 1 success, got {success_count}")
        self.assertEqual(
            replay_denied_count,
            concurrency_count - 1,
            f"Expected {concurrency_count - 1} replay denials, got {replay_denied_count}",
        )

    def test_at09_semantics_drift_attack(self):
        """AT-09: Semantics Drift Attack - Tampering with any dimension of semantics violates hash parity"""
        provenance = self.prov_signer.sign_provenance(
            caller_id="tester",
            origin_source="system_internal",
            taint_tag="HUMAN_CONFIRMED",
        )

        base_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('BENIGN')"),
            cwd=self.test_dir,
            env_allowlist=(("ENV_A", "1"),),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        req = CapabilityRequest(
            request_id=str(uuid.uuid4()),
            task_id="task_proc_redteam",
            requested_primitive="PROCESS_EXECUTE",
            provenance=provenance,
            untrusted_semantics=base_semantics,
        )
        grant = self.client.request_capability(req)
        self.assertTrue(grant.broker_signature)

        # Drift Vector 1: Tampered cwd
        drift_cwd = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('BENIGN')"),
            cwd="/tmp",  # Drift
            env_allowlist=(("ENV_A", "1"),),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        res_cwd = self.process_gate.execute(grant, drift_cwd)
        self.assertFalse(res_cwd.success)
        self.assertEqual(res_cwd.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

        # Drift Vector 2: Tampered env_allowlist (Privilege escalation via injected env)
        drift_env = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('BENIGN')"),
            cwd=self.test_dir,
            env_allowlist=(("ENV_A", "1"), ("LD_PRELOAD", "/tmp/malicious.so")),  # Drift
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        res_env = self.process_gate.execute(grant, drift_env)
        self.assertFalse(res_env.success)
        self.assertEqual(res_env.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

        # Drift Vector 3: Tampered sandbox profile (Downgrade attack)
        drift_profile = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('BENIGN')"),
            cwd=self.test_dir,
            env_allowlist=(("ENV_A", "1"),),
            sandbox_profile="UNRESTRICTED",  # Drift
            network_policy="DENY_ALL",
        )
        res_profile = self.process_gate.execute(grant, drift_profile)
        self.assertFalse(res_profile.success)
        self.assertEqual(res_profile.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_at10_agent_zero_private_keys_memory_audit(self):
        """AT-10: Agent Zero-Key Memory Audit - Introspection asserts 0 private keys in Agent runtime memory"""
        runtime_objects = [
            self.client,
            self.process_gate,
            self.storage_gate,
            self.network_gate,
            self.adapter,
        ]

        def inspect_object_recursively(obj: Any, seen: set) -> List[str]:
            violations = []
            obj_id = id(obj)
            if obj_id in seen:
                return violations
            seen.add(obj_id)

            # Check if object itself is an Ed25519PrivateKey
            if isinstance(obj, ed25519.Ed25519PrivateKey):
                violations.append(f"Direct Ed25519PrivateKey found in {type(obj)}")

            # Check attributes
            if hasattr(obj, "__dict__"):
                for attr_name, attr_val in obj.__dict__.items():
                    if isinstance(attr_val, ed25519.Ed25519PrivateKey):
                        violations.append(f"Ed25519PrivateKey found in {type(obj)}.{attr_name}")
                    elif isinstance(attr_val, (list, tuple, set)):
                        for item in attr_val:
                            if isinstance(item, ed25519.Ed25519PrivateKey):
                                violations.append(f"Ed25519PrivateKey in collection {type(obj)}.{attr_name}")
                    elif hasattr(attr_val, "__dict__") and not isinstance(attr_val, (str, bytes, int, float)):
                        violations.extend(inspect_object_recursively(attr_val, seen))

            return violations

        all_violations = []
        visited = set()
        for target in runtime_objects:
            violations = inspect_object_recursively(target, visited)
            all_violations.extend(violations)

        self.assertEqual(
            len(all_violations),
            0,
            f"Zero-Key Principle violated: Found private key instances in Agent runtime: {all_violations}",
        )

        # Assert that gates only possess Ed25519PublicKey
        self.assertIsInstance(self.process_gate.public_key, ed25519.Ed25519PublicKey)
        self.assertIsInstance(self.storage_gate.public_key, ed25519.Ed25519PublicKey)
        self.assertIsInstance(self.network_gate.public_key, ed25519.Ed25519PublicKey)


if __name__ == "__main__":
    unittest.main()
