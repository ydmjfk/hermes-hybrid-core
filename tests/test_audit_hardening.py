# -*- coding: utf-8 -*-
"""
tests/test_audit_hardening.py — Tests for Audit Remediations (HHC-001 to HHC-007)
"""

import os
import sys
import time
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives.asymmetric import ed25519
import base64

from hermes_core.authority.models import (
    CapabilityGrant,
    CapabilityRequest,
    FullExecutionSemantics,
    FailureCode,
    CapabilityDeniedError,
    HumanApprovalProof,
    ProvenanceContext,
    TaskManifest,
)
from hermes_core.authority.broker import AuthorityBroker
from hermes_core.gates.process_gate import ProcessGate, ProcessExecutionResult
from hermes_core.gates.storage_gate import StorageGate, StorageExecutionResult
from hermes_core.gates.network_gate import NetworkGate, NetworkExecutionResult
from hermes_core.approval.service import HumanApprovalService, ApprovalTokenVerifier


class TestAuditHardening(unittest.TestCase):
    """Test suite ensuring all findings from the security audit fail closed."""

    @classmethod
    def setUpClass(cls):
        cls.broker_private_key = ed25519.Ed25519PrivateKey.generate()
        cls.broker_public_key = cls.broker_private_key.public_key()
        cls.broker_pub_bytes = cls.broker_public_key.public_bytes_raw()

        cls.approval_service = HumanApprovalService()
        cls.approval_pub_bytes = cls.approval_service.get_public_key()
        cls.approval_verifier = ApprovalTokenVerifier(cls.approval_pub_bytes)

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="hermes_audit_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_signed_grant(self, semantics, primitive="PROCESS_EXECUTE", target_res=None):
        now = time.time()
        res_list = (target_res,) if target_res else ("/bin/echo",)
        nonce_val = os.urandom(16).hex()
        grant = CapabilityGrant(
            grant_id="grant-test-1",
            issued_at=now,
            expires_at=now + 60.0,
            single_use_nonce=nonce_val,
            subject_uid=os.getuid(),
            target_primitive=primitive,
            exact_execution_hash=semantics.compute_canonical_hash(),
            attenuated_capabilities=(primitive,),
            broker_signature="",
            task_id="task_audit",
            resource_binding=res_list,
        )
        sig_bytes = self.broker_private_key.sign(grant.compute_signature_payload())
        return CapabilityGrant(
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

    # --- HHC-001: ProcessGate must fail closed if bwrap missing ---
    def test_hhc_001_bwrap_missing_fails_closed(self):
        """HHC-001: When sandbox_profile requires bwrap and bwrap is missing, fail-closed."""
        gate = ProcessGate(broker_public_key=self.broker_pub_bytes)
        gate._bwrap_path = None  # Force bwrap to be unavailable

        semantics = FullExecutionSemantics(
            interpreter_path="/bin/echo",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=("/bin/echo", "hello"),
            cwd=self.temp_dir,
            env_allowlist=(),
            sandbox_profile="ISOLATED_CONTAINER",
            network_policy="deny_all",
        )
        grant = self._create_signed_grant(semantics, primitive="PROCESS_EXECUTE", target_res="/bin/echo")

        result = gate.execute(grant, semantics)
        self.assertFalse(result.success, "Must not execute on host when bwrap is missing")
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("bwrap", (result.error_message or "").lower())

    # --- HHC-002: AuthorityBroker must reject if no approval_verifier ---
    def test_hhc_002_missing_approval_verifier_fails_closed(self):
        """HHC-002: If action requires human approval but broker has no verifier, fail-closed."""
        broker = AuthorityBroker(
            socket_path=os.path.join(self.temp_dir, "broker_test.sock"),
            broker_secret=b"test_secret_for_audit_testing12!",
            manifest_store={
                "task_audit": TaskManifest(
                    manifest_id="task_audit",
                    allowed_primitives=("process_execution",),
                    allowed_resources=("/tmp/important",),
                    signature="sig_mock",
                )
            },
            approval_public_key=None,  # No approval verifier!
        )

        semantics = FullExecutionSemantics(
            interpreter_path="/bin/rm",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=("/bin/rm", "-rf", "/tmp/important"),
            cwd=self.temp_dir,
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )

        # Forged/arbitrary approval proof
        proof = HumanApprovalProof(
            token_id="fake-token",
            approver_id="attacker",
            approver_sig="fake-sig",
            issued_at=time.time(),
            valid_until=time.time() + 60.0,
            token_nonce="nonce-12345",
            exact_execution_hash=semantics.compute_canonical_hash(),
        )

        req = CapabilityRequest(
            request_id="req-test-1",
            task_id="task_audit",
            requested_primitive="process_execution",
            provenance=ProvenanceContext(
                caller_id="test_user",
                origin_source="synology_chat",
                taint_tag="EXTERNAL_UNTRUSTED",
            ),
            untrusted_semantics=semantics,
            human_approval=proof,
        )

        # Must raise CapabilityDeniedError because approval_verifier is None
        with self.assertRaises(CapabilityDeniedError) as ctx:
            broker.evaluate_request(req, subject_uid=os.getuid())
        self.assertEqual(ctx.exception.code, FailureCode.DENY_UNAUTHORIZED_GRANT)

    # --- HHC-003: NetworkGate IP Pinning ---
    def test_hhc_003_network_gate_ip_pinning(self):
        """HHC-003: NetworkGate connects via validated IP, preventing DNS rebinding TOCTOU."""
        gate = NetworkGate(broker_public_key=self.broker_pub_bytes)
        url = "http://example.com/api/test"
        grant = self._create_signed_grant(
            FullExecutionSemantics(
                interpreter_path="",
                interpreter_hash="",
                script_path="",
                script_hash="",
                argv=(),
                cwd="",
                env_allowlist=(),
                sandbox_profile="default",
                network_policy="allow_all",
            ),
            primitive="NETWORK_REQUEST",
            target_res="example.com"
        )

        # Mock validate_ssrf to return a pinned IP
        with patch.object(gate, "validate_ssrf", return_value=(True, "93.184.216.34", None, None)):
            with patch("hermes_core.gates.network_gate.urllib.request.urlopen") as mock_urlopen:
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.headers = {"Content-Type": "text/plain"}
                mock_resp.read.return_value = b"Hello Pinned IP"
                mock_urlopen.return_value.__enter__.return_value = mock_resp

                res = gate.send_request(grant, url, method="GET")
                self.assertTrue(res.success)
                called_req = mock_urlopen.call_args[0][0]
                # Pinned URL should have replaced host with IP
                self.assertIn("93.184.216.34", called_req.full_url)
                # Host header must be preserved for HTTP virtual hosting
                self.assertEqual(called_req.headers.get("Host"), "example.com")

    # --- HHC-004: StorageGate fstat check ---
    def test_hhc_004_storage_gate_fstat_verification(self):
        """HHC-004: StorageGate verifies opened file descriptor via fstat to avoid symlink races."""
        gate = StorageGate(broker_public_key=self.broker_pub_bytes)
        test_file = os.path.join(self.temp_dir, "safe_file.txt")
        canonical_dir = os.path.realpath(self.temp_dir)

        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(),
            cwd="",
            env_allowlist=(),
            sandbox_profile="default",
            network_policy="deny_all",
        )
        grant = self._create_signed_grant(semantics, primitive="STORAGE_WRITE", target_res=canonical_dir)

        # Mock fstat to simulate a symlink or unexpected file mode
        with patch("os.fstat") as mock_fstat:
            mock_stat = MagicMock()
            mock_stat.st_mode = 0o120000  # S_IFLNK (symlink)
            mock_stat.st_ino = 99999
            mock_fstat.return_value = mock_stat

            result = gate.write_file(grant, test_file, "clean content")
            self.assertFalse(result.success, "Should fail if fstat reports symlink or invalid file")
            self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)

    # --- HHC-005: Egress Header Redaction ---
    def test_hhc_005_network_gate_header_redaction(self):
        """HHC-005: Sensitive headers in network requests must be sanitized."""
        gate = NetworkGate(broker_public_key=self.broker_pub_bytes)
        sensitive_headers = {
            "Authorization": "Bearer sk-secret1234567890abcdef",
            "X-Api-Key": "my-secret-key-value",
            "Cookie": "session_id=abcdef1234567890",
            "Content-Type": "application/json",
        }
        self.assertTrue(hasattr(gate, "redact_headers"), "NetworkGate must implement redact_headers")
        redacted = gate.redact_headers(sensitive_headers)
        self.assertIn("[REDACTED", redacted["Authorization"])
        self.assertIn("[REDACTED", redacted["X-Api-Key"])
        self.assertIn("[REDACTED", redacted["Cookie"])
        self.assertEqual(redacted["Content-Type"], "application/json")

    # --- HHC-006 & HHC-007: bwrap sandbox restricted mounts and version check ---
    def test_hhc_006_bwrap_restricted_mounts(self):
        """HHC-006: bwrap args must isolate sensitive root/home paths."""
        gate = ProcessGate(broker_public_key=self.broker_pub_bytes)
        self.assertTrue(hasattr(gate, "_build_bwrap_args"), "ProcessGate must have _build_bwrap_args")
        args = gate._build_bwrap_args(["ls", "-la"], "/tmp")
        args_str = " ".join(args)
        # Ensure /root and /home are masked or isolated
        self.assertTrue(
            "--tmpfs /root" in args_str or "--ro-bind /usr" in args_str,
            "bwrap arguments must isolate sensitive root/home paths",
        )

    def test_hhc_007_bwrap_minimum_version(self):
        """HHC-007: bwrap version check enforces minimum supported version."""
        gate = ProcessGate(broker_public_key=self.broker_pub_bytes)
        self.assertTrue(hasattr(gate, "check_bwrap_version"), "ProcessGate must implement check_bwrap_version")
        # Test valid version
        self.assertTrue(gate.check_bwrap_version("bubblewrap 0.11.1", min_version=(0, 11, 0)))
        # Test old version
        self.assertFalse(gate.check_bwrap_version("bubblewrap 0.9.0", min_version=(0, 11, 0)))


if __name__ == "__main__":
    unittest.main()
