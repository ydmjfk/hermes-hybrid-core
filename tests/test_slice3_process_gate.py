# -*- coding: utf-8 -*-
"""
tests/test_slice3_process_gate.py — Unit Tests for Slice 3 ProcessGate & Subprocess Choke Point

Verifies:
1. Zero-key architecture: ProcessGate holds ONLY Key_Broker_Public.
2. Exact Execution Semantics Hash anti-tampering (Anti-TOCTOU).
3. Full TTL enforcement and clock anomaly detection.
4. Fail-closed defense against drift, signature forgery, and timeout.
5. Strict output size budgeting (Anti-Context / Memory DoS).
"""

import os
import sys
import time
import uuid
import base64
import hashlib
import unittest
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_core.authority.models import (
    CapabilityGrant,
    FullExecutionSemantics,
    FailureCode,
)
from hermes_core.gates.process_gate import (
    ProcessGate,
    ProcessExecutionResult,
    MAX_OUTPUT_BYTES,
)


class TestSlice3ProcessGate(unittest.TestCase):
    """Slice 3 ProcessGate Verification Test Suite (G-01 ~ G-11)"""

    @classmethod
    def setUpClass(cls):
        # Generate broker test keypair
        cls.broker_private_key = ed25519.Ed25519PrivateKey.generate()
        cls.broker_public_key = cls.broker_private_key.public_key()
        cls.broker_pub_bytes = cls.broker_public_key.public_bytes_raw()

    def setUp(self):
        # ProcessGate instantiated with ONLY public key
        self.gate = ProcessGate(broker_public_key=self.broker_pub_bytes)

    def _sign_grant(
        self,
        semantics: FullExecutionSemantics,
        primitive: str = "PROCESS_EXECUTE",
        ttl_seconds: float = 30.0,
        now: float = None,
        tamper_signature: bool = False,
    ) -> Tuple[CapabilityGrant, FullExecutionSemantics]:
        """Helper to create a cryptographically valid CapabilityGrant from Broker"""
        current_time = time.time() if now is None else now
        issued_at = current_time
        expires_at = current_time + ttl_seconds
        exact_hash = semantics.compute_canonical_hash()

        grant = CapabilityGrant(
            grant_id=str(uuid.uuid4()),
            issued_at=issued_at,
            expires_at=expires_at,
            single_use_nonce=uuid.uuid4().hex,
            subject_uid=os.getuid(),
            target_primitive=primitive,
            exact_execution_hash=exact_hash,
            attenuated_capabilities=("PROCESS_EXECUTE",),
            broker_signature="",
            task_id="test_task_s3",
            resource_binding=("/bin/echo",),
        )

        sig_bytes = self.broker_private_key.sign(grant.compute_signature_payload())
        if tamper_signature:
            # Corrupt signature
            sig_bytes = b"X" * len(sig_bytes)

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
        return signed_grant, semantics

    def test_g01_valid_execution(self):
        """G-01: Valid grant and matching semantics executes successfully"""
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('PROCESS_GATE_OK')"),
            cwd=os.getcwd(),
            env_allowlist=(("TEST_KEY", "TEST_VAL"),),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics)

        result = self.gate.execute(grant, semantics)
        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("PROCESS_GATE_OK", result.stdout)
        self.assertIsNone(result.error_code)

    def test_g02_forged_signature_rejected(self):
        """G-02: Tampered/forged broker signature is blocked (DENY_SIGNATURE_TAMPERED)"""
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('FORGED')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics, tamper_signature=True)

        result = self.gate.execute(grant, semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, -1)
        self.assertEqual(result.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)

    def test_g03_expired_grant_rejected(self):
        """G-03: Expired CapabilityGrant is blocked (DENY_TTL_EXPIRED)"""
        now = time.time()
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('EXPIRED')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics, ttl_seconds=10.0, now=now)

        # Execute at now + 15s (past expires_at)
        result = self.gate.execute(grant, semantics, now=now + 15.0)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_TTL_EXPIRED)

    def test_g04_future_grant_rejected(self):
        """G-04: Grant issued in future (clock skew) is blocked (DENY_CLOCK_UNRELIABLE)"""
        now = time.time()
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('FUTURE')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics, ttl_seconds=30.0, now=now + 10.0)

        # Execute at 'now' while grant issued at 'now + 10'
        result = self.gate.execute(grant, semantics, now=now)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_CLOCK_UNRELIABLE)

    def test_g05_command_tampering_drift_rejected(self):
        """G-05: Tampering with command arguments triggers DENY_EXECUTION_SEMANTICS_DRIFT"""
        authorized_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('SAFE')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(authorized_semantics)

        # Attacker tries to execute malicious payload with the safe grant
        malicious_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('MALICIOUS')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        result = self.gate.execute(grant, malicious_semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_g06_env_injection_drift_rejected(self):
        """G-06: Injecting unauthorized environment variables triggers drift rejection"""
        authorized_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('ENV')"),
            cwd=os.getcwd(),
            env_allowlist=(("AUTHORIZED_VAR", "1"),),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(authorized_semantics)

        tampered_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('ENV')"),
            cwd=os.getcwd(),
            env_allowlist=(("AUTHORIZED_VAR", "1"), ("INJECTED_LD_PRELOAD", "/evil.so")),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        result = self.gate.execute(grant, tampered_semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_g07_cwd_drift_rejected(self):
        """G-07: Changing working directory triggers drift rejection"""
        authorized_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('CWD')"),
            cwd="/tmp",
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(authorized_semantics)

        tampered_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('CWD')"),
            cwd="/home/ydmjfk",
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        result = self.gate.execute(grant, tampered_semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_g08_sandbox_profile_downgrade_rejected(self):
        """G-08: Sandbox profile downgrade triggers drift rejection"""
        authorized_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('SANDBOX')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="RESTRICTED_BWRAP",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(authorized_semantics)

        downgraded_semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('SANDBOX')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        result = self.gate.execute(grant, downgraded_semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_EXECUTION_SEMANTICS_DRIFT)

    def test_g09_invalid_primitive_rejected(self):
        """G-09: Grant with non-execution primitive is rejected (DENY_UNAUTHORIZED_GRANT)"""
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "print('WRONG_PRIMITIVE')"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics, primitive="STORAGE_READ")

        result = self.gate.execute(grant, semantics)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_UNAUTHORIZED_GRANT)

    def test_g10_timeout_containment(self):
        """G-10: Subprocess exceeding timeout is safely killed and reported (DENY_TIMEOUT)"""
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", "import time; time.sleep(10)"),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics)

        # Set 1.0s timeout
        result = self.gate.execute(grant, semantics, timeout=1.0)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_TIMEOUT)
        self.assertIn("timed out", result.stderr)

    def test_g11_output_truncation_budget(self):
        """G-11: Subprocess stdout exceeding 1MB is strictly truncated to budget"""
        # Generate 2MB of output
        payload = "A" * 1024
        code = f"for _ in range(2048): print('{payload}')"
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(sys.executable, "-c", code),
            cwd=os.getcwd(),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )
        grant, _ = self._sign_grant(semantics)

        result = self.gate.execute(grant, semantics)
        self.assertTrue(result.success)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), MAX_OUTPUT_BYTES)
        self.assertIn("TRUNCATED BY PROCESS_GATE", result.stdout)


if __name__ == "__main__":
    unittest.main()
