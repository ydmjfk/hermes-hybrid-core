# -*- coding: utf-8 -*-
"""
tests/test_slice5_network_gate.py — Unit Tests for Slice 5 NetworkGate & Egress Control

Verifies:
1. Zero-key architecture: NetworkGate holds ONLY Key_Broker_Public.
2. Target domain & resource binding enforcement.
3. Strict SSRF protection (loopback, private IPs, cloud metadata).
4. Internal service access capability attenuation.
5. Egress secret redaction before transmission.
6. Bounded response size budgeting (Anti-DoS).
"""

import os
import time
import uuid
import base64
import unittest
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_core.authority.models import (
    CapabilityGrant,
    FailureCode,
)
from hermes_core.gates.network_gate import (
    NetworkGate,
    NetworkExecutionResult,
    MAX_RESPONSE_BYTES,
)


class TestSlice5NetworkGate(unittest.TestCase):
    """Slice 5 NetworkGate Verification Test Suite (N-01 ~ N-10)"""

    @classmethod
    def setUpClass(cls):
        cls.broker_private_key = ed25519.Ed25519PrivateKey.generate()
        cls.broker_public_key = cls.broker_private_key.public_key()
        cls.broker_pub_bytes = cls.broker_public_key.public_bytes_raw()

    def setUp(self):
        def mock_dns_resolver(host, port):
            if host in ("httpbin.org", "api.github.com"):
                return [(2, 1, 6, "", ("93.184.216.34", 443))]
            elif host in ("malicious-site.com",):
                return [(2, 1, 6, "", ("198.51.100.1", 443))]
            raise Exception("Host not found in mock DNS")

        self.gate = NetworkGate(
            broker_public_key=self.broker_pub_bytes,
            dns_resolver=mock_dns_resolver,
        )

    def _sign_grant(
        self,
        authorized_domain: str,
        primitive: str = "NETWORK_REQUEST",
        ttl_seconds: float = 30.0,
        now: float = None,
        attenuated_capabilities: Tuple[str, ...] = ("NETWORK_STANDARD",),
        tamper_signature: bool = False,
    ) -> CapabilityGrant:
        """Helper to create a signed CapabilityGrant bound to authorized_domain"""
        current_time = time.time() if now is None else now
        issued_at = current_time
        expires_at = current_time + ttl_seconds

        grant = CapabilityGrant(
            grant_id=str(uuid.uuid4()),
            issued_at=issued_at,
            expires_at=expires_at,
            single_use_nonce=uuid.uuid4().hex,
            subject_uid=os.getuid(),
            target_primitive=primitive,
            exact_execution_hash="test_network_hash",
            attenuated_capabilities=attenuated_capabilities,
            broker_signature="",
            task_id="test_task_s5",
            resource_binding=(authorized_domain,),
        )

        sig_bytes = self.broker_private_key.sign(grant.compute_signature_payload())
        if tamper_signature:
            sig_bytes = b"Y" * len(sig_bytes)

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

    def test_n01_valid_domain_request(self):
        """N-01: Valid grant for authorized public domain succeeds"""
        url = "https://httpbin.org/get"
        grant = self._sign_grant(authorized_domain="httpbin.org")

        mock_resp = (200, {"Content-Type": "application/json"}, '{"origin": "1.2.3.4"}')
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 200)
        self.assertIn("1.2.3.4", result.body)
        self.assertIsNone(result.error_code)

    def test_n02_tampered_signature_rejected(self):
        """N-02: Forged or tampered grant signature is blocked"""
        url = "https://httpbin.org/get"
        grant = self._sign_grant(authorized_domain="httpbin.org", tamper_signature=True)

        mock_resp = (200, {}, "OK")
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)

    def test_n03_expired_grant_rejected(self):
        """N-03: Expired CapabilityGrant is blocked"""
        now = time.time()
        url = "https://httpbin.org/get"
        grant = self._sign_grant(authorized_domain="httpbin.org", ttl_seconds=5.0, now=now)

        mock_resp = (200, {}, "OK")
        result = self.gate.send_request(grant, url, now=now + 10.0, mock_response=mock_resp)

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_TTL_EXPIRED)

    def test_n04_unauthorized_domain_rejected(self):
        """N-04: Requesting a domain not bound in grant is blocked"""
        url = "https://malicious-site.com/steal"
        grant = self._sign_grant(authorized_domain="httpbin.org")

        mock_resp = (200, {}, "OK")
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("not authorized", result.error_message)

    def test_n05_ssrf_loopback_blocked(self):
        """N-05: SSRF attack against loopback (127.0.0.1) is blocked without internal capability"""
        url = "http://127.0.0.1:8080/admin"
        grant = self._sign_grant(authorized_domain="127.0.0.1")

        mock_resp = (200, {}, "ADMIN_PANEL")
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("SSRF violation", result.error_message)

    def test_n06_ssrf_cloud_metadata_blocked(self):
        """N-06: SSRF attack against AWS/GCP cloud metadata endpoint (169.254.169.254) is blocked"""
        url = "http://169.254.169.254/latest/meta-data/"
        grant = self._sign_grant(authorized_domain="169.254.169.254")

        mock_resp = (200, {}, "CREDENTIALS")
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("metadata endpoint", result.error_message)

    def test_n07_ssrf_private_network_blocked(self):
        """N-07: SSRF probe against internal private network (10.0.0.1) is blocked"""
        url = "http://10.0.0.1/status"
        grant = self._sign_grant(authorized_domain="10.0.0.1")

        mock_resp = (200, {}, "INTERNAL_SWITCH")
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("SSRF violation", result.error_message)

    def test_n08_whitelisted_internal_service_allowed(self):
        """N-08: Authorized access to internal services with INTERNAL_SERVICE_ACCESS capability succeeds"""
        url = "http://127.0.0.1:8080/v1/models"
        grant = self._sign_grant(
            authorized_domain="127.0.0.1",
            attenuated_capabilities=("INTERNAL_SERVICE_ACCESS",),
        )

        mock_resp = (200, {"Content-Type": "application/json"}, '{"models": ["Qwen3.8-27B"]}')
        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertTrue(result.success)
        self.assertEqual(result.status_code, 200)
        self.assertIn("Qwen3.8-27B", result.body)

    def test_n09_egress_secret_redaction(self):
        """N-09: Egress data containing secret tokens is scrubbed before transmission"""
        raw_payload = '{"api_key": "mock_secret_token_1234567890abcdef", "query": "hello"}'
        sanitized = self.gate.redact_egress_data(raw_payload)

        self.assertNotIn("mock_secret_token_1234567890abcdef", sanitized)
        self.assertIn("[REDACTED_BY_NETWORK_GATE]", sanitized)
        self.assertIn("hello", sanitized)

    def test_n10_response_size_budget_truncation(self):
        """N-10: Oversized response body exceeding 1MB is strictly truncated"""
        url = "https://httpbin.org/large"
        grant = self._sign_grant(authorized_domain="httpbin.org")

        large_body = "B" * (2 * 1024 * 1024)  # 2MB
        mock_resp = (200, {}, large_body)

        result = self.gate.send_request(grant, url, mock_response=mock_resp)

        self.assertTrue(result.success)
        self.assertLessEqual(len(result.body.encode("utf-8")), MAX_RESPONSE_BYTES)
        self.assertIn("TRUNCATED BY NETWORK_GATE", result.body)


if __name__ == "__main__":
    unittest.main()
