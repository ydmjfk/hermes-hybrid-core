# -*- coding: utf-8 -*-
"""
tests/test_slice4_storage_gate.py — Unit Tests for Slice 4 StorageGate & Inode/Deletion Defense

Verifies:
1. Zero-key architecture: StorageGate holds ONLY Key_Broker_Public.
2. Resource binding verification and Anti-Path-Traversal.
3. Anti-Symlink Defense on write & delete (O_NOFOLLOW).
4. Inode-Anchored Anti-TOCTOU defense on destructive deletion.
5. Constitutional file protection (MEMORY.md, USER.md, SOUL.md, command_whitelist.json).
6. File permission minimization (0600 on write).
"""

import os
import stat
import time
import uuid
import base64
import shutil
import tempfile
import unittest
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_core.authority.models import (
    CapabilityGrant,
    FailureCode,
)
from hermes_core.gates.storage_gate import (
    StorageGate,
    StorageExecutionResult,
)


class TestSlice4StorageGate(unittest.TestCase):
    """Slice 4 StorageGate Verification Test Suite (S4-01 ~ S4-10)"""

    @classmethod
    def setUpClass(cls):
        cls.broker_private_key = ed25519.Ed25519PrivateKey.generate()
        cls.broker_public_key = cls.broker_private_key.public_key()
        cls.broker_pub_bytes = cls.broker_public_key.public_bytes_raw()

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="storage_gate_test_")
        self.gate = StorageGate(broker_public_key=self.broker_pub_bytes)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _sign_grant(
        self,
        target_path: str,
        primitive: str = "STORAGE_WRITE",
        ttl_seconds: float = 30.0,
        now: float = None,
        attenuated_capabilities: Tuple[str, ...] = ("STORAGE_STANDARD",),
        tamper_signature: bool = False,
    ) -> CapabilityGrant:
        """Helper to create a signed CapabilityGrant bound to target_path"""
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
            exact_execution_hash="test_storage_hash",
            attenuated_capabilities=attenuated_capabilities,
            broker_signature="",
            task_id="test_task_s4",
            resource_binding=(target_path,),
        )

        sig_bytes = self.broker_private_key.sign(grant.compute_signature_payload())
        if tamper_signature:
            sig_bytes = b"Z" * len(sig_bytes)

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

    def test_s4_01_valid_file_write_and_permissions(self):
        """S4-01: Valid grant writes file safely with strict 0600 permissions"""
        file_path = os.path.join(self.test_dir, "test_file.txt")
        grant = self._sign_grant(target_path=file_path, primitive="STORAGE_WRITE")

        content = "SECURE_STORAGE_CONTENT_2026"
        result = self.gate.write_file(grant, file_path, content)

        self.assertTrue(result.success)
        self.assertEqual(result.bytes_written, len(content.encode("utf-8")))
        self.assertTrue(os.path.exists(file_path))

        # Verify 0600 file permission (only owner read/write)
        st = os.stat(file_path)
        mode = stat.S_IMODE(st.st_mode)
        self.assertEqual(mode, 0o600)

        # Verify content
        with open(file_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), content)

    def test_s4_02_tampered_signature_rejected(self):
        """S4-02: Forged or tampered grant signature is blocked"""
        file_path = os.path.join(self.test_dir, "forged.txt")
        grant = self._sign_grant(target_path=file_path, primitive="STORAGE_WRITE", tamper_signature=True)

        result = self.gate.write_file(grant, file_path, "MALICIOUS")
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_SIGNATURE_TAMPERED)
        self.assertFalse(os.path.exists(file_path))

    def test_s4_03_expired_grant_rejected(self):
        """S4-03: Expired CapabilityGrant is blocked"""
        now = time.time()
        file_path = os.path.join(self.test_dir, "expired.txt")
        grant = self._sign_grant(target_path=file_path, primitive="STORAGE_WRITE", ttl_seconds=5.0, now=now)

        result = self.gate.write_file(grant, file_path, "EXPIRED", now=now + 10.0)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_TTL_EXPIRED)
        self.assertFalse(os.path.exists(file_path))

    def test_s4_04_unauthorized_path_rejected(self):
        """S4-04: Writing to a path not bound to grant is blocked"""
        authorized_path = os.path.join(self.test_dir, "allowed.txt")
        unauthorized_path = os.path.join(self.test_dir, "forbidden.txt")

        grant = self._sign_grant(target_path=authorized_path, primitive="STORAGE_WRITE")

        result = self.gate.write_file(grant, unauthorized_path, "ATTACK")
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertFalse(os.path.exists(unauthorized_path))

    def test_s4_05_symlink_write_attack_blocked(self):
        """S4-05: Target path being a symbolic link is blocked (Anti-Symlink Defense)"""
        real_target = os.path.join(self.test_dir, "real_target.txt")
        with open(real_target, "w") as f:
            f.write("INITIAL")

        symlink_path = os.path.join(self.test_dir, "symlink_attack.txt")
        os.symlink(real_target, symlink_path)

        grant = self._sign_grant(target_path=symlink_path, primitive="STORAGE_WRITE")

        result = self.gate.write_file(grant, symlink_path, "POISON")
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)

        # Confirm target was not overwritten
        with open(real_target, "r") as f:
            self.assertEqual(f.read(), "INITIAL")

    def test_s4_06_constitutional_file_protection_on_write(self):
        """S4-06: Modifying protected constitutional files (e.g. MEMORY.md) is blocked"""
        target_path = os.path.join(self.test_dir, "MEMORY.md")
        grant = self._sign_grant(target_path=target_path, primitive="STORAGE_WRITE")

        result = self.gate.write_file(grant, target_path, "OVERWRITE_CONSTITUTION")
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("protected constitutional asset", result.error_message)

    def test_s4_07_valid_file_deletion(self):
        """S4-07: Valid grant deletes file safely"""
        file_path = os.path.join(self.test_dir, "to_delete.txt")
        with open(file_path, "w") as f:
            f.write("DELETE_ME")

        grant = self._sign_grant(target_path=file_path, primitive="STORAGE_DELETE")

        result = self.gate.delete_file(grant, file_path)
        self.assertTrue(result.success)
        self.assertFalse(os.path.exists(file_path))

    def test_s4_08_inode_drift_anti_toctou(self):
        """S4-08: Inode drift detection prevents deletion of substituted file (Anti-TOCTOU)"""
        file_path = os.path.join(self.test_dir, "victim.txt")
        with open(file_path, "w") as f:
            f.write("ORIGINAL")

        original_inode = os.stat(file_path).st_ino

        grant = self._sign_grant(target_path=file_path, primitive="STORAGE_DELETE")

        # Attacker replaces the file with a new file (different inode)
        os.unlink(file_path)
        with open(file_path, "w") as f:
            f.write("SUBSTITUTED")
        new_inode = os.stat(file_path).st_ino
        self.assertNotEqual(original_inode, new_inode)

        # Deletion expecting original_inode must fail
        result = self.gate.delete_file(grant, file_path, expected_inode=original_inode)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertIn("Inode drift detected", result.error_message)
        self.assertTrue(os.path.exists(file_path))

    def test_s4_09_symlink_deletion_blocked(self):
        """S4-09: Attempting to delete a symbolic link is blocked"""
        real_file = os.path.join(self.test_dir, "real_file.txt")
        with open(real_file, "w") as f:
            f.write("KEEP_SAFE")

        symlink_path = os.path.join(self.test_dir, "link_to_real.txt")
        os.symlink(real_file, symlink_path)

        grant = self._sign_grant(target_path=symlink_path, primitive="STORAGE_DELETE")

        result = self.gate.delete_file(grant, symlink_path)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertTrue(os.path.exists(real_file))

    def test_s4_10_constitutional_file_protection_on_deletion(self):
        """S4-10: Attempting to delete constitutional protected files is blocked"""
        target_path = os.path.join(self.test_dir, "command_whitelist.json")
        with open(target_path, "w") as f:
            f.write("{}")

        grant = self._sign_grant(target_path=target_path, primitive="STORAGE_DELETE")

        result = self.gate.delete_file(grant, target_path)
        self.assertFalse(result.success)
        self.assertEqual(result.error_code, FailureCode.DENY_POLICY_VIOLATION)
        self.assertTrue(os.path.exists(target_path))


if __name__ == "__main__":
    unittest.main()
