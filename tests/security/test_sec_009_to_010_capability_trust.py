#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEC-009 ~ SEC-010: Capability Trust & Integrity Gate Test Matrix
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from capabilities.extension_layer.extension_registry_engine import ExtensionRegistryEngine


class TestCapabilityTrustSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.caps_dir = Path(self.temp_dir.name).resolve()

        # Create valid approved capability
        self.valid_cap = self.caps_dir / "valid_cap"
        self.valid_cap.mkdir()
        tool_code = "def sample_tool():\n    '''Sample'''\n    return 'OK'\n"
        val_code = "def validate_capability():\n    return True, 'Health check passed'\n"
        (self.valid_cap / "tools.py").write_text(tool_code, encoding="utf-8")
        (self.valid_cap / "validator.py").write_text(val_code, encoding="utf-8")

        import hashlib
        h_tool = hashlib.sha256(tool_code.encode("utf-8")).hexdigest()
        h_val = hashlib.sha256(val_code.encode("utf-8")).hexdigest()

        # Setup test trust root keypair
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from hermes_core.trust_root import sign_capability_digest

        self.priv_key = ed25519.Ed25519PrivateKey.generate()
        self.pub_bytes = self.priv_key.public_key().public_bytes_raw()
        import os
        self.orig_env_key = os.environ.get("HERMES_TRUST_ROOT_PUBKEY")
        os.environ["HERMES_TRUST_ROOT_PUBKEY"] = self.pub_bytes.hex()

        files_map = {
            "tools.py": h_tool,
            "validator.py": h_val
        }

        sig = sign_capability_digest(
            private_key_bytes=self.priv_key.private_bytes_raw(),
            capability_id="CAP-099-TEST",
            version="1.0.0",
            files_map=files_map
        )

        manifest_data = {
            "capability_id": "CAP-099-TEST",
            "name": "valid_cap",
            "version": "1.0.0",
            "entrypoint": "tools.py:sample_tool",
            "files": ["manifest.json", "tools.py", "validator.py"],
            "integrity": {
                "algorithm": "sha256",
                "files": files_map
            },
            "trust": {
                "approved": True,
                "approved_by": "Security Admin",
                "policy": "CRYPTOGRAPHICALLY_VERIFIED",
                "signature": sig
            }
        }
        (self.valid_cap / "manifest.json").write_text(json.dumps(manifest_data), encoding="utf-8")

    def tearDown(self):
        import os
        if self.orig_env_key is not None:
            os.environ["HERMES_TRUST_ROOT_PUBKEY"] = self.orig_env_key
        else:
            os.environ.pop("HERMES_TRUST_ROOT_PUBKEY", None)
        self.temp_dir.cleanup()

    def test_sec_009_extension_hash_mismatch_quarantined(self):
        """SEC-009: Tampered capability file triggers SHA-256 mismatch and quarantine"""
        # Tamper validator.py
        (self.valid_cap / "validator.py").write_text("def validate_capability():\n    # Hacked\n    return True, 'Hacked'\n")

        engine = ExtensionRegistryEngine(str(self.caps_dir))
        res = engine.discover_and_register_all()

        self.assertIn("valid_cap", res.get("quarantined_extensions", []))
        self.assertNotIn("valid_cap", res.get("active_extensions", []))
        self.assertIn("SHA-256 integrity mismatch", engine.quarantined_extensions["valid_cap"]["reason"])

    def test_sec_010_unauthorized_capability_execution_rejected(self):
        """SEC-010: Capability lacking explicit trust.approved=True must be quarantined"""
        # Set trust.approved to False
        mf_path = self.valid_cap / "manifest.json"
        data = json.loads(mf_path.read_text(encoding="utf-8"))
        data["trust"]["approved"] = False
        mf_path.write_text(json.dumps(data), encoding="utf-8")

        engine = ExtensionRegistryEngine(str(self.caps_dir))
        res = engine.discover_and_register_all()

        self.assertIn("valid_cap", res.get("quarantined_extensions", []))
        self.assertNotIn("valid_cap", res.get("active_extensions", []))
        self.assertIn("not approved", engine.quarantined_extensions["valid_cap"]["reason"])

    def test_sec_021_cryptographic_signature_tamper_rejected(self):
        """SEC-021: Altered cryptographic signature or untrusted signing key must be quarantined"""
        mf_path = self.valid_cap / "manifest.json"
        data = json.loads(mf_path.read_text(encoding="utf-8"))
        # Tamper signature with invalid hex
        data["trust"]["signature"] = "0" * 128
        mf_path.write_text(json.dumps(data), encoding="utf-8")

        engine = ExtensionRegistryEngine(str(self.caps_dir))
        res = engine.discover_and_register_all()

        self.assertIn("valid_cap", res.get("quarantined_extensions", []))
        self.assertNotIn("valid_cap", res.get("active_extensions", []))
        self.assertIn("Cryptographic signature verification failed", engine.quarantined_extensions["valid_cap"]["reason"])


if __name__ == "__main__":
    unittest.main()
