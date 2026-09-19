#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/sign_capability.py — Official Release Authority Signing Tool
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Calculates canonical file SHA-256 hashes and signs capability manifest
using the isolated local Ed25519 Release Authority private key.
"""

import os
import sys
import json
import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from hermes_core.trust_root import sign_capability_digest, verify_capability_signature
except ImportError as e:
    print(f"Error: Required crypto modules could not be imported: {e}")
    sys.exit(1)

DEFAULT_PRIVKEY_FILE = Path.home() / ".hermes" / "secrets" / "release_authority.key"


def get_private_key_bytes() -> bytes:
    env_key = os.environ.get("HERMES_RELEASE_AUTHORITY_KEY")
    if env_key:
        return bytes.fromhex(env_key.strip())
    if DEFAULT_PRIVKEY_FILE.exists():
        key_hex = DEFAULT_PRIVKEY_FILE.read_text(encoding="utf-8").strip()
        return bytes.fromhex(key_hex)
    raise FileNotFoundError(
        f"Release Authority private key not found at {DEFAULT_PRIVKEY_FILE} or HERMES_RELEASE_AUTHORITY_KEY"
    )


def sign_capability(cap_dir: Path) -> bool:
    manifest_file = cap_dir / "manifest.json"
    if not manifest_file.exists():
        print(f"Error: manifest.json not found in {cap_dir}")
        return False

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    cap_id = manifest.get("capability_id")
    version = manifest.get("version", "1.0.0")
    files_declared = manifest.get("files", [])

    # Compute sha256 for all declared files except manifest.json
    files_map = {}
    for fname in files_declared:
        if fname == "manifest.json":
            continue
        fpath = cap_dir / fname
        if not fpath.exists():
            print(f"Error: Declared file {fname} does not exist in {cap_dir}")
            return False
        content = fpath.read_bytes()
        files_map[fname] = hashlib.sha256(content).hexdigest()

    priv_key_bytes = get_private_key_bytes()
    signature_hex = sign_capability_digest(
        private_key_bytes=priv_key_bytes,
        capability_id=cap_id,
        version=version,
        files_map=files_map
    )

    # Verify signature before updating manifest
    pub_key_bytes = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_bytes).public_key().public_bytes_raw()
    is_valid, reason = verify_capability_signature(
        capability_id=cap_id,
        version=version,
        files_map=files_map,
        signature_hex=signature_hex,
        public_key_bytes=pub_key_bytes
    )
    if not is_valid:
        print(f"Signing self-verification failed: {reason}")
        return False

    # Update manifest
    manifest["integrity"] = {
        "algorithm": "sha256",
        "files": files_map
    }
    manifest["trust"] = {
        "approved": True,
        "approved_by": "Hermes Release Authority",
        "policy": "CRYPTOGRAPHICALLY_VERIFIED",
        "signature": signature_hex
    }

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"✅ Successfully signed {cap_id} ({cap_dir.name}) with signature: {signature_hex[:16]}...")
    return True


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    caps_base = REPO_ROOT / "capabilities"

    if target == "all":
        success = True
        for cdir in sorted(caps_base.iterdir()):
            if cdir.is_dir() and (cdir / "manifest.json").exists():
                if not sign_capability(cdir):
                    success = False
        sys.exit(0 if success else 1)
    else:
        target_dir = caps_base / target
        if not target_dir.exists() or not target_dir.is_dir():
            print(f"Error: Capability directory not found: {target_dir}")
            sys.exit(1)
        ok = sign_capability(target_dir)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
