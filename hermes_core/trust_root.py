#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hermes_core/trust_root.py — Cryptographic Capability Trust Root & Signature Verifier (P0-03)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
實作具備獨立密碼學根信任之外掛能力簽章驗證機制。
解耦「批准機構」與「可變代碼庫」：
- 透過 Ed25519 非對稱數位簽章驗證 manifest.json 中的 trust.signature
- 簽章內容強制綁定正規化摘要：SHA256(capability_id:version:file1=hash1|file2=hash2)
- 任何代碼或 manifest 內容變更，若無 Release Authority 私鑰簽署，即刻觸發安全隔離 (Quarantine)
"""

import hashlib
import os
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

TRUST_ROOT_DIR = Path(__file__).resolve().parent / "trust_root"
DEFAULT_PUBKEY_FILE = TRUST_ROOT_DIR / "release_authority.pub"

# 內建官方 Release Authority 根公鑰 (Ed25519 Raw 32-bytes Hex)
# 可透過環境變數 HERMES_TRUST_ROOT_PUBKEY 覆寫以自訂企業內部信任根
BUILTIN_RELEASE_AUTHORITY_PUBKEY_HEX = (
    "a50e72a59f0f95217cb1ca8420ec9eb2d2db68051339d27953cbccf513567f7b"
)


def compute_canonical_digest(
    capability_id: str,
    version: str,
    files_map: Dict[str, str]
) -> bytes:
    """
    計算 Capability 結構之唯一正規化摘要 (Deterministic Canonical Digest)。
    排序所有檔案雜湊，確保比對具備唯一確定性。
    """
    sorted_pairs = [f"{fname}={files_map[fname]}" for fname in sorted(files_map.keys())]
    canonical_payload = f"{capability_id.strip()}:{version.strip()}:" + "|".join(sorted_pairs)
    return hashlib.sha256(canonical_payload.encode("utf-8")).digest()


def load_trust_root_pubkey() -> bytes:
    """
    載入當前受信任的 Release Authority 公鑰 (32 bytes)。
    依序優先權：
    1. 環境變數 HERMES_TRUST_ROOT_PUBKEY (可傳 hex 字串或檔案路徑)
    2. 本地檔案 hermes_core/trust_root/release_authority.pub
    3. 內建常數 BUILTIN_RELEASE_AUTHORITY_PUBKEY_HEX
    """
    env_key = os.environ.get("HERMES_TRUST_ROOT_PUBKEY")
    if env_key:
        env_path = Path(env_key).expanduser()
        if env_path.exists() and env_path.is_file():
            key_text = env_path.read_text(encoding="utf-8").strip()
            return bytes.fromhex(key_text)
        try:
            return bytes.fromhex(env_key.strip())
        except ValueError:
            pass

    if DEFAULT_PUBKEY_FILE.exists() and DEFAULT_PUBKEY_FILE.is_file():
        try:
            key_text = DEFAULT_PUBKEY_FILE.read_text(encoding="utf-8").strip()
            return bytes.fromhex(key_text)
        except Exception:
            pass

    return bytes.fromhex(BUILTIN_RELEASE_AUTHORITY_PUBKEY_HEX)


def verify_capability_signature(
    capability_id: str,
    version: str,
    files_map: Dict[str, str],
    signature_hex: str,
    public_key_bytes: Optional[bytes] = None
) -> Tuple[bool, str]:
    """
    以 Release Authority 公鑰驗證能力模組簽章 (P0-03)。
    回傳: (is_valid: bool, reason: str)
    """
    if not HAS_CRYPTOGRAPHY:
        return False, "環境未安裝 cryptography 套件，無法執行 Ed25519 數位簽章驗證"

    if not signature_hex or not isinstance(signature_hex, str):
        return False, "缺少簽章 (manifest.trust.signature is missing)"

    try:
        sig_bytes = bytes.fromhex(signature_hex.strip())
        if len(sig_bytes) != 64:
            return False, f"無效簽章長度: 預期 64 bytes，實際為 {len(sig_bytes)} bytes"
    except ValueError:
        return False, "簽章格式錯誤：非有效 16 進位字串"

    if public_key_bytes is None:
        public_key_bytes = load_trust_root_pubkey()

    if len(public_key_bytes) != 32:
        return False, f"無效信任根公鑰長度: 預期 32 bytes，實際為 {len(public_key_bytes)} bytes"

    digest = compute_canonical_digest(capability_id, version, files_map)

    try:
        pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key_obj.verify(sig_bytes, digest)
        return True, "Cryptographic signature verified successfully"
    except InvalidSignature:
        return False, "數位簽章驗證失敗：代碼雜湊或 Manifest 資訊與簽署內容不符"
    except Exception as e:
        return False, f"簽章驗證異常: {e}"


def sign_capability_digest(
    private_key_bytes: bytes,
    capability_id: str,
    version: str,
    files_map: Dict[str, str]
) -> str:
    """
    [僅供 Release Authority 發布建置時使用]
    使用私鑰簽署 Capability Canonical Digest，回傳 128 字元 hex 簽章。
    """
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography package required for signing")
    priv_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    digest = compute_canonical_digest(capability_id, version, files_map)
    signature = priv_key_obj.sign(digest)
    return signature.hex()
