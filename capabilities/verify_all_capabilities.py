#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hermes Capability Lab: Master Capability Health & Compatibility Verification Suite
===================================================================================
Automatically executes pre-flight health validators across all promoted capabilities
in ~/.hermes/capabilities/ to ensure 100% operational readiness and 0 regression.
"""

import sys
import json
import time
import hashlib
import importlib.util
from pathlib import Path

CAPABILITIES_DIR = Path(__file__).resolve().parent
REPO_ROOT = CAPABILITIES_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def verify_all_capabilities():
    print("=" * 88)
    print("🏛️  HERMES MASTER CAPABILITY LIBRARY: 6 大核心外掛能力全域健康度總驗收")
    print("=" * 88)

    results = []
    total_latency_ms = 0.0
    all_healthy = True

    for cap_dir in sorted(CAPABILITIES_DIR.iterdir()):
        if not cap_dir.is_dir() or cap_dir.name.startswith("."):
            continue

        manifest_path = cap_dir / "manifest.json"
        validator_path = cap_dir / "validator.py"

        if not manifest_path.exists():
            continue

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        cap_id = manifest.get("capability_id", cap_dir.name)
        cap_name = manifest.get("name", cap_dir.name)
        version = manifest.get("version", "1.0.0")

        # Pre-Execution Integrity & Trust Gate (P1-05)
        start_t = time.perf_counter()
        is_healthy = False
        diag_msg = "Unknown status"

        # 1. 驗證 manifest 完整性與授權狀態
        integrity = manifest.get("integrity", {})
        trust = manifest.get("trust", {})
        files_map = integrity.get("files", {})

        if integrity.get("algorithm") != "sha256" or not files_map:
            is_healthy = False
            diag_msg = "Security Blocked: 缺少或無效的 SHA-256 完整性宣告"
        elif not trust.get("approved"):
            is_healthy = False
            diag_msg = "Security Blocked: 未獲得授權 (trust.approved != true)"
        else:
            # 檢查各檔案 Hash
            hash_ok = True
            for rel_file, expected_hash in files_map.items():
                target_file = cap_dir / rel_file
                if not target_file.exists():
                    is_healthy = False
                    diag_msg = f"Security Blocked: 缺少完整性校驗檔案 '{rel_file}'"
                    hash_ok = False
                    break
                hasher = hashlib.sha256()
                with open(target_file, "rb") as fp:
                    while chunk := fp.read(65536):
                        hasher.update(chunk)
                if hasher.hexdigest() != expected_hash:
                    is_healthy = False
                    diag_msg = f"Security Blocked: 檔案 Hash 不相符 '{rel_file}'"
                    hash_ok = False
                    break

            # 驗證獨立密碼學信任根數位簽章 (P0-03)
            if hash_ok:
                sig_hex = trust.get("signature")
                try:
                    from hermes_core.trust_root import verify_capability_signature
                    is_sig_valid, sig_msg = verify_capability_signature(
                        capability_id=cap_id,
                        version=version,
                        files_map=files_map,
                        signature_hex=sig_hex
                    )
                except Exception as e:
                    is_sig_valid, sig_msg = False, f"Trust root check exception: {e}"

                if not is_sig_valid:
                    is_healthy = False
                    diag_msg = f"Security Blocked: 密碼學簽章驗證失敗 ({sig_msg})"
                    hash_ok = False

            # 2. 只有前置安全門禁全部 PASS，才允許載入並執行 validator.py
            if hash_ok:
                if validator_path.exists():
                    parent_dir = str(cap_dir)
                    added_path = False
                    if parent_dir not in sys.path:
                        sys.path.insert(0, parent_dir)
                        added_path = True

                    try:
                        spec = importlib.util.spec_from_file_location(f"val_{cap_name}", str(validator_path))
                        val_mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(val_mod)
                        if hasattr(val_mod, "validate_capability"):
                            is_healthy, diag_msg = val_mod.validate_capability()
                        else:
                            is_healthy = True
                            diag_msg = "Implicit PASS"
                    except Exception as e:
                        is_healthy = False
                        diag_msg = f"Validator Exception: {e}"
                    finally:
                        if added_path and parent_dir in sys.path:
                            sys.path.remove(parent_dir)
                else:
                    is_healthy = False
                    diag_msg = "No validator.py found"

        elapsed_ms = (time.perf_counter() - start_t) * 1000
        total_latency_ms += elapsed_ms

        if not is_healthy:
            all_healthy = False

        status_tag = "✅ PASS" if is_healthy else "❌ FAIL"
        results.append({
            "cap_id": cap_id,
            "name": cap_name,
            "version": version,
            "status": status_tag,
            "latency_ms": round(elapsed_ms, 2),
            "message": diag_msg
        })

        print(f"[{cap_id:30s}] {cap_name:22s} ｜ 耗時: {elapsed_ms:5.2f}ms ｜ 狀態: {status_tag} ｜ 說明: {diag_msg[:35]}")

    passed_count = sum(1 for r in results if "PASS" in r["status"])
    print("=" * 88)
    print("📊 全庫驗收總結：")
    print(f"  - 驗收能力總數：{passed_count} / {len(results)} PASS (健全度 {(passed_count/len(results)*100):.1f}%)")
    print(f"  - 6 大能力總驗收診斷耗時：{total_latency_ms:.2f} ms")
    print("=" * 88)

    return all_healthy, results


if __name__ == "__main__":
    ok, _ = verify_all_capabilities()
    sys.exit(0 if ok else 1)
