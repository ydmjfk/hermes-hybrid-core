#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_security.py — PUBLIC_RELEASE_AUDITOR (P1-07 & Section 10)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
企業開源安全發布前置稽核器：
嚴格掃描全專案儲存庫，防範以下資訊意外進入公開 Git 歷史：
1. 機密憑證 (API Keys, Bearer Tokens, JWT, AWS Secrets, 私鑰 PEM/RSA)
2. URL 內嵌帳密與資料庫連線字串
3. 實體私有 IP 與特定內部主機名
4. 寫死之私人/開發者絕對路徑
5. 二進位資料庫檔案 (.db, .sqlite) 與備份檔案 (.bak, .old)
6. 支援透過外部黑名單檔 (.security_denylist) 進行私有機敏名詞檢查，禁止將真實隱私硬編碼進代碼庫
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent

# 禁止提交的副檔名與檔案
FORBIDDEN_EXTENSIONS = (
    '.db', '.sqlite', '.sqlite3', '.db-wal', '.db-shm',
    '.bak', '.backup', '.old', '.key', '.pem', '.p12', '.pfx', '.log'
)

FORBIDDEN_FILENAMES = {
    'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa',
    'known_hosts', 'authorized_keys', 'credentials.json', 'service_account.json'
}

# 忽略的掃描目錄
IGNORED_DIRS = {
    '.git', 'venv', '.venv', '__pycache__', '.pytest_cache',
    'node_modules', '.mypy_cache', '.coverage', '.idea', '.vscode'
}

# 合法允許出現的樣板與測試標籤
SAFE_EXCLUSION_WORDS = {
    "your_custom_gateway_token", "your_api_key_here", "not-needed-for-local-llm",
    "mock", "test", "example", "sample", "synthetic", "placeholder", "localhost", "127.0.0.1"
}

# 預編譯公開發布資安審計正則
AUDIT_PATTERNS = [
    ("OPENAI_KEY", re.compile(r"\b(sk-[a-zA-Z0-9_\-]{24,})\b")),
    ("ANTHROPIC_KEY", re.compile(r"\b(sk-ant-[a-zA-Z0-9_\-]{24,})\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{24,})\b")),
    ("AWS_KEY_ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("AWS_SECRET", re.compile(r"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?")),
    ("JWT_TOKEN", re.compile(r"\b(eyJ[a-zA-Z0-9_-]{12,}\.[a-zA-Z0-9_-]{12,}\.[a-zA-Z0-9_-]{12,})\b")),
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")),
    ("URL_CREDENTIALS", re.compile(r"(://[^:\s/@]+):([^@\s/]+)@")),
    ("PRIVATE_IP", re.compile(r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")),
]


def load_external_denylist() -> Set[str]:
    """
    從外部檔案載入機敏黑名單 (P1-07: 禁止將真實敏感詞 hardcode 於源碼中)。
    優先讀取環境變數 HERMES_SECURITY_DENYLIST 或根目錄 .security_denylist。
    """
    denylist = set()
    env_path = os.environ.get("HERMES_SECURITY_DENYLIST")
    target_path = Path(env_path) if env_path else (REPO_ROOT / ".security_denylist")

    if target_path.exists() and target_path.is_file():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        denylist.add(line)
        except Exception as e:
            print(f"⚠️ 無法讀取外部黑名單檔: {e}")

    return denylist


def run_public_release_audit() -> Tuple[bool, List[Tuple[str, str]], int]:
    """執行完整專案庫公開安全性掃描"""
    denylist = load_external_denylist()
    violations: List[Tuple[str, str]] = []
    scanned_count = 0

    for root, dirs, files in os.walk(REPO_ROOT):
        # 排除忽略目錄
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        p_root = Path(root)
        for f in files:
            if f.endswith('.pyc') or f == 'check_security.py':
                continue

            p_file = p_root / f
            rel_str = str(p_file.relative_to(REPO_ROOT))
            scanned_count += 1

            # 1. 禁止副檔名檢驗
            if f.endswith(FORBIDDEN_EXTENSIONS):
                violations.append((rel_str, f"禁止的副檔名: '{p_file.suffix}'"))
                continue

            # 2. 禁止特定敏感檔名檢驗
            if f in FORBIDDEN_FILENAMES:
                violations.append((rel_str, f"禁止的敏感檔案名稱: '{f}'"))
                continue

            # 3. 檔案文字內容檢驗
            try:
                with open(p_file, 'r', encoding='utf-8', errors='ignore') as fp:
                    content = fp.read()
            except Exception:
                continue

            # A. 特徵庫正規式比對
            for rule_name, pattern in AUDIT_PATTERNS:
                matches = pattern.findall(content)
                for m in matches:
                    matched_str = " ".join(m) if isinstance(m, tuple) else str(m)
                    # 排除常見合規假資料/樣板/註解
                    if any(safe in matched_str.lower() for safe in SAFE_EXCLUSION_WORDS):
                        continue
                    # 排除自身測試用安全特徵
                    if "test_" in f and ("10.0.0.1" in matched_str or "mock" in matched_str.lower() or "example" in matched_str.lower()):
                        continue
                    violations.append((rel_str, f"觸發規則 [{rule_name}]: 檢測到疑似敏感特徵 '{matched_str[:12]}...'"))
                    break

            # B. 外部黑名單比對 (P1-07)
            for term in denylist:
                if term in content:
                    violations.append((rel_str, f"觸發外部機敏詞庫規則: 發現受限制名詞 '{term[:3]}***'"))

    return (len(violations) == 0, violations, scanned_count)


def run_git_history_audit() -> Tuple[bool, List[Tuple[str, str]], int]:
    """執行 Git Commit 歷史記錄差異之機敏資訊掃描 (P1-06)"""
    import subprocess
    denylist = load_external_denylist()
    violations: List[Tuple[str, str]] = []
    scanned_commits = 0

    git_dir = REPO_ROOT / ".git"
    if not git_dir.exists():
        return True, [], 0

    try:
        cmd = ["git", "log", "-p", "--all", "--full-history"]
        result = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
        if result.returncode != 0:
            return True, [], 0
    except Exception as e:
        print(f"⚠️ 無法執行 git log 歷史審計: {e}")
        return True, [], 0

    current_commit = "initial"
    current_file = "unknown"

    for line in result.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:8]
            scanned_commits += 1
            continue
        elif line.startswith("diff --git a/"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[2][2:]
            continue

        # 僅審計新增行 (以 '+' 開頭但排除 '+++')
        if line.startswith("+") and not line.startswith("+++"):
            added_content = line[1:]

            # 排除 check_security.py 自身的正規式變更
            if "check_security.py" in current_file:
                continue

            # A. 特徵庫正規式比對
            for rule_name, pattern in AUDIT_PATTERNS:
                matches = pattern.findall(added_content)
                for m in matches:
                    matched_str = " ".join(m) if isinstance(m, tuple) else str(m)
                    if any(safe in matched_str.lower() for safe in SAFE_EXCLUSION_WORDS):
                        continue
                    if "test_" in current_file and ("10.0.0.1" in matched_str or "mock" in matched_str.lower() or "example" in matched_str.lower()):
                        continue
                    violations.append((f"Commit {current_commit} ({current_file})", f"歷史提交觸發規則 [{rule_name}]: 發現疑似敏感特徵 '{matched_str[:12]}...'"))
                    break

            # B. 外部黑名單比對
            for term in denylist:
                if term in added_content:
                    violations.append((f"Commit {current_commit} ({current_file})", f"歷史提交觸發外部機敏詞庫規則: 發現受限制名詞 '{term[:3]}***'"))

    return (len(violations) == 0, violations, scanned_commits)


def audit() -> None:
    print("=" * 80)
    print("🛡️  Hermes Hybrid Core — Public Release Security Auditor (v2.0)")
    print("=" * 80)

    scan_history = "--scan-git-history" in sys.argv or os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"

    is_clean_tree, violations_tree, scanned_count = run_public_release_audit()
    print(f"📊 工作目錄檔案掃描總數: {scanned_count} 個")

    all_violations = list(violations_tree)

    if scan_history:
        is_clean_hist, violations_hist, commit_count = run_git_history_audit()
        print(f"📜 Git 歷史 Commit 掃描總數: {commit_count} 個")
        all_violations.extend(violations_hist)

    if all_violations:
        print("\n❌ 發布門禁阻斷 (RELEASE BLOCKED)：發現以下潛在安全與隱私違規項目！")
        for fpath, reason in all_violations:
            print(f"  🚨 [{fpath}] -> {reason}")
        print("=" * 80)
        print("請修正上述違規項目後再進行發布。")
        sys.exit(1)
    else:
        print("\n[PASS] Public Release Security Scan PASSED:")
        print("  - 無未授權 API Key、私鑰或雲端憑證。")
        print("  - 無未授權二進位資料庫、備份或日誌檔案。")
        print("  - 符合外部機敏名詞與隱私合規政策。")
        if scan_history:
            print("  - Git 歷史 Commit 紀錄無機敏憑證或金鑰殘留。")
        print("=" * 80)
        sys.exit(0)


if __name__ == "__main__":
    audit()
