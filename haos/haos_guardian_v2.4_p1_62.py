#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAOS Security Guardian Daemon v2.4.1 (Enterprise Hardened & Fail-Closed)
- P1-59: Precise ENOENT vs EACCES vs Symlink vs Modify Exception Handling
- P1-62.2: Hardened Trust Chain & Cryptographic Anti-Replay Nonce Engine
  1. Manifest HMAC Verification -> Extract guardian_hash -> Self-Integrity Check -> Immutable Core Check
  2. Fail-Closed if guardian_hash missing in Manifest
  3. Single-Use Replay Protection with persistent Nonce/Signature tracking in /var/lib/haos-guardian/
  4. Symlink rejection, Canonical JSON, HMAC-SHA256, TTL enforcement
- POSIX O_NOFOLLOW & Symlink Attack Defense
- Per-File Exception Isolation
- Deterministic Fail-Closed State Machine
"""

import os
import sys
import time
import hmac
import hashlib
import json
import glob
import tempfile
from datetime import datetime

class GuardianState:
    STARTING = "STARTING"
    UNINITIALIZED = "UNINITIALIZED"
    VERIFYING_SELF = "VERIFYING_SELF"
    VERIFYING_MANIFEST = "VERIFYING_MANIFEST"
    TRUSTED = "TRUSTED"
    VIOLATION = "VIOLATION"
    EMERGENCY_LOCK = "EMERGENCY_LOCK"

class GuardianV22:
    def __init__(self, 
                 haos_dir, 
                 snapshot_dir, 
                 approvals_dir, 
                 log_file, 
                 trust_root_key, 
                 self_script_path=None, 
                 expected_self_hash=None,
                 log_to_stdout=False):
        self.haos_dir = haos_dir
        self.snapshot_dir = snapshot_dir
        self.approvals_dir = approvals_dir
        self.log_file = log_file
        self.manifest_file = os.path.join(self.snapshot_dir, "manifest.json")
        self.manifest_sig_file = os.path.join(self.snapshot_dir, "manifest.sig")
        self.consumed_tokens_file = os.path.join(self.snapshot_dir, "consumed_tokens.json")
        self.trust_root_key = trust_root_key if isinstance(trust_root_key, bytes) else trust_root_key.encode("utf-8")
        self.self_script_path = self_script_path or os.path.realpath(__file__)
        self.expected_self_hash = expected_self_hash
        self.log_to_stdout = log_to_stdout
        self.state = GuardianState.STARTING
        self.events = []
        
        # P1-62.2: 載入已消耗 Token 之簽名與 Nonce 清冊（防重放引擎）
        self.consumed_signatures = self._load_consumed_tokens()
        
        self.immutable_files = [
            "00_Constitution.md",
            "01_Core.md",
            "02_Policy.md",
            "19_Config.md",
            "20_SecurityFilter.md",
            "27_SafetyPermission.md"
        ]

    def _load_consumed_tokens(self):
        """從受保護之 Snapshot 目錄載入已消耗 Token 之簽名雜湊"""
        if os.path.exists(self.consumed_tokens_file):
            try:
                with open(self.consumed_tokens_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return set(data)
            except Exception:
                pass
        return set()

    def _try_consume_token_atomic(self, signature):
        """以 fcntl.flock 進行跨程序/跨執行緒排他鎖定，原子檢查並消費 Token，根絕 TOCTOU Race Condition"""
        lock_file = self.consumed_tokens_file + ".lock"
        try:
            with open(lock_file, "w") as lock_f:
                import fcntl
                fcntl.flock(lock_f, fcntl.LOCK_EX)
                try:
                    current_set = self._load_consumed_tokens()
                    if signature in current_set:
                        return False
                    
                    current_set.add(signature)
                    self.consumed_signatures = current_set
                    
                    temp_f = self.consumed_tokens_file + ".tmp"
                    with open(temp_f, "w", encoding="utf-8") as f:
                        json.dump(list(current_set), f, ensure_ascii=False)
                    os.replace(temp_f, self.consumed_tokens_file)
                    return True
                finally:
                    fcntl.flock(lock_f, fcntl.LOCK_UN)
        except Exception:
            return False

    def log_event(self, event_type, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] [{event_type}] [STATE:{self.state}] {details}"
        self.events.append((event_type, details))
        if self.log_to_stdout:
            print(log_line, flush=True)
        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
        except Exception:
            pass

    @staticmethod
    def canonical_json(data):
        return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode("utf-8")

    def sign_payload(self, data_dict):
        """產生 HMAC-SHA256 簽名 (代表 Human Approval Signer)"""
        canonical = self.canonical_json(data_dict)
        return hmac.new(self.trust_root_key, canonical, hashlib.sha256).hexdigest()

    def verify_signature(self, data_dict, signature):
        """驗證簽名是否由持有 Trust Root Key 的 Human 簽署"""
        expected = self.sign_payload(data_dict)
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def get_file_hash_safe(filepath):
        """以 O_NOFOLLOW 安全讀取檔案並計算 SHA256，拒絕 Symlink。遭遇 PermissionError 顯式拋出。"""
        if os.path.islink(filepath):
            return None
        try:
            fd = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
            try:
                hasher = hashlib.sha256()
                while chunk := os.read(fd, 65536):
                    hasher.update(chunk)
                return hasher.hexdigest()
            finally:
                os.close(fd)
        except (FileNotFoundError,):
            return None
        except PermissionError:
            raise
        except (OSError, IOError) as e:
            if getattr(e, 'errno', None) == 13: # EACCES
                raise PermissionError(str(e))
            return None

    def verify_manifest(self):
        """
        信任鏈起點 (Trust Anchor Step 1):
        1. 驗證 Manifest 與分離簽名檔存在性
        2. 以 Trust Root Key 驗證 HMAC 簽名
        3. 驗證 guardian_hash 是否存在（若缺失則 Fail-Closed）
        4. 校驗所有快照檔案 Hash
        """
        if not os.path.exists(self.manifest_file) or not os.path.exists(self.manifest_sig_file):
            self.state = GuardianState.UNINITIALIZED
            self.log_event("MANIFEST_MISSING", "快照 Manifest 或簽名檔不存在，進入 UNINITIALIZED 狀態！")
            return False
        
        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            with open(self.manifest_sig_file, "r", encoding="utf-8") as f:
                sig_data = json.load(f)
            
            sig = sig_data.get("signature", "")
            if not self.verify_signature(manifest_data, sig):
                self.state = GuardianState.EMERGENCY_LOCK
                self.log_event("MANIFEST_SIGNATURE_INVALID", "Manifest 簽名無效！可能遭到惡意偽造。")
                return False
            
            # P1-62.2: 檢查 Manifest 內是否有 guardian_hash，無則 Fail-Closed
            if "guardian_hash" not in manifest_data or not manifest_data["guardian_hash"]:
                self.state = GuardianState.EMERGENCY_LOCK
                self.log_event("MANIFEST_GUARDIAN_HASH_MISSING", "Manifest 缺少 guardian_hash，違反信任鏈安全規範！進入 EMERGENCY_LOCK。")
                return False
            
            self.expected_self_hash = manifest_data["guardian_hash"]

            # 校驗 Manifest 內所有快照實體檔案
            for fname, expected_h in manifest_data.get("files", {}).items():
                snap_p = os.path.join(self.snapshot_dir, fname)
                snap_h = self.get_file_hash_safe(snap_p)
                if snap_h != expected_h:
                    self.state = GuardianState.EMERGENCY_LOCK
                    self.log_event("SNAPSHOT_TAMPER_DETECTED", f"快照檔案 {fname} 遭篡改！(Expected {expected_h}, got {snap_h})")
                    return False
            return True
        except Exception as e:
            self.state = GuardianState.EMERGENCY_LOCK
            self.log_event("MANIFEST_PARSE_ERROR", f"解析 Manifest 失敗: {e}")
            return False

    def verify_guardian_self_integrity(self):
        """
        信任鏈第二步 (Trust Anchor Step 2):
        以 Manifest 簽名信任之 expected_self_hash 校驗 Guardian 自身的完整性。
        """
        if not self.self_script_path or not self.expected_self_hash:
            self.state = GuardianState.EMERGENCY_LOCK
            self.log_event("SELF_INTEGRITY_CONFIG_ERROR", "缺少 self_script_path 或 expected_self_hash，進入 EMERGENCY_LOCK。")
            return False
        try:
            actual_hash = self.get_file_hash_safe(self.self_script_path)
            if actual_hash != self.expected_self_hash:
                self.state = GuardianState.EMERGENCY_LOCK
                self.log_event("SELF_TAMPER_DETECTED", f"Guardian 自身腳本遭篡改！(Expected {self.expected_self_hash}, got {actual_hash})")
                return False
        except PermissionError as e:
            self.state = GuardianState.EMERGENCY_LOCK
            self.log_event("SELF_INTEGRITY_ERROR", f"校驗 Guardian 自身完整性時權限不足: {e}")
            return False
        return True

    def check_unlock_token(self):
        """
        P1-62.2 強化型受控解鎖引擎 (Controlled Emergency Unlock Engine):
        1. 拒絕 Symlink
        2. 驗證 action == 'UNLOCK_EMERGENCY_LOCK'
        3. 驗證 expires_at > now (TTL)
        4. 驗證 HMAC 簽名
        5. 防重放：檢查 signature 是否曾被消費（雙重防禦：Memory + Persistent JSON）
        6. 驗證成功後記錄為已消耗，嘗試刪除實體檔案（若權限不足亦不影響防重放安全）
        7. 重設 state = STARTING 並重新由 Manifest 發起全量嚴格自檢
        """
        if not os.path.exists(self.approvals_dir):
            return False
        token_files = glob.glob(os.path.join(self.approvals_dir, "UNLOCK-*.json"))
        now = time.time()
        for tf in token_files:
            try:
                if os.path.islink(tf):
                    self.log_event("SECURITY_ALERT", f"解鎖 Token {tf} 為 Symlink，拒絕處理！")
                    continue
                with open(tf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                if data.get("action") == "UNLOCK_EMERGENCY_LOCK":
                    sig = data.get("signature", "")
                    if not sig:
                        self.log_event("TOKEN_INVALID", f"解鎖 Token {os.path.basename(tf)} 缺少簽名。")
                        continue

                    exp = data.get("expires_at", 0)
                    if exp <= now:
                        self.log_event("TOKEN_EXPIRED", f"解鎖 Token {os.path.basename(tf)} 已過期。")
                        continue
                    
                    payload = {k: v for k, v in data.items() if k != "signature"}
                    if not self.verify_signature(payload, sig):
                        self.log_event("TOKEN_SIGNATURE_INVALID", f"解鎖 Token {os.path.basename(tf)} 簽名無效！")
                        continue
                    
                    # 原子防重放檢查與消耗（透過 flock 排他鎖）
                    if not self._try_consume_token_atomic(sig):
                        self.log_event("TOKEN_REPLAY_BLOCKED", f"偵測到重複使用已消耗之解鎖 Token ({os.path.basename(tf)})！拒絕重放。")
                        continue

                    # 嘗試移除實體檔案
                    try:
                        os.remove(tf)
                    except Exception:
                        pass
                    
                    self.log_event("EMERGENCY_LOCK_UNLOCKED", f"收到合法 Human Signed 解鎖 Token ({os.path.basename(tf)})，解除鎖定並重啟全量驗證。")
                    self.state = GuardianState.STARTING
                    return True
            except Exception as e:
                self.log_event("TOKEN_ERROR", f"解析解鎖 Token {tf} 失敗: {e}")
        return False

    def get_valid_approval_token(self, target_file, current_hash):
        """
        嚴格審批 Token 比對：
        1. 拒絕 target_file == 'ALL'
        2. 驗證 schema 完整性
        3. 驗證 signature 必須符合 Trust Root 密鑰
        4. 驗證 expires_at > now
        5. 驗證 approved_content_hash == current_hash
        6. 防重放檢查
        """
        if not os.path.exists(self.approvals_dir):
            return None
        token_files = glob.glob(os.path.join(self.approvals_dir, "APPROVE-*.json"))
        now = time.time()
        for tf in token_files:
            try:
                if os.path.islink(tf):
                    self.log_event("SECURITY_ALERT", f"Token {tf} 為 Symlink，拒絕處理！")
                    continue
                with open(tf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                if data.get("target_file") == "ALL":
                    self.log_event("SECURITY_ALERT", f"偵測到非法的萬用 Token ({os.path.basename(tf)})，拒絕受理！")
                    continue
                
                if data.get("target_file") == target_file:
                    sig = data.get("signature", "")
                    if not sig or sig in self.consumed_signatures:
                        continue

                    exp = data.get("expires_at", 0)
                    if exp <= now:
                        self.log_event("TOKEN_EXPIRED", f"Token {os.path.basename(tf)} 已過期。")
                        continue
                    
                    payload = {k: v for k, v in data.items() if k != "signature"}
                    if not self.verify_signature(payload, sig):
                        self.log_event("TOKEN_SIGNATURE_INVALID", f"Token {os.path.basename(tf)} 簽名無效（非 Human 簽發）！")
                        continue
                    
                    approved_h = data.get("approved_content_hash", "")
                    if approved_h != current_hash:
                        self.log_event("TOKEN_HASH_MISMATCH", f"Token {os.path.basename(tf)} 指定 Hash ({approved_h}) 與 Current ({current_hash}) 不符！")
                        continue
                    
                    if not self._try_consume_token_atomic(sig):
                        self.log_event("TOKEN_REPLAY_BLOCKED", f"偵測到重複使用已消耗之 Token ({os.path.basename(tf)})！拒絕重放。")
                        continue

                    try:
                        os.remove(tf)
                    except Exception:
                        pass
                    return data
            except Exception as e:
                self.log_event("TOKEN_ERROR", f"解析 Token {tf} 失敗: {e}")
        return None

    def safe_atomic_copy(self, src_path, dst_path, expected_hash=None, target_mode=0o444):
        """
        POSIX 安全原子複製：
        1. 以 O_NOFOLLOW 開啟讀取 source bytes
        2. 比對 expected_hash
        3. 寫入同目錄下 tempfile
        4. 驗證 tempfile 寫入完整性
        5. os.replace 原子覆蓋
        """
        if os.path.islink(src_path):
            raise ValueError(f"Source file is symlink: {src_path}")
        
        try:
            fd_src = os.open(src_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
        except FileNotFoundError:
            raise ValueError(f"Source file missing: {src_path}")
        except PermissionError:
            raise
        except OSError as e:
            if getattr(e, 'errno', None) == 13:
                raise PermissionError(str(e))
            raise

        try:
            content = os.read(fd_src, 10 * 1024 * 1024)
        finally:
            os.close(fd_src)
        
        src_hash = hashlib.sha256(content).hexdigest()
        if expected_hash and src_hash != expected_hash:
            raise ValueError(f"TOCTOU_VIOLATION: Source hash {src_hash} != Expected {expected_hash}")
        
        dst_dir = os.path.dirname(dst_path)
        os.makedirs(dst_dir, exist_ok=True)
        fd_tmp, tmp_file = tempfile.mkstemp(dir=dst_dir, prefix=".atomic_tmp_")
        try:
            with os.fdopen(fd_tmp, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            
            with open(tmp_file, "rb") as f:
                written_hash = hashlib.sha256(f.read()).hexdigest()
            if written_hash != src_hash:
                raise IOError(f"Write corruption in {tmp_file}")
            
            os.replace(tmp_file, dst_path)
            try:
                os.chmod(dst_path, target_mode)
            except Exception:
                pass
        except Exception:
            if os.path.exists(tmp_file):
                try: os.remove(tmp_file)
                except Exception: pass
            raise

    def update_snapshot_and_manifest(self, fname, new_bytes_hash):
        """合法審批後，原子更新快照並重新產生簽名 Manifest"""
        src = os.path.join(self.haos_dir, fname)
        snap = os.path.join(self.snapshot_dir, fname)
        self.safe_atomic_copy(src, snap, expected_hash=new_bytes_hash, target_mode=0o400)
        
        files_map = {}
        for f in self.immutable_files:
            sp = os.path.join(self.snapshot_dir, f)
            h = self.get_file_hash_safe(sp)
            if h:
                files_map[f] = h
        
        manifest_payload = {
            "version": 1,
            "updated_at": int(time.time()),
            "files": files_map
        }
        if self.expected_self_hash:
            manifest_payload["guardian_hash"] = self.expected_self_hash
            
        sig = self.sign_payload(manifest_payload)
        
        with open(self.manifest_file + ".tmp", "w", encoding="utf-8") as f:
            json.dump(manifest_payload, f, indent=2, ensure_ascii=False)
        with open(self.manifest_sig_file + ".tmp", "w", encoding="utf-8") as f:
            json.dump({"signature": sig}, f, indent=2)
        
        os.replace(self.manifest_file + ".tmp", self.manifest_file)
        os.replace(self.manifest_sig_file + ".tmp", self.manifest_sig_file)
        self.log_event("MANIFEST_UPDATED", f"已更新 {fname} 快照與 Manifest 簽名。")

    def check_and_enforce_file(self, fname):
        """單檔隔離執法流程：P1-59 精確分流 ENOENT (刪除)、EACCES (權限拒絕)、Symlink 與修改"""
        src = os.path.join(self.haos_dir, fname)
        snap = os.path.join(self.snapshot_dir, fname)

        # 1. 檢查 Current 狀態（以 lstat 精確判定）
        try:
            st = os.lstat(src)
            if os.path.islink(src):
                self.log_event("VIOLATION_SYMLINK", f"偵測到核心檔案 {fname} 被置換為非法 Symlink！觸發 Rollback。")
                if os.path.exists(snap):
                    snap_hash = self.get_file_hash_safe(snap)
                    self.safe_atomic_copy(snap, src, expected_hash=snap_hash, target_mode=0o444)
                    self.log_event("ROLLBACK_SUCCESS", f"已由快照成功還原 {fname}。")
                else:
                    self.state = GuardianState.EMERGENCY_LOCK
                    self.log_event("CRITICAL_ERROR", f"快照缺失，無法還原 {fname}！進入 EMERGENCY_LOCK。")
                return
        except FileNotFoundError:
            # 確鑿為真實檔案被刪除 (ENOENT)
            self.log_event("VIOLATION_DELETE", f"偵測到核心檔案 {fname} 實體不存在！觸發 Rollback。")
            if os.path.exists(snap):
                snap_hash = self.get_file_hash_safe(snap)
                self.safe_atomic_copy(snap, src, expected_hash=snap_hash, target_mode=0o444)
                self.log_event("ROLLBACK_SUCCESS", f"已由快照成功還原 {fname}。")
            else:
                self.state = GuardianState.EMERGENCY_LOCK
                self.log_event("CRITICAL_ERROR", f"快照缺失，無法還原 {fname}！進入 EMERGENCY_LOCK。")
            return
        except PermissionError as e:
            # 權限拒絕 (EACCES)：絕對禁止 Rollback！進入 EMERGENCY_LOCK
            self.state = GuardianState.EMERGENCY_LOCK
            self.log_event("PERMISSION_ERROR", f"存取核心檔案 {fname} 權限不足 (EACCES): {e}。鎖定狀態，禁止覆蓋！")
            return
        except OSError as e:
            if getattr(e, 'errno', None) == 13: # EACCES
                self.state = GuardianState.EMERGENCY_LOCK
                self.log_event("PERMISSION_ERROR", f"存取核心檔案 {fname} 權限不足 (EACCES): {e}。鎖定狀態，禁止覆蓋！")
                return
            self.state = GuardianState.EMERGENCY_LOCK
            self.log_event("OS_ERROR", f"檢查核心檔案 {fname} 遭遇底層系統異常: {e}。進入 EMERGENCY_LOCK。")
            return

        # 2. 實體存在且非 Symlink，進行 Hash 與授權比對
        if os.path.exists(snap):
            try:
                src_hash = self.get_file_hash_safe(src)
                snap_hash = self.get_file_hash_safe(snap)
            except PermissionError as e:
                self.state = GuardianState.EMERGENCY_LOCK
                self.log_event("PERMISSION_ERROR", f"計算 {fname} 雜湊時權限不足: {e}。鎖定狀態，禁止覆蓋！")
                return

            if src_hash != snap_hash:
                token = self.get_valid_approval_token(fname, src_hash)
                if token:
                    self.update_snapshot_and_manifest(fname, src_hash)
                    self.log_event("AUTHORIZED_CHANGE", f"{fname} 具備合法 Human Signed Token，已更新安全快照與 Manifest。")
                else:
                    self.log_event("VIOLATION_MODIFY", f"偵測到非授權修改 {fname}！即時強制 Rollback。")
                    self.safe_atomic_copy(snap, src, expected_hash=snap_hash, target_mode=0o444)
                    self.log_event("ROLLBACK_SUCCESS", f"已強制還原 {fname} 為快照基準。")

    def check_and_enforce_all(self):
        """
        P1-62.2 嚴格信任鏈循環 (Deterministic Trust Chain Flow):
        Step 0: 若處於 EMERGENCY_LOCK，檢查解鎖 Token
        Step 1: 驗證 Manifest 簽名並萃取 guardian_hash (Trust Anchor)
        Step 2: 驗證 Guardian 自身完整性 (Self-Integrity Check)
        Step 3: 走訪校驗 6 個 Immutable Core 檔案
        """
        # Step 0: 解鎖檢查
        if self.state == GuardianState.EMERGENCY_LOCK:
            if not self.check_unlock_token():
                return False

        # Step 1: Manifest 簽名與快照信任根校驗
        if not self.verify_manifest():
            return False
        
        # Step 2: 自身完整性校驗
        if not self.verify_guardian_self_integrity():
            return False
        
        # Step 3: 核心檔案執法
        has_error = False
        for fname in self.immutable_files:
            try:
                self.check_and_enforce_file(fname)
            except Exception as e:
                has_error = True
                self.log_event("PER_FILE_ERROR", f"執法檔案 {fname} 失敗: {e}")
        
        if not has_error and self.state not in [GuardianState.EMERGENCY_LOCK, GuardianState.UNINITIALIZED]:
            self.state = GuardianState.TRUSTED
        return True

def main():
    key_path = "/etc/haos/guardian.key"
    if not os.path.exists(key_path):
        print(f"CRITICAL: Key {key_path} missing!", file=sys.stderr)
        sys.exit(1)
    
    with open(key_path, "rb") as f:
        key = f.read().strip()
    
    self_path = "/usr/local/libexec/haos/haos_guardian.py"
    
    guardian = GuardianV22(
        haos_dir="${HERMES_HOME}/haos",
        snapshot_dir="/var/lib/haos-guardian/snapshots",
        approvals_dir="${HERMES_HOME}/approvals",
        log_file="${HERMES_HOME}/logs/haos_security.log",
        trust_root_key=key,
        self_script_path=self_path,
        log_to_stdout=True
    )
    
    guardian.log_event("GUARDIAN_START", "HAOS Guardian v2.4.1 Enterprise Daemon 正式啟動監控。")
    while True:
        try:
            guardian.check_and_enforce_all()
        except Exception as e:
            guardian.log_event("LOOP_EXCEPTION", f"守護迴圈異常: {e}")
        time.sleep(1)

if __name__ == "__main__":
    main()
