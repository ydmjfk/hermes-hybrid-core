#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_security_governance.py — 企業級安全審計與回歸驗證套件
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
測試覆蓋：
1. 目錄穿越與沙盒邊界逃逸防護 (Path Traversal & Sandbox Escape)
2. SQL 注入與多語句堆疊攔截 (SQL Injection & Multi-statement Stacking)
3. 正則表達式 ReDoS 線性耗時壓力測試 (ReDoS Mitigation)
4. 機密與憑證自動脫敏驗證 (Secret Redaction Filter)
5. 證據日誌與帳本抗洩漏審計 (Evidence Logger Zero-Leakage)
"""

import os
import sys
import time
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hermes_core.path_sanitizer import (
    PathSanitizer,
    PathSanitizerError,
    sanitize_path,
    is_safe_path,
    PathTraversalError,
    SensitivePathBlockedError,
)
from hermes_core.security_filter import (
    sanitize_secrets,
    sanitize_dict,
    contains_secrets,
    mask_secret_string,
)
from hermes_core.db_pool import execute_query, get_db_connection
from hermes_core.evidence_logger import log_event, record_evidence
from hermes_core.config_loader import get_db_path, get_env_var, get_secret, is_sensitive_key, check_file_permissions
from hermes_core.circuit_breaker import record_negative_cache, check_negative_cache, clear_negative_cache
from agent.fast_path import CommandSideEffectAnalyzer, FastPathClassifier, FastPathTier, ActionKind


class TestSecurityGovernance(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.test_dir.name).resolve()
        self.sanitizer = PathSanitizer(workspace_root=self.workspace)

        # 建立一個測試用安全檔案
        (self.workspace / "safe_file.txt").write_text("safe content", encoding="utf-8")
        (self.workspace / "sub_dir").mkdir(exist_ok=True)
        (self.workspace / "sub_dir" / "nested.txt").write_text("nested content", encoding="utf-8")

    def tearDown(self):
        self.test_dir.cleanup()

    # ==========================================================================
    # 1. 目錄穿越與沙盒邊界測試 (Path Traversal & Sandbox Escape)
    # ==========================================================================
    def test_path_sanitizer_normal_access(self):
        """合法路徑應順利通過並回傳規範絕對路徑"""
        res = self.sanitizer.sanitize_path("safe_file.txt")
        self.assertEqual(res, self.workspace / "safe_file.txt")

        res_nested = self.sanitizer.sanitize_path("sub_dir/nested.txt")
        self.assertEqual(res_nested, self.workspace / "sub_dir" / "nested.txt")

    def test_path_traversal_parent_escape(self):
        """嘗試使用 '../' 逃逸出工作區必須被物理攔截"""
        with self.assertRaises(PathSanitizerError):
            self.sanitizer.sanitize_path("../../etc/passwd")

        with self.assertRaises(PathTraversalError):
            self.sanitizer.sanitize_path("sub_dir/../../outside.txt")

    def test_path_traversal_absolute_escape(self):
        """傳入外部絕對路徑必須被阻斷"""
        with self.assertRaises(SensitivePathBlockedError):
            self.sanitizer.sanitize_path("/etc/shadow")

        with self.assertRaises(PathTraversalError):
            self.sanitizer.sanitize_path("/var/log/syslog")

    def test_path_traversal_null_byte(self):
        """空位元組注入攻擊 (%00 / \\x00) 必須被阻斷"""
        with self.assertRaises(PathTraversalError):
            self.sanitizer.sanitize_path("safe_file.txt\x00.exe")

        with self.assertRaises(PathTraversalError):
            self.sanitizer.sanitize_path("safe_file.txt%00.php")

    def test_path_traversal_url_encoded(self):
        """URL 編碼繞過 (%2e%2e/etc/passwd) 必須被解碼並阻斷"""
        with self.assertRaises(PathSanitizerError):
            self.sanitizer.sanitize_path("%2e%2e/%2e%2e/etc/passwd")

    def test_path_traversal_symlink_escape(self):
        """嘗試透過符號連結指向工作區外部檔案必須被阻斷"""
        symlink_path = self.workspace / "symlink_to_root"
        try:
            os.symlink("/etc/passwd", symlink_path)
            with self.assertRaises(PathSanitizerError):
                self.sanitizer.sanitize_path(symlink_path)
        except OSError:
            pass  # 在無符號連結權限環境跳過

    def test_path_sanitizer_sensitive_blacklist(self):
        """即使在工作區內部，高敏感目標 (如 .ssh, .env, .kube, .pem, .key, .vscode, Dockerfile) 也嚴禁存取"""
        for sensitive in [
            ".env", "config.yaml", ".git", ".ssh", ".bashrc", ".aws", ".azure", ".gcp",
            ".kube", ".docker", "credentials.json", ".vscode", ".idea", ".terraform",
            "Dockerfile", "docker-compose.yml"
        ]:
            with self.assertRaises(SensitivePathBlockedError):
                self.sanitizer.sanitize_path(sensitive)
            with self.assertRaises(SensitivePathBlockedError):
                self.sanitizer.sanitize_path(f"sub_dir/{sensitive}")

        # 憑證、金鑰與加密副檔名阻斷
        for cert_file in ["server.pem", "id_rsa.key", "identity.p12", "cert.pfx", "backup.enc", "keys.gpg", "sec.asc", "vault.kdbx", "prod.tfvars"]:
            with self.assertRaises(SensitivePathBlockedError):
                self.sanitizer.sanitize_path(cert_file)

    # ==========================================================================
    # 2. SQL 注入防護與查詢安全約束 (SQL Injection & Query Hardening)
    # ==========================================================================
    def test_sql_parameterized_query_success(self):
        """正常參數化查詢應正確執行"""
        test_db = self.workspace / "test.db"
        conn = get_db_connection(test_db)
        with conn:
            conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);")
            conn.execute("INSERT INTO users (name, role) VALUES (?, ?);", ("Alice", "admin"))
            conn.execute("INSERT INTO users (name, role) VALUES (?, ?);", ("Bob", "user"))
        conn.close()

        # 參數化查詢
        rows = execute_query(test_db, "SELECT name FROM users WHERE role = ?;", ("admin",))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Alice")

    def test_sql_multi_statement_stacking_blocked(self):
        """多語句堆疊注入 (Statement Stacking) 必須被阻斷"""
        test_db = self.workspace / "test.db"
        malicious_query = "SELECT * FROM users; DROP TABLE users;"
        with self.assertRaises(ValueError) as ctx:
            execute_query(test_db, malicious_query)
        self.assertIn("多語句堆疊", str(ctx.exception))

    def test_sql_destructive_dml_in_execute_query_blocked(self):
        """execute_query 僅限唯讀，任何嘗試執行 DROP/DELETE/INSERT 必須被阻斷"""
        test_db = self.workspace / "test.db"
        for bad_stmt in [
            "DROP TABLE users;",
            "DELETE FROM users WHERE id = 1;",
            "UPDATE users SET role = 'hacked';",
            "INSERT INTO users VALUES (3, 'evil', 'root');"
        ]:
            with self.assertRaises(ValueError) as ctx:
                execute_query(test_db, bad_stmt)
            self.assertIn("僅限唯讀查詢", str(ctx.exception))

    def test_sql_forbidden_keywords_and_pragma_blocked(self):
        """ATTACH、DETACH、VACUUM 與危險 PRAGMA 必須被阻斷"""
        test_db = self.workspace / "test.db"
        with self.assertRaises(ValueError) as ctx1:
            execute_query(test_db, "ATTACH DATABASE 'other.db' AS other;")
        self.assertIn("特權 SQL 關鍵字", str(ctx1.exception))

        with self.assertRaises(ValueError) as ctx2:
            execute_query(test_db, "PRAGMA writable_schema = 1;")
        self.assertIn("PRAGMA", str(ctx2.exception))

    # ==========================================================================
    # 3. 正則表達式 ReDoS 線性耗時壓力測試 (ReDoS Mitigation Test)
    # ==========================================================================
    def test_fast_path_redos_resilience(self):
        """測試 fast_path 在面對超長惡意字串時，是否能以 < 300ms 線性時間完成，無回溯卡死"""
        adversarial_input_1 = "檔案 " + ("a" * 50000) + " 不是關鍵字"
        adversarial_input_2 = ("搜尋 " * 500) + ("&" * 1000) + (" rm -rf /" * 100)

        t0 = time.perf_counter()
        tier_1 = FastPathClassifier.classify(adversarial_input_1)
        elapsed_1 = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        tier_2 = FastPathClassifier.classify(adversarial_input_2)
        elapsed_2 = (time.perf_counter() - t1) * 1000

        # 必須在 300ms 內完成（確認無指數級回溯災難）
        self.assertLess(elapsed_1, 300.0, f"ReDoS 檢測超時: {elapsed_1:.2f}ms")
        self.assertLess(elapsed_2, 300.0, f"ReDoS 檢測超時: {elapsed_2:.2f}ms")
        self.assertEqual(tier_2, FastPathTier.L3_HIGH_RISK)

    # ==========================================================================
    # 4. 機密與憑證自動脫敏驗證 (Secret Redaction Filter)
    # ==========================================================================
    def test_sanitize_secrets_api_keys(self):
        """各類平台 API Key 與 Token 必須被自動置換為 [REDACTED]"""
        mock_sk = "sk-" + "abcdef1234567890abcdef1234567890"
        mock_ghp = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        mock_akia = "AKIA" + "IOSFODNN7EXAMPLE"
        raw_text = f"OpenAI 金鑰為 {mock_sk}，GitHub Token 為 {mock_ghp}，AWS 金鑰為 {mock_akia}。"
        clean = sanitize_secrets(raw_text)
        self.assertNotIn(mock_sk, clean)
        self.assertNotIn(mock_ghp, clean)
        self.assertNotIn(mock_akia, clean)
        self.assertIn("[REDACTED]", clean)

    def test_sanitize_secrets_passwords_and_urls(self):
        """URL 帳密與鍵值對密碼必須被自動脫敏"""
        url_text = "連線字串: postgresql://postgres:mock_super_secret_password_123@db.internal:5432/prod"
        clean_url = sanitize_secrets(url_text)
        self.assertNotIn("mock_super_secret_password_123", clean_url)
        self.assertIn("[REDACTED]@", clean_url)

        kv_text = 'config: {"api_key": "my_super_secret_token_12345", "timeout": 30}'
        clean_kv = sanitize_secrets(kv_text)
        self.assertNotIn("my_super_secret_token_12345", clean_kv)

    def test_sanitize_nested_dict(self):
        """巢狀字典資料結構遞迴脫敏"""
        mock_token = "sk-" + "12345678901234567890123456"
        data = {
            "service": "openai",
            "auth": {
                "token": mock_token,
                "nested_pass": {"password": "admin_password_999"}
            },
            "public_info": "hello world"
        }
        clean_data = sanitize_dict(data)
        self.assertEqual(clean_data["auth"]["token"], "[REDACTED]")
        self.assertEqual(clean_data["auth"]["nested_pass"]["password"], "[REDACTED]")
        self.assertEqual(clean_data["public_info"], "hello world")

    # ==========================================================================
    # 5. 證據帳本零洩漏審計 (Evidence Logger Sanitization)
    # ==========================================================================
    def test_evidence_logger_sanitizes_records(self):
        """寫入證據庫的摘要中包含金鑰時，必須在存入前被自動脫敏"""
        task_id = "TASK-SEC-001"
        mock_secret = "sk-" + "secret9999999999999999999999"
        sensitive_summary = f"執行完成，輸出密鑰: {mock_secret}"
        record_evidence(task_id, "test_tool", 0, "SUCCESS", sensitive_summary)

        from hermes_core.evidence_logger import get_recent_evidence
        recent = get_recent_evidence(limit=1)
        self.assertTrue(len(recent) >= 1)
        latest_summary = recent[0]["summary"]
        self.assertNotIn(mock_secret, latest_summary)
        self.assertIn("[REDACTED]", latest_summary)

    # ==========================================================================
    # 6. ConfigLoader 路徑穿越防護與敏感變數隔離
    # ==========================================================================
    def test_config_loader_get_db_path_traversal_blocked(self):
        """get_db_path 必須阻斷相對路徑逃逸、絕對路徑與非法字符"""
        # 正常預定義路徑
        self.assertTrue(str(get_db_path("state")).endswith("state.db"))
        from hermes_core.semantic_cache import CACHE_DB as SEMANTIC_CACHE_DB
        self.assertEqual(SEMANTIC_CACHE_DB, get_db_path("semantic_cache"))

        # 相對路徑逃逸嘗試
        with self.assertRaises(ValueError):
            get_db_path("../../../etc/passwd")

        # 絕對路徑逃逸嘗試
        with self.assertRaises(ValueError):
            get_db_path("/etc/shadow")

        # 空位元組與特殊字符注入
        with self.assertRaises(ValueError):
            get_db_path("mydb\x00escape")
        with self.assertRaises(ValueError):
            get_db_path("sub/nested.db")

    def test_config_loader_sensitive_env_protection(self):
        """敏感環境變數識別與遮罩保護"""
        self.assertTrue(is_sensitive_key("OPENAI_API_KEY"))
        self.assertTrue(is_sensitive_key("DB_PASSWORD"))
        self.assertTrue(is_sensitive_key("AUTH_TOKEN"))
        self.assertFalse(is_sensitive_key("PORT"))
        self.assertFalse(is_sensitive_key("HOST"))

        os.environ["TEMP_SECRET_KEY"] = "super_secret_val_12345"
        try:
            # 遮罩模式
            masked = get_env_var("TEMP_SECRET_KEY", mask_if_sensitive=True)
            self.assertTrue(masked.startswith("sup***") or "[REDACTED]" in masked)
            # 專用密鑰存取
            secret = get_secret("TEMP_SECRET_KEY")
            self.assertEqual(secret, "super_secret_val_12345")
        finally:
            del os.environ["TEMP_SECRET_KEY"]

    # ==========================================================================
    # 7. CircuitBreaker 負向快取輸入驗證與 JSON 注入防護
    # ==========================================================================
    def test_circuit_breaker_record_negative_cache_hardening(self):
        """record_negative_cache 必須具備型別檢查、長度截斷與控制字元清理"""
        # 非法型別
        with self.assertRaises(TypeError):
            record_negative_cache(12345, "failed")
        with self.assertRaises(TypeError):
            record_negative_cache("url", None)

        # 注入與長度測試
        long_reason = "A" * 500 + "\r\nINJECTION: True\x00"
        mock_res = "https://example.com/test-endpoint"
        record_negative_cache(mock_res, long_reason, ttl_seconds=60.0)

        hit, msg = check_negative_cache(mock_res)
        self.assertTrue(hit)
        self.assertNotIn("\r", msg)
        self.assertNotIn("\n", msg)
        self.assertNotIn("\x00", msg)
        clear_negative_cache(mock_res)

    # ==========================================================================
    # 8. FastPath 中文動作詞 ReDoS 線性安全檢查
    # ==========================================================================
    def test_fast_path_chinese_mutation_safe_check(self):
        """中文變更關鍵字需精準判定為 WRITE 且不會觸發正規表達式回溯"""
        actions, _ = CommandSideEffectAnalyzer.analyze_segment("請幫我修改設定檔案")
        self.assertIn(ActionKind.WRITE, actions)

        actions, _ = CommandSideEffectAnalyzer.analyze_segment("清空暫存並覆寫新資料")
        self.assertIn(ActionKind.WRITE, actions)

    def test_fast_path_classifier_input_validation_and_tiers(self):
        """FastPath 分類器輸入邊界檢查與各安全層級精準路由"""
        # 非字串與空字串防護
        self.assertEqual(FastPathClassifier.classify(None), FastPathTier.L0_DIRECT_LLM)
        self.assertEqual(FastPathClassifier.classify(""), FastPathTier.L0_DIRECT_LLM)
        self.assertEqual(FastPathClassifier.classify("   "), FastPathTier.L0_DIRECT_LLM)
        self.assertEqual(FastPathClassifier.classify(12345), FastPathTier.L0_DIRECT_LLM)

        # 高危提權與系統變更指令 -> L3_HIGH_RISK
        self.assertEqual(FastPathClassifier.classify("rm -rf /"), FastPathTier.L3_HIGH_RISK)
        self.assertEqual(FastPathClassifier.classify("sudo systemctl restart"), FastPathTier.L3_HIGH_RISK)
        self.assertEqual(FastPathClassifier.classify("chmod 777 /var/data"), FastPathTier.L3_HIGH_RISK)

        # 核心受保護路徑篡改防護 -> L3_HIGH_RISK
        self.assertEqual(FastPathClassifier.classify("echo 'attack' > /haos/00_Constitution.md"), FastPathTier.L3_HIGH_RISK)

        # 唯讀查詢 -> L1_READONLY_TOOL
        self.assertEqual(FastPathClassifier.classify("查看目前的 git status"), FastPathTier.L1_READONLY_TOOL)

        # 純對話 -> L0_DIRECT_LLM
        self.assertEqual(FastPathClassifier.classify("你好，請為我說明這套系統"), FastPathTier.L0_DIRECT_LLM)

    def test_config_loader_file_permission_enforcement(self):
        """敏感設定檔權限檢查 (禁止 0777/0666 過度開放權限)"""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            temp_path = Path(f.name)
            temp_path.write_text("key: value", encoding="utf-8")

        try:
            # 1. 安全權限 (0600 - 僅擁有者讀寫)
            os.chmod(temp_path, 0o600)
            self.assertTrue(check_file_permissions(temp_path, strict=True))

            # 2. 過度開放權限 (0666 - 其他人可讀寫)
            os.chmod(temp_path, 0o666)
            self.assertFalse(check_file_permissions(temp_path, strict=False))
            with self.assertRaises(PermissionError):
                check_file_permissions(temp_path, strict=True)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_kv_password_redos_resilience(self):
        """KV_PASSWORD 正則在超長無引號閉合惡意輸入下需在 100ms 內完成無回溯卡死"""
        adversarial_input = 'password="' + ("a" * 500) + '!'
        t0 = time.time()
        res = sanitize_secrets(adversarial_input)
        elapsed = time.time() - t0
        self.assertTrue(elapsed < 0.1, f"KV_PASSWORD 正則耗時過長: {elapsed}s")

    def test_config_loader_blocks_custom_yaml_tags(self):
        """load_config 必須主動阻斷包含 !! 自訂標籤的惡意 YAML"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_home = Path(temp_dir)
            cfg = temp_home / "config.yaml"
            cfg.write_text("evil: !!python/object/apply:os.system ['id']", encoding="utf-8")
            os.chmod(cfg, 0o600)

            orig_home = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = str(temp_home)
            try:
                # 重新動態匯入或直接測試 load_config
                import hermes_core.config_loader as cl
                cl.HERMES_HOME = temp_home
                with self.assertRaises(ValueError):
                    cl.load_config(strict_permissions=True)
            finally:
                if orig_home:
                    os.environ["HERMES_HOME"] = orig_home
                cl.HERMES_HOME = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))

    def test_path_sanitizer_symlink_loop_defense(self):
        """符號連結迴圈 (A -> B -> A) 必須被主動偵測並拋出 PathTraversalError 阻斷"""
        link_a = self.workspace / "loop_a"
        link_b = self.workspace / "loop_b"
        try:
            link_a.symlink_to(link_b)
            link_b.symlink_to(link_a)
            with self.assertRaises(PathTraversalError):
                self.sanitizer.sanitize_path("loop_a")
        finally:
            if link_a.is_symlink() or link_a.exists():
                link_a.unlink()
            if link_b.is_symlink() or link_b.exists():
                link_b.unlink()

    def test_chat_client_ssl_verification_enforcement(self):
        """Synology Chat 客戶端預設必須強制啟用 CERT_REQUIRED 與主機名稱檢驗"""
        import ssl
        from hermes_core.chat_client import _get_ssl_context

        # 預設狀態 (嚴格安全模式)
        if "SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY" in os.environ:
            del os.environ["SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY"]
        if "TESTING_MODE" in os.environ:
            del os.environ["TESTING_MODE"]

        ctx = _get_ssl_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

        # 僅設 SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY 但無 TESTING_MODE=local_sandbox 仍必須強制維持 CERT_REQUIRED
        os.environ["SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY"] = "1"
        try:
            ctx_no_sandbox = _get_ssl_context()
            self.assertEqual(ctx_no_sandbox.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx_no_sandbox.check_hostname)

            # 兩者皆滿足時才允許放寬 (僅限本地測試沙盒)
            os.environ["TESTING_MODE"] = "local_sandbox"
            relaxed_ctx = _get_ssl_context()
            self.assertEqual(relaxed_ctx.verify_mode, ssl.CERT_NONE)
            self.assertFalse(relaxed_ctx.check_hostname)
        finally:
            del os.environ["SYNOLOGY_CHAT_INSECURE_SKIP_VERIFY"]
            if "TESTING_MODE" in os.environ:
                del os.environ["TESTING_MODE"]

    def test_chat_client_response_bounded_and_strict_json(self):
        """測試 Synology Chat 客戶端回應長度邊界 (防 DoS) 與嚴格 JSON 反序列化"""
        from unittest.mock import patch, MagicMock
        from hermes_core.chat_client import send_chat_message

        # 1. 模擬回應資料超過 1MB 邊界
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"x" * 1_048_576

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            res = send_chat_message("test", channel_id="123")
            self.assertFalse(res)

        # 2. 模擬非嚴格 JSON (如包含控制字元)
        mock_resp_bad = MagicMock()
        mock_resp_bad.status = 200
        mock_resp_bad.read.return_value = b'{"success": true, "msg": "bad\x00char"}'

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = mock_resp_bad
            res = send_chat_message("test", channel_id="123")
            self.assertFalse(res)

    def test_config_loader_safe_loader_error_logging(self):
        """config_loader 在 YAML 語法損壞時使用 SafeLoader 解析，並記錄警告不拋未捕捉異常"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_home = Path(temp_dir)
            cfg = temp_home / "config.yaml"
            cfg.write_text("broken: [unclosed list", encoding="utf-8")
            os.chmod(cfg, 0o600)

            orig_home = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = str(temp_home)
            try:
                import hermes_core.config_loader as cl
                cl.HERMES_HOME = temp_home
                with self.assertLogs("hermes.config_loader", level="WARNING") as cm:
                    res = cl.load_config(strict_permissions=True)
                    self.assertEqual(res, {})
                    self.assertTrue(any("讀取設定檔失敗" in msg for msg in cm.output))
            finally:
                if orig_home:
                    os.environ["HERMES_HOME"] = orig_home
                cl.HERMES_HOME = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))

    def test_semantic_cache_secret_sanitization_and_caller_guard(self):
        """語意快取敏感憑證寫入自動脫敏與未受信任呼叫者阻斷"""
        from hermes_core.semantic_cache import set_cached_response, get_cached_response

        # 1. 呼叫者驗證：未受信任者或未提供身分寫入失敗 (防快取中毒)
        res_bad = set_cached_response("測試未授權查詢", "一些結果", caller_id="malicious_user")
        self.assertFalse(res_bad)

        # 嚴格模式下拋出 PermissionError
        with self.assertRaises(PermissionError):
            set_cached_response("測試未授權查詢", "一些結果", caller_id="malicious_user", strict_caller_check=True)

        res_none = set_cached_response("測試未授權查詢", "一些結果", caller_id=None)
        self.assertFalse(res_none)

        res_empty = set_cached_response("測試未授權查詢", "一些結果", caller_id="")
        self.assertFalse(res_empty)

        # 2. 受信任呼叫者 (如 internal_service 與 agent) 驗證
        res_internal = set_cached_response("測試內部服務查詢", "內部資料", caller_id="internal_service")
        self.assertTrue(res_internal)

        # 3. 受信任呼叫者寫入包含 API Key 的回應，確認取出時已自動脫敏
        mock_key = "sk-" + "token1234567890abcdef123456"
        secret_content = f"回答結果：請使用您的金鑰 {mock_key} 進行驗證。"
        res_ok = set_cached_response("查詢機密配置", secret_content, caller_id="agent")
        self.assertTrue(res_ok)

        hit = get_cached_response("查詢機密配置")
        self.assertIsNotNone(hit)
        cached_text = hit["response_text"]
        self.assertNotIn(mock_key, cached_text)
        self.assertIn("[REDACTED]", cached_text)

        # 4. TTL 上限防護 (MAX_CACHE_TTL_SECONDS)
        from hermes_core.semantic_cache import MAX_CACHE_TTL_SECONDS, MAX_RESPONSE_LENGTH
        set_cached_response("測試超長TTL查詢", "資料", ttl_seconds=999999999, caller_id="agent")
        hit_ttl = get_cached_response("測試超長TTL查詢")
        self.assertIsNotNone(hit_ttl)

        # 5. 回應長度上限 (16KB) 與空字節防護
        res_oversized = set_cached_response("大回應測試", "A" * (MAX_RESPONSE_LENGTH + 1), caller_id="agent")
        self.assertFalse(res_oversized)

        res_null = set_cached_response("查詢\x00注入", "正常回答", caller_id="agent")
        self.assertFalse(res_null)

    def test_get_env_var_strict_permission_enforcement(self):
        """get_env_var 讀取過度開放權限之 .env 檔時必須拋出 PermissionError 阻斷"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_home = Path(temp_dir)
            env_f = temp_home / ".env"
            env_f.write_text("SENSITIVE_CONFIG=very_secret_token\n", encoding="utf-8")
            os.chmod(env_f, 0o666)

            orig_home = os.environ.get("HERMES_HOME")
            os.environ["HERMES_HOME"] = str(temp_home)
            try:
                import hermes_core.config_loader as cl
                cl.HERMES_HOME = temp_home
                with self.assertRaises(PermissionError):
                    cl.get_env_var("SENSITIVE_CONFIG", strict_permissions=True)
            finally:
                if orig_home:
                    os.environ["HERMES_HOME"] = orig_home
                cl.HERMES_HOME = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))

    def test_circuit_breaker_max_json_size_protection(self):
        """CircuitBreaker 狀態檔與負向快取若超過 1MB 必須被主動略過防範記憶體 DoS"""
        from hermes_core.circuit_breaker import _load_breakers, _load_negative_cache, STATE_FILE, NEGATIVE_CACHE_FILE
        from unittest.mock import patch

        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "stat") as mock_stat:
                mock_stat.return_value.st_size = 2_000_000  # 2MB > 1MB
                res_breakers = _load_breakers()
                self.assertEqual(res_breakers, {})

                res_negative = _load_negative_cache()
                self.assertEqual(res_negative, {})


if __name__ == "__main__":
    unittest.main()
