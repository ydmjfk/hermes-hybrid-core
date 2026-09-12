# Hermes Hybrid Core — 資安治理與運維安全最佳實踐 (Security Best Practices)

本文檔制定 Hermes Hybrid Core 於企業生產環境運行的安全性標準與防護實務。

---

## 1. 憑證與環境變數安全輪轉 (Secret & Credential Rotation Policy)

### 1.1 輪轉週期
- **外部 LLM API Key (OpenAI / Anthropic)**：建議每 90 天進行輪轉。
- **即時通訊 Token (Synology Chat / Webhook)**：每 180 天或任職異動時立即重設。
- **本地敏感檔案權限**：
  ```bash
  chmod 600 ~/.hermes/.env
  chmod 700 ~/.hermes/
  ```

### 1.2 程式碼安全讀取慣例
- **常規配置查詢**：使用 `get_env_var(key, mask_if_sensitive=True)`，即使在日誌打印時亦自動遮蔽（例如 `sk-***ef`）。
- **機密憑證注入**：僅在向外部 API 發起連線時透過專用函式 `get_secret(key)` 存取，嚴禁將 `get_secret` 之回傳值傳入任何 Logger、Print 或中繼快取。

---

## 2. 審計證據帳本防護 (Audit Ledger Protection)

- **日誌自動脫敏**：所有寫入 `verification_evidence.db` 的工具執行輸出與狀態摘要，均自動透過 `security_filter.sanitize_secrets()` 進行特徵比對與掩碼置換。
- **靜態資料保護 (Data at Rest)**：
  - 本地 SQLite 資料庫權限應限定為執行使用者私有 (`chmod 600 ~/.hermes/data/*.db`)。
  - 對於具備強規管需求（如 HIPAA / GDPR）之企業部署，建議結合 Linux LUKS 磁碟加密或配置 SQLCipher 擴展模組。

---

## 3. 依賴項漏洞自動化掃描 (Vulnerability & Dependency Audit)

- **依賴釘選**：`requirements.txt` 嚴格鎖定已知無重大 CVE 之安全版本。
- **自動化安全審計指令**：
  建議在 CI/CD 流程中加入定期掃描：
  ```bash
  # 使用 pip-audit 進行 PyPI 已知漏洞審查
  pip install pip-audit
  pip-audit -r requirements.txt

  # 或使用 Safety 工具
  pip install safety
  safety check -r requirements.txt
  ```

---

## 4. 本機提交雙閘門防禦架構 (Two-Tier Gate Defense)

1. **Pre-commit Gate (`.git/hooks/pre-commit`)**：
   - 阻止任何寫死真實金鑰、私有路徑或業務黑名單名詞之變更提交。
2. **Pre-push Gate (`.git/hooks/pre-push`)**：
   - 強制人工安全確認，必須宣告環境變數 `ALLOW_PUSH=1` 方可發布至遠端倉庫，徹底杜絕自動化腳本誤推行為。
