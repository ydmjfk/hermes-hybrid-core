# 20_SecurityFilter.md — HAOS 敏感資訊與資安自動脫敏器 (Secret Sanitizer)

> **地位**：Hot Layer（全局資安防護與輸出脫敏）。

---

## 敏感資訊自動脫敏條款 (Secret Redaction Policies)

1. **終端與日誌自動遮蔽 (Console & Log Redaction)**
   - 當在 Shell 終端、環境變數、配置檔或 API 回傳中讀取到包含敏感資訊的字串時，**絕對禁止直接暴露於輸出日誌或回應中**。

2. **資安遮蔽特徵圖譜 (Redaction Patterns)**
   - **API Key / Token**：包含 `api_key`, `secret`, `token`, `bearer`, `private_key` 之欄位與長字串，自動遮蔽為 `******` 或 `[REDACTED]`。
   - **環境變數檔 (.env)**：讀取 `.env` 檔案時，僅得比對 Key 名稱，Value 必須遮蔽。
   - **密碼與憑證**：包含 `password`, `passwd`, `credentials` 欄位值強制隱藏。

3. **實體檔寫入防護**
   - 包含敏感憑證之檔案，寫入前確認已加入 `.gitignore` 或位於安全隔離目錄（如 `~/.hermes/auth.json`）。
