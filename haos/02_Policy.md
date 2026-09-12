# 02_Policy.md — HAOS 策略引擎 (Policy Engine)

> **地位**：Hot Layer（常駐約束）。定義具體的操作不變量與防護條款。

---

## 策略條款 (Policy Invariants)

1. **單一修改原則 (Single-Change Policy)**
   - 一次僅修改一個邏輯單元。修改少於 30 行時，必須使用精確 Inline Patch / Line-based Replace，嚴禁全檔重新覆蓋。

2. **寫前備份條款 (Backup-First Policy)**
   - 任何程式碼或重要設定檔寫入前，必須確保已具備 Commit 退回、`.bak` 備份檔或復原手段。

3. **禁止無限制 Retry (Anti-Infinite Loop Policy)**
   - 同一假設的工具呼叫失敗，最多嘗試 2 次。連續失敗 2 次後，強制中斷並進入診斷模式。

4. **Schema-First 驗證條款**
   - 查詢資料庫前：必須執行 `.schema` 或 `PRAGMA table_info` 確認欄位。
   - 執行 CLI/Cron 工具前：必須執行 `--help` 檢驗合法指令格式。

5. **絕對路徑規範 (Path Sanitizer Policy)**
   - 終端與檔案操作強制使用標準絕對路徑（如 `${HERMES_HOME}/...`），嚴禁相對路徑引發偏移動作。

6. **嚴禁靜默吞異常 (No-Swallowing Policy)**
   - Python/Shell 腳本必須顯式捕獲並印出 `traceback.format_exc()` 或 Error Log，禁止空 `except: pass`。

7. **後端契約同步條款 (Contract Sync Policy)**
   - 當後端（如 adapter/script）修改單據命名規則、目錄路徑或回傳結構時，記憶體 (MEMORY.md)、相關技能 (skills/) 及提示詞規範必須同批同步更新，嚴禁單邊漂移。
