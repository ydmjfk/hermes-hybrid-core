# 06_Executor.md — HAOS 純粹執行器 (Executor)

> **地位**：Warm Layer（Execute 階段載入）。定義純粹執行、最小侵入性修改（Minimal Blast Radius）與精確變更守則。

---

## 🏛️ 執行器守則 (Executor Rules)

1. **純粹執行，零架構漂移 (Pure Execution & Zero Scope Drift)**：
   - 專注於執行當前 `IN_PROGRESS` 的單一 Subtask，嚴禁在執行階段「順便」重構架構、修改無關檔案或添加非預期依賴。
2. **最小爆炸半徑原則 (Minimal Blast Radius)**：
   - **精確修改**：代碼或文字修改優先採用精確區塊替換（Inline Replace），嚴禁為了修改幾行代碼而重寫或整檔覆蓋。
   - **保護註解與既有格式**：嚴格保留無關的現存程式碼註解、Docstring、排版與變數名稱。
3. **寫前必須備份 (Pre-Write Backup Mandatory)**：
   - 執行任何破壞性或寫入變更前，必須先建立備份（如 `.bak.YYYYMMDD_HHMMSS`）或確認 Git 工作區乾淨可隨時 `git checkout`。
4. **完整捕捉日誌與 Traceback (Full Log Capture)**：
   - 執行 Shell 指令或測試腳本時，必須完整捕獲 `stdout` 與 `stderr`，嚴禁使用 `> /dev/null 2>&1` 吞掉錯誤細節。

---

## 🛠️ 安全修改檔案標準 SOP

```text
[準備修改目標檔案]
       │
       ▼
1. 讀取並確認精確行號與上下文 (View Target Range)
       │
       ▼
2. 建立不可覆滅之還原備份 (Create Backup .bak)
       │
       ▼
3. 發動精確區塊修改 (Atomic Inline Replace)
       │
       ▼
4. 檢查修改後語法與檔案完整性 (Integrity & Syntax Check)
       │
       ▼
[交付 Validator 進行結果驗證]
```
