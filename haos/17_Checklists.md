# 17_Checklists.md — HAOS 實戰執行檢查清單庫 (Checklists)

> **地位**：Warm Layer（各階段關卡驗證）。

---

## 常用作業標準檢查清單 (Standard Execution Checklists)

### 1. 程式碼修改前檢查清單 (Pre-Edit Checklist)
- [ ] 根本原因已由 Log / Stack Trace 客觀定位？
- [ ] 修改範圍已限制在最小侵入行數（Minimal Blast Radius，優先精確區塊替換）？
- [ ] 已建立前置不可覆滅備份（`.bak`）或確認 Git 狀態乾淨？
- [ ] 既有註解、Docstrings 與格式排版未受無關破壞？

### 2. 資料庫查詢前檢查清單 (Pre-Database Query Checklist)
- [ ] 已執行 `.schema` 或 `PRAGMA table_info(表名)` 確認真實欄位？
- [ ] 查詢已設定合理 `LIMIT` 或精確 `WHERE` 條件（嚴禁無限制全表輸出）？

### 3. 命令列與工具執行前檢查清單 (Pre-CLI Checklist)
- [ ] 不熟悉之指令已先以 `--help` 檢驗合法子指令與參數？
- [ ] 路徑皆採用標準絕對路徑，已通過 `path_sanitizer.py` 沙盒邊界檢查？
- [ ] 嚴禁使用 `cat << 'EOF'` 或 Pipe 管道在 Terminal 寫入測試腳本？
- [ ] 嚴禁在查詢對話中引發超過 2 輪工具連環探索？

### 4. 傳檔與檔案發布檢查清單 (Pre-Attachment Checklist)
- [ ] 使用者是否已發出明確傳檔指令（若無，嚴禁主動傳檔）？
- [ ] 是否調用專屬傳檔腳本（`request_file_attachment.py`）而非自行拼裝 URL？
- [ ] 對外回覆是否已嚴格過濾內網 IP（如 `127.0.0.1`）、`/download/` 與本機檔案路徑？

### 5. 模型與 Cron Job 變更檢查清單 (Pre-Model-Change Checklist)
- [ ] 變更前是否已備份 `config.yaml` 與 `jobs.json`？
- [ ] 是否已透過 `model_defaults` anchor 機制進行全域連動？
- [ ] 變更後是否已執行漂移檢查並在 [32_DecisionJournal.md](haos/32_DecisionJournal.md) 記錄技術選型理由？
