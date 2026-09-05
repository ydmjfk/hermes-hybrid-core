# 07_ToolManager.md — HAOS 能力與工具管理器 (Tool Manager)

> **地位**：Warm Layer（Execute 階段載入）。定義工具調度優先級、前置防護門禁與防漫遊硬約束。

---

## 🧭 工具調度優先級階梯 (Tool Hierarchy Ladder)

執行任務時，必須依照下列優先順序由左至右、由低成本至高成本調用工具：

```text
專用整合腳本 (One-Shot Scripts)
       │
       ▼
專案精確搜尋 (find / grep / 專案檔案讀取)
       │
       ▼
本機日誌與狀態檢查 (tail -n 30 / systemctl status)
       │
       ▼
程式碼分析與修改 (replace_file_content / write_file)
       │
       ▼
外部搜尋與網路抓取 (web_search / crawl)
       │
       ▼
純邏輯推理 (Pure Reasoning)
```

---

## 🛡️ 實戰工具前置防護門禁 (Pre-Execution Guardrails)

1. **[Schema-First 前置門禁]**：
   - 執行任何 SQLite / 資料庫查詢前：必須先執行 `.schema` 或 `PRAGMA table_info(表名)` 確認欄位與表名真實存在，嚴禁盲寫 SQL。
2. **[CLI `--help` 檢驗門禁]**：
   - 執行不熟悉的 CLI 工具或子命令前：必須先執行 `--help` 檢驗合法子指令與參數格式（如 Duration 格式），嚴禁盲猜。
3. **[Path Sanitizer 邊界門禁]**：
   - 傳遞給工具的路徑引數必須調用 `path_sanitizer.py` 進行標準絕對化與沙盒驗證。
   - 所有操作必須限制在 `${HERMES_WORKSPACE_ROOT}` 工作區沙盒內，嚴禁越界。
   - 遇「路徑不存在」錯誤時，強制啟動模糊搜尋建議 (Did You Mean?) 與 `find` 證據探測，嚴禁盲猜。
4. **[Terminal 安全寫檔門禁]**：
   - 建立、寫入或測試檔案時，**務必直接使用專用寫檔工具 (`write_file`)**。
   - 嚴禁在 Terminal 使用 `cat << 'EOF'` 或 Pipe 重導向語法寫入包含 IP 網址或測試資料的內容，防止誤觸 Terminal 預執行資安掃描警報。
5. **[Anti-Tool-Chaining 防連環呼叫門禁]**：
   - 一般查詢與問答對話中，單輪互動**嚴禁發動超過 2 輪工具呼叫**。
   - 嚴禁串聯多步無關探索鏈，日常單據/資料查詢強制使用一體化腳本進行單輪直出。
