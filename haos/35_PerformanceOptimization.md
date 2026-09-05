# 35_PerformanceOptimization.md — HAOS 效能優化最佳實踐 (Performance & Token Efficiency)

> **地位**：Hot Layer（提升回應速度、減少 Token 消耗、防卡死門禁）。

---

## 1. 0-Tool Fast Path 極速直出機制

**原則**：已知標準業務（如圖片自動歸檔、結構化查詢），優先啟用後台一體化腳本，達成 0~1 輪工具直出。

| 業務場景 | 標準處置方式 | 效能效益 |
| :--- | :--- | :--- |
| **圖片單據標準歸檔完成通知** | 嚴禁調用任何視覺/終端工具，直接使用系統提示 Markdown 表格回覆 | 耗時從 15s 降至 1s |
| **歷史單據與維修紀錄查詢** | 調用 `search_archives.py` 單輪產出摘要，直接生成表格回覆 | 避免多步目錄漫遊探索 |
| **純問答與確認** | 直接依據 Context 回答，不調用額外工具 | 節省 100% 工具往返時間 |

---

## 2. Anti-Tool-Chaining 門禁（限制工具呼叫輪次）

- **工具輪次硬限制（最多 2 輪）**：單一互動對話中，嚴禁發動超過 2 輪工具呼叫。
- **嚴禁漫遊探索鏈**：嚴禁串聯 `session_search` $\rightarrow$ `skill_view` $\rightarrow$ `read_file` $\rightarrow$ `search_files` 等多步連環探索。
- **單輪直出規範**：日常單據查詢一律使用一體化腳本，單輪取得結構化摘要後立即產出最終回覆。

---

## 3. 工具限制（減少載入時間）

**原則**：簡單任務指定 `enabled_toolsets`，只載入必要工具。

### Cronjob 工具限制範例

| 任務類型 | enabled_toolsets | 說明 |
| :--- | :--- | :--- |
| 股價追蹤 | `["web"]` | 只需 web_search |
| 日誌清理 | `["terminal"]` | 只需執行 shell 指令 |
| 檔案處理 | `["terminal", "file"]` | 只需終端機與檔案操作 |
| 記憶檢查 | `["file", "terminal", "memory"]` | 需讀取檔案與修改記憶 |
| 網頁抓取 | `["web", "terminal"]` | 需 web_search + Python 腳本 |

---

## 4. 批次處理（減少工具呼叫次數）

**原則**：多項檢查整合為單一指令，減少來回次數。

### ❌ 低效：多次獨立呼叫
```bash
tail -n 30 agent.log
tail -n 30 errors.log
tail -n 30 gateway.log
```

### ✅ 高效：批次整合
```bash
echo "=== agent.log ===" && tail -n 30 agent.log && echo "=== errors.log ===" && tail -n 30 errors.log && echo "=== gateway.log ===" && tail -n 30 gateway.log
```

---

## 5. 日誌讀取最佳實踐

**原則**：使用 `tail -n 30` 或 `grep`，嚴禁讀取完整日誌。

| 情境 | 指令 |
| :--- | :--- |
| 檢查最新錯誤 | `tail -n 30 ~/.hermes/logs/errors.log` |
| 搜尋特定錯誤 | `grep -i "error" ~/.hermes/logs/errors.log | tail -n 20` |
| 檢查最近工具呼叫 | `tail -n 50 ~/.hermes/logs/agent.log | grep -i "tool_call"` |

---

## 6. Context 與 Memory 瘦身

- **只存高價值事實**：系統路徑、DB 結構、Port、使用者偏好。
- **不存任務進度與過程日誌**：進度由 session 紀錄管理，不塞入持久記憶。
- **長度控制**：`MEMORY.md` 建議精簡於 50 行以內，`USER.md` 控制於 30 行以內。

---

## 7. 熔斷與截斷應對矩陣

| 情境 | 熔斷條件 | 處置動作 |
| :--- | :--- | :--- |
| 工具失敗 | 相同假設連續失敗 2 次 | 強制熔斷，退回 `04_Planner.md` 或求助 |
| 被截斷 | 被截斷 1 次 | 立即縮短重寫（≤ 30 行、≤ 1500 字） |
| 被截斷 | 被截斷 2 次 | 強制熔斷，只輸出 3 行結論，避免死鎖 |
| web_search | 連續 2 次未獲得精確數據 | 變換關鍵字或主動停止搜尋 |
