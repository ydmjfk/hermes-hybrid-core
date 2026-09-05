# 24_ContextManager.md — HAOS 上下文管理器 (Context Manager)

> **地位**：Hot Layer（Context Window 預算配置、Token 節流與 KV Cache 保護）。

---

## ⚡ Context 精準剪裁策略 (Relevant-Only Context Strategy)

嚴禁全量盲目塞入歷史流水帳、全部記憶與冗長日誌（Context Bloat 會造成推理變慢、關注力稀釋、Token 成本暴增）。
正確載入鏈：`[使用者目標] → [當前階段關聯 Context] → [僅載入必要 1 個 Skill] → [狀態結算]`

---

## 📊 上下文預算配置矩陣 (Budget Allocation)

| Context 類別 | Token 預算比例 | 內容限制與過濾原則 |
| :--- | :--- | :--- |
| **System Hot Layer** | $\le 10\%$ (~800 Tokens) | 最高憲法、核心政策與安全脫敏摘要 |
| **User Task & State** | $\sim 20\%$ | 原始 Goal、目前進度與驗收條件 |
| **Relevant Skill / Tool** | $\sim 30\%$ | 僅讀取當前任務必要的 1 個 Skill SOP |
| **Execution Evidence / Log** | $\sim 40\%$ | 嚴禁讀取全檔，使用 `tail -n 30` 或 `grep` 片段 |

---

## 🧹 自動釋放與中間結算
- 每當連續工具呼叫達 15 次，主動輸出「中間結算小結」，提示系統壓縮舊 Log，維持模型高敏銳度。
