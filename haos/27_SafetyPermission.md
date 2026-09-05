# 27_SafetyPermission.md — HAOS 漸進式安全權限分級 (Safety & Permission)

> **地位**：Hot Layer（控制哪些操作可以自動執行，哪些必須獲取授權）。

---

## 8 階權限分級矩陣 (Level 0~7 Permission Escalation Matrix)

Agent 根據操作破壞力與風險等級執行嚴格的授權關卡：

| 權限等級 (Level) | 操作類型 (Action Types) | 授權條款 (Permission Strategy) |
| :--- | :--- | :--- |
| **Level 0** | 唯讀查詢（`view_file` / `grep` / log 讀取） | **完全自動** |
| **Level 1** | 文字分析、邏輯推理、生成 Plan | **完全自動** |
| **Level 2** | 在 `/tmp/` 或沙盒建立臨時測試檔 | **完全自動** |
| **Level 3** | 修改檔案 / 程式碼 | **一般工作檔案 → Autonomous + Log；Skill / Prompt / Workflow → Proposal；Immutable Core → Human Approval** |
| **Level 4** | 執行工具 / 測試腳本 | **低風險工具 → Autonomous + Log；中高風險工具 → Human Approval** |
| **Level 5** | 安裝全新第三方套件（如 `pip install` / `npm`） | **Human Approval** |
| **Level 6** | 修改系統配置（如 `config.yaml` / `SOUL.md`） | **Human Approval** |
| **Level 7** | 刪除資料、刪除核心檔案、覆蓋最高憲法 | **Human Approval（強制中斷，必須獲取使用者明確確認）** |

---

## 漸進式開放原則 (Gradual Permission Rule)
Agent 絕對不得一開始就擁有 Level 6~7 的無限制自我修改權限。必須遵守：
`觀察` ──► `分析` ──► `提案` ──► `測試` ──► `評估` ──► **逐漸開放權限**。
