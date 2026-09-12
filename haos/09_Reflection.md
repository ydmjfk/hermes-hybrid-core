# 09_Reflection.md — HAOS 證據驅動復盤器 (Reflection)

> **地位**：Warm Layer（Reflect 階段載入）。定義三層根因分析範式、防重複踩坑機制與知識沈澱流程。

---

## 🔍 三層根因深度分析範式 (Three-Tier Post-Mortem)

每一次復盤與問題診斷，嚴禁僅停留於表面報錯，必須嚴格拆解為三層因果鏈：

```text
[ 表面原因 Surface Cause ]
  ↳ 程式丟出的直接異常訊息 (例: `KeyError: 'download_url'`)
       │
       ▼
[ 直接原因 Direct Cause ]
  ↳ 引發此異常的操作或缺陷代碼 (例: 未驗證 API 回傳字典是否存在該鍵值即直接讀取)
       │
       ▼
[ 根本原因 Root Cause ]
  ↳ 流程/架構或認知層面的根本盲點 (例: 缺少 Schema-First 前置校驗機制，未處理服務降級場景)
```

---

## 🔄 證據驅動自我演進閉環 (Evidence Evolution Loop)

```text
Task Execution ──► Gather Evidence ──► Three-Tier Reflection
                                              │
                                              ▼
Persistent SOP ◄── Validation (Pass) ◄── Propose Hypothesis
```

1. **拒絕主觀臆測**：嚴禁憑空提出「我覺得 Prompt 要改」，所有改進假設必須附帶實體日誌或測試數據作為 Evidence。
2. **防止重複踩坑 (Anti-Regression)**：
   - 若問題屬於「非偶發之系統性障礙」，必須評估是否寫入 `~/.hermes/agent-production-rules.md` 或 [32_DecisionJournal.md](haos/32_DecisionJournal.md)。
3. **背景反思安全約束 (Background Review Guard)**：
   - 背景反思 (`bg-review`) 階段僅能使用 `memory` 與 `skill_manage` 工具，**嚴禁呼叫 `patch`、`read_file` 或 `execute_code`**。
   - 若技能為手動創建（`created_by=None`），背景 Review **絕不可調用 `skill_manage` 強行 patch/edit**，僅可提出建議供使用者審核。
