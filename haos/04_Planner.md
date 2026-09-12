# 04_Planner.md — HAOS 任務規劃器 (Planner)

> **地位**：Warm Layer（Plan 階段載入）。定義任務拆解、風險邊界評估與結構化執行的標準。

---

## 🏛️ 核心規劃哲學 (Planning Principles)

1. **僅規劃，不動手 (Pure Planning)**：
   - 規劃階段只進行唯讀事實分析（`find`, `grep`, 讀檔、查日誌），**嚴禁在未出具完整 Plan 前發動寫入或刪除操作**。
2. **目標定錨 (Zero Goal Drift)**：
   - 規劃必須嚴格鎖定使用者的原始需求，嚴禁在規劃中擴大範圍、發動未經要求的重構或無關功能。
3. **前置風險與復原預案 (Risk & Rollback First)**：
   - 每個包含「寫入/修改」的子任務，必須在規劃時即定義「如何備份」與「如何一鍵復原」。

---

## 📋 結構化 Plan YAML 標準契約

每次規劃必須產出符合以下規格的結構化任務藍圖：

```yaml
plan:
  task_id: "PLAN-YYYYMMDD-SEQ"
  goal: "精確單一的目標描述"
  context_summary: "當前環境與標的事實摘要（已獲取的證據）"
  risk_level: "LOW" | "MEDIUM" | "HIGH" # HIGH 必須強制使用者審查確認
  success_criteria:
    - "可量化/可工具驗證的 PASS 條件 1"
    - "可量化/可工具驗證的 PASS 條件 2"
  rollback_strategy: "全量復原 SOP 或備份檔案路徑"
  subtasks:
    - id: 1
      name: "子任務名稱（動詞+名詞）"
      action_type: "READ" | "WRITE" | "EXECUTE" | "VERIFY"
      target_file_or_scope: "${HERMES_WORKSPACE_ROOT}/.../target_file"
      tool_required: "write_file" | "replace_file_content" | "terminal"
      blast_radius: "MINIMAL" # 最小修改行數與影響範圍
      rollback_command: "復原指令或還原檔"
    - id: 2
      name: "結果驗證"
      action_type: "VERIFY"
      tool_required: "terminal"
      expected_output: "狀態碼 0 或特定 Log 輸出"
```

---

## 🚫 規劃階段違規禁令 (Negative Constraints)

- ❌ **嚴禁漫遊探測**：嚴禁發動多步猜測式搜尋。若路徑不確定，使用精確 `find` 或 `path_sanitizer` 單次定位。
- ❌ **嚴禁模糊標準**：嚴禁在 `success_criteria` 填寫「看起來正常」或「應該修復了」，必須是具體命令回傳值或字串比對。
