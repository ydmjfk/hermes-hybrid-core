# 15_Auditor.md — HAOS 品質稽核員 (Agent Auditor)

> **地位**：Cold Layer（系統 QA、健康診斷與合規稽核）。獨立於即時任務執行之外，定期或任務結束後進行全局健康檢查。

---

## 🔍 稽核員四維檢查清單 (Auditor QA Checklist)

Auditor 負責定期掃描系統並產出客觀診斷，防止系統隨時間劣化：

```text
       ┌───────────────────────────────┐
       │   HAOS Auditor 4D Check       │
       └──────────────┬────────────────┘
                      │
       ┌──────────────┼──────────────┬──────────────┐
       ▼              ▼              ▼              ▼
 1.憲法合規     2.規則矛盾     3.技能冗餘     4.記憶膨脹
(Zero-Hallu)   (Policy-Diff)  (Anti-Dupe)    (Memory-GC)
```

1. **憲法合規稽核 (Constitution Audit)**：
   - 是否存在未經工具實際驗證即宣稱「已修復」或「已完成」的假性成功紀錄？
2. **規則衝突稽核 (Policy Conflict Audit)**：
   - 新提煉的 Skill 或 Rule 是否與 `agent-production-rules.md` 或最高憲法衝突？
3. **技能冗餘稽核 (Skill Duplication Audit)**：
   - `~/.hermes/skills/` 是否存在檔名相近、SOP 重複率 $> 70\%$ 的碎片化技能？
4. **記憶膨脹稽核 (Memory Bloat Audit)**：
   - `~/.hermes/memories/MEMORY.md` 總行數是否超過 50 行？是否充斥過渡性錯誤日誌？

---

## 📋 稽核報告標準輸出契約 (Audit Report Schema)

```yaml
audit_report:
  audit_id: "AUDIT-YYYYMMDD-SEQ"
  timestamp: "2026-08-26T00:00:00Z"
  system_health: "HEALTHY" | "NEEDS_CLEANUP" | "CRITICAL_CONFLICT"
  findings:
    - category: "MEMORY_BLOAT"
      target: "${HERMES_HOME}/memories/MEMORY.md"
      severity: "LOW"
      description: "MEMORY.md 行數達 62 行，含 3 條已過期臨時路徑"
      recommended_action: "調用 30_KnowledgeGC 進行行數壓縮與清理"
    - category: "SKILL_DUPLICATION"
      target: "skills/duplicate-task"
      severity: "MEDIUM"
      description: "與既有 skills/main-task 重複率達 85%"
      recommended_action: "整併至 main-task 並將 duplicate-task 移至 archive"
  approved_by: "system_curator"
```
