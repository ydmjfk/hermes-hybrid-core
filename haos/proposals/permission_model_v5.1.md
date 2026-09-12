# Permission Model v5.1 Proposal

> **Proposal ID**: PROP-20260808-03  
> **Status**: ✅ APPROVED BY HUMAN  
> **Evidence Level**: [已有依據]  
> **Author**: HAOS v4 Self-Analysis  
> **Date**: 2026-08-08  
> **Approved By**: hermes_user  
> **Approved At**: 2026-08-17

## 修正後的權限分級矩陣

| Level | 操作 | 授權條款 |
|---|---|---|
| L0 | Read | Autonomous |
| L1 | Analyze | Autonomous |
| L2 | Create | Autonomous |
| L3 | Modify | 一般工作檔案 → Autonomous + Log<br>Skill / Prompt / Workflow → Proposal<br>Immutable Core → Human Approval |
| L4 | Execute | 低風險工具 → Autonomous + Log<br>中高風險工具 → Human Approval |
| L5 | Install | Human Approval |
| L6 | System Change | Human Approval |
| L7 | Delete | Human Approval |

## 重要規則

- 「提示」不等於「批准」。
- 需要 Human Approval 的操作，在沒有批准之前必須停止執行。
