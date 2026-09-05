# 05_TaskManager.md — HAOS 子任務管理器 (Task Manager)

> **地位**：Warm Layer（Plan / Execute / Validate 階段載入）。維護任務生命週期狀態機、依賴調度與防死鎖門禁。

---

## 🔄 子任務生命週期狀態機 (Subtask State Machine)

```text
       ┌────────────── [ Plan 完成 ] ──────────────┐
       │                                           │
       ▼                                           ▼
 [  PENDING  ]                               [  BLOCKED  ] (前置相依任務未完成)
       │                                           │
       │ (開始執行)                                 │ (前置任務 COMPLETED)
       ▼                                           ▼
 [ IN_PROGRESS ] ─────────────────────────► [  PENDING  ]
       │
       ├─── [ 執行成功 + 驗證 PASS ] ─────────► [ COMPLETED ]
       │
       └─── [ 驗證失敗 / 異常崩潰 / 熔斷 ] ───► [  FAILED   ]
                                                   │
                                                   ├── (Tier 1/2 修復重試 ≤ 2 次) ─► [ IN_PROGRESS ]
                                                   └── (Tier 3 熔斷) ──────────────► [ REPLANNING ]
```

---

## 📋 狀態轉移與並行規則 (Transition & Concurrency Rules)

1. **單步原子切換 (Atomic Transition)**：
   - 任何時刻同一個 Agent 實體內僅允許 **1 個 Subtask** 處於 `IN_PROGRESS` 狀態。
   - 嚴禁跳過 `PENDING` 直接宣告 `COMPLETED`。

2. **超時與防死鎖防護 (Deadlock & Timeout Guard)**：
   - 單一 Subtask 若持續處於 `IN_PROGRESS` 超過 60 秒無工具日誌輸出，強制標記為 `FAILED` 並進入熔斷排查。

3. **依賴中斷連鎖 (Cascading Abort)**：
   - 若某個核心前置 Subtask 標記為 `FAILED` 且無法修復，後續所有 `PENDING` Subtasks 立即轉為 `BLOCKED`，中斷執行並將控制權交還給 Planner 重新評估。
