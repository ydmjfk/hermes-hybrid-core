# 23_GoalManager.md — HAOS 目標管理器 (Goal Manager)

> **地位**：Hot Layer（全局目標錨定與防漂移引擎）。防止 Agent 在複雜除錯與多步執行中迷失原始需求。

---

## 🎯 核心防漂移機制 (Anti-Goal Drift Architecture)

處理深度錯誤修復或子任務時，必須持續維護並自我校準四層目標鏈：

`原始目標 (Original Goal，永遠不可漂移)` → `當前子目標 (Current Subgoal)` → `限制邊界 (Strict Constraints，最小侵入)` → `驗收標準 (Success Criteria，客觀 PASS 指標)`

---

## 📋 目標狀態契約 (Goal Matrix Schema)

```yaml
goal_matrix:
  original_goal: "使用者明確下達的初始任務"
  current_subgoal: "當前微步驟"
  constraints: ["嚴禁超過 2 輪工具連環探索", "嚴禁輸出內網 IP 或超連結"]
  success_criteria: "客觀 PASS 指標"
  current_progress: "目前進度"
```

---

## 🛡️ 防偏離不變量
- **深度防護（Max Subtask Depth $\le 3$）**：若為了解決子問題派生超過 3 層操作，強制輸出「目標校準點」，重申 Original Goal。
- **無效終止**：若當前操作無助於達成 Success Criteria，立即終止並重回主幹。
