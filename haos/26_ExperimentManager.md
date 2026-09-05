# 26_ExperimentManager.md — HAOS 實驗與 A/B 測試管理器 (Experiment Manager)

> **地位**：Cold Layer（修訂演進前的 A/B 實驗驗證與候選比對）。

---

## 🧪 演進 A/B 測試比對機制 (A/B Testing Framework)

所有 Policy、Prompt 或 Skill 的修訂提案，必須透過沙盒進行客觀數據對比：

```text
                     [ 新修訂提案 (Candidate V2) ]
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │    Experiment Sandbox A/B Test      │
               └──────────┬───────────────┬──────────┘
                          │               │
                          ▼               ▼
                   [ 既有版本 V1 ]   [ 候選版本 V2 ]
                   (成功率: 75%)    (成功率: 92%)
                          │               │
                          └───────┬───────┘
                                  ▼
                     [ 評估：V2 胜出 ──► 允許升級 ]
```

---

## 📋 實驗執行標準流程

1. **基準建立 (Baseline)**：鎖定現有版本 V1 成功率指標。
2. **對照跑分 (A/B Runs)**：在 [21_BenchmarkSandbox.md](haos/21_BenchmarkSandbox.md) 針對測試案例執行 $N \ge 5$ 次跑分。
3. **數據裁決**：若 $Score(V2) > Score(V1)$ 且未引發副作用，始能正式合併；否則直接拋棄提案。
