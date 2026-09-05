# 18_Prompts.md — HAOS 提示詞庫與 Prompt Score 評分

> **地位**：Cold Layer（Prompt 版本庫維護與勝率比對機制）。

---

## 📊 Prompt 勝率評分機制 (Prompt Score Matrix)

對不同階段所使用的模組提示詞（Prompt）進行定量版本比對，杜絕「越改越差」的主觀盲目覆蓋：

$$ \text{Prompt Score} = \frac{\text{該版本 Prompt 一次性通過 Validator 驗證數}}{\text{總執行 Turn 數}} \times 100\% $$

```text
Prompt: "Planner_YAML_v1"      │ 成功率: 68%  │ 狀態: DEPRECATED
Prompt: "Planner_YAML_v2"      │ 成功率: 81%  │ 狀態: OUTDATED
Prompt: "Planner_YAML_v3"      │ 成功率: 94%  │ 狀態: ACTIVE (當前採用)
```

---

## 🛠️ Prompt 修訂標準 SOP

1. **版本派生 (Forking)**：嚴禁直接原地改寫當前 ACTIVE 的 Prompt，必須複製為 `_candidate_vN`。
2. **沙盒比對 (A/B Comparison)**：在 [21_BenchmarkSandbox.md](haos/21_BenchmarkSandbox.md) 中針對標準 Case 進行至少 5 次跑分。
3. **定量晉升 (Promotion Gate)**：只有當候選版本勝率高於現行版本至少 5% 且無新增 Side Effect 時，才允許晉升為 ACTIVE。
