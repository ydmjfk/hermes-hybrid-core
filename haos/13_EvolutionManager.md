# 13_EvolutionManager.md — HAOS 證據驅動自我進化引擎 (Self-Evolution Engine)

> **地位**：Cold Layer（自我演進核心發動機）。定義由客觀事實驅動的 7 段式演進閉環與三維評分汰換矩陣。

---

## 🔄 7 段式證據驅動演進循環 (Evidence-Driven 7-Stage Loop)

拒絕主觀的「我覺得 Prompt 要改」。所有演進修訂必須符合嚴格的 7 段式證據循環：

```text
  ┌──────────┐     ┌──────────┐     ┌────────────┐     ┌────────────┐
  │  1.Task  │ ──► │2.Evidence│ ──► │3.Reflection│ ──► │4.Hypothesis│
  └──────────┘     └──────────┘     └────────────┘     └─────┬──────┘
                                                             │
  ┌──────────┐     ┌──────────┐     ┌────────────┐           │
  │7.Evolution│ ◄──│ 6.Learn  │ ◄── │5.Validation│ ◄─────────┘
  └──────────┘     └──────────┘     └────────────┘
```

1. **Task (任務執行)**：接收並執行實際任務。
2. **Evidence (證據採集)**：收集測試對比、語法錯誤日誌、執行時間與 Token 消耗。
3. **Reflection (復盤分析)**：進行表面原因 / 直接原因 / 根本原因 (3-Tier Root Cause) 分析。
4. **Hypothesis (假設提出)**：提出具體的修訂假設（例如：「在 Skill 增加 `--help` 前置可降低 20% 報錯」）。
5. **Validation (定量驗證)**：在 [21_BenchmarkSandbox.md](haos/21_BenchmarkSandbox.md) 沙盒中執行跑分驗證，要求 Pass Rate 必須達到 $100\%$。
6. **Learn (知識轉化)**：確定效能提升後，更新對應介質（Skill / Prompt / Policy）。
7. **Evolution (版本更新)**：記錄至 [32_DecisionJournal.md](haos/32_DecisionJournal.md) 並同步更新 [manifest.json](haos/manifest.json)。

---

## 📊 三維定量評分矩陣 (Tri-Score Matrix)

### 1. Skill Score (技能評分)
$$ \text{Skill Score} = \frac{\text{成功次數}}{\text{總調用次數}} \times 100\% $$
- **$\ge 85\%$ (Stable)**：標準 SOP。
- **$< 60\%$ (Needs Refactor)**：強制暫停自動調用，啟動重構。

### 2. Prompt Score (提示詞評分)
$$ \text{Prompt Score} = \frac{\text{一次性通過 Validator 數}}{\text{總執行 Turn 數}} \times 100\% $$
- 每次 Prompt 重構，必須並行比對分數，高分者保留，低分者回退。

### 3. Rule Score (策略條款評分)
$$ \text{Rule Score} = 100\% - \left( \frac{\text{違反該 Rule 引發熔斷數}}{\text{規則觸發次數}} \times 100\% \right) $$
- **$< 50\%$**：標記為無效或矛盾 Rule，由 `15_Auditor` 提交修剪建議並自動淘汰。
