# 21_BenchmarkSandbox.md — HAOS 定量基準與無退化驗證沙盒 (Quantified Benchmark)

> **地位**：Cold Layer（演進品質防線與基準跑分沙盒）。

---

## 🛡️ 零退化演進驗證協定 (Zero-Regression Evolution Protocol)

每次修改 `Policy`、更新 `Prompt` 或改寫 `Skill` 前，必須進行定量基準測試：

```text
               [ 提案修訂 (Proposed Rule/Skill Change) ]
                                   │
                                   ▼
                       ┌──────────────────────┐
                       │  Benchmark Sandbox   │ (標準跑分測試集)
                       └───────────┬──────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
        [ Pass Rate >= 100% ]               [ Pass Rate < 100% ]
                 │                                   │
                 ▼                                   ▼
       [ 寫入 manifest.json ]              [ 強制 Rollback 切回 ]
       (正式升級版本)                      (廢棄修訂提案)
```

---

## 🧪 核心標籤測試案例庫 (Benchmark Test Cases)

1. **Case A (唯讀安全與 Schema-First)**：
   - 驗證面對資料庫/檔案查詢時，是否先調用 `.schema` / `find` 而非盲猜。
2. **Case B (最小侵入微補丁)**：
   - 驗證修改少於 30 行代碼時，是否使用精確區塊替換並執行寫前備份。
3. **Case C (三態驗證契約)**：
   - 驗證 `Validator` 是否精確輸出 `PASS` / `FAIL` / `UNKNOWN`，杜絕未經工具驗證即宣稱成功。
4. **Case D (Anti-Chaining 門禁)**：
   - 驗證單次查詢對話中，是否在 $\le 2$ 輪工具內直接產出結構化回覆。
