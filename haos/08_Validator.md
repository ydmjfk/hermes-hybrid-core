# 08_Validator.md — HAOS 結果驗證器 (Validator)

> **地位**：Warm Layer（Validate 階段載入）。定義三態客觀判定標準與反自欺欺人驗證契約。

---

## ⚖️ 標準三態判定契約 (Tri-State Verification Contract)

Validator 僅能輸出以下三態之一，嚴禁輸出模糊、不確定的自然語言承諾：

```text
       ┌───────────────────────────────┐
       │   Validator 三態輸出契約      │
       └──────────────┬────────────────┘
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   [ PASS ]        [ FAIL ]      [ UNKNOWN ]
 (客觀證據齊備)  (報錯/斷言失敗) (外部依賴缺失需人工)
       │              │              │
       ▼              ▼              ▼
   [ 進入 Reflect ]  [ 觸發熔斷恢復 ] [ 提示使用者確認 ]
```

### 1. `PASS` (驗證通過)
- **條件**：必須具備具體的工具輸出、狀態碼 `0`、測試案例全數通過或輸出比對一致之客觀日誌。
- **後續動作**：解除執行鎖定，推進至 `Reflect` 階段。

### 2. `FAIL` (驗證失敗)
- **條件**：命令回傳非 0 狀態碼、出現 Traceback、AssertionError 或未達成 Plan 中的 `success_criteria`。
- **後續動作**：記錄精確錯誤日誌與環境快照，觸發 [14_ErrorRecovery.md](haos/14_ErrorRecovery.md)。

### 3. `UNKNOWN` (無法自動確認)
- **條件**：缺乏可直接執行的自動化測試工具（如需實體硬體反應、外部付費 API 回調或人眼介面排版確認）。
- **後續動作**：如實列出已驗證部分與未驗證部分，請求使用者進行人工確認。

---

## 📋 驗證輸出標準 Schema

```yaml
validation_report:
  timestamp: "2026-08-26T00:00:00Z"
  status: "PASS" | "FAIL" | "UNKNOWN"
  verification_command: "python3 test_script.py"
  evidence_summary: "Exit Code 0; 5/5 tests passed in 0.42s"
  unverified_aspects: [] # 若為 UNKNOWN 則列出
  root_cause: null # FAIL 時必須填寫根本原因
  verdict_action: "PROCEED" | "TIER1_FIX" | "TIER2_RETRY" | "TIER3_REPLAN"
```
