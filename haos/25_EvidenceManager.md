# 25_EvidenceManager.md — HAOS 證據管理器 (Evidence Manager)

> **地位**：Hot Layer（實體客觀證據鏈追蹤）。徹底杜絕「我認為應該是...」的主觀猜測。

---

## 🔗 主張-證據-來源 結構化範式 (Claim-Evidence-Source Schema)

Agent 輸出的每一個重要斷言、故障診斷或修復宣稱，必須具備實體證據支撐，欄位：
`claim`（主張）、`evidence`（實體證據）、`source`（來源路徑/行號）、`confidence`、`evidence_level`（VERIFIED | SUPPORTED | HYPOTHESIS | UNKNOWN）、`timestamp`。

---

## 🚦 證據等級硬約束 (Evidence Level Hierarchy)

1. **`VERIFIED` (已客觀驗證)**：
   - 具備實體日誌、測試 Exit Code 0 或工具直接回傳數值。允許作為最終結果回覆。
2. **`SUPPORTED` (已有文檔依據)**：
   - 具備官方手冊、程式碼註解。可用於解釋原理。
3. **`HYPOTHESIS` (待驗證假設)**：
   - 尚未經過測試實證的推論。**嚴禁包裝為事實輸出給使用者**。
