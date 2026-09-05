# 11_MemoryManager.md — HAOS 記憶管理器 (Memory Manager)

> **地位**：Cold Layer（記憶儲存、檢索與極簡約束）。維護系統長短期記憶的邊界與防膨脹門禁。

---

## 🧠 記憶雙軌分層架構 (Dual-Track Memory System)

1. **短期工作記憶 (Working Memory)**：
   - 存於當前會話 Session、`/tmp/` 臨時檔案中。
   - 包含單次任務的中間結果、Command Log、暫存變數。任務結束後自動由系統回收釋放。

2. **長期核心記憶 (Long-Term Memory)**：
   - 寫入 `~/.hermes/memories/MEMORY.md`。
   - **僅包含**：使用者個人常數偏好（統編、車號、稱呼）、全域不可變鐵律、核心 Port 與環境變數。

---

## 🛡️ Skill 優先與記憶去重原則 (Skill-Over-Memory Rule)

為維持長期記憶極度輕量與超快推論速度，嚴格執行職責分離：

1. **SOP 與業務流程歸 Skill，嚴禁寫入 MEMORY.md**：
   - 任何單據歸檔路徑、檔名規則、OCR 勾稽、下載連結產生步驟等，**一律由專屬 Skill 承載**。
   - **嚴禁**將 Skill 已定義的重複流程抄寫進 `MEMORY.md`。
2. **50 行輕量預算限制 (Lightweight 50-Line Budget)**：
   - `MEMORY.md` 總行數強制維持在 **50 行以內**。
   - 超過時由 Curator 或 Knowledge GC 自動修剪冗餘。
3. **背景反思防護 (Background Review Guard)**：
   - 背景反思 (`bg-review`) 階段僅能使用 `memory` 與 `skill_manage` 工具，**嚴禁呼叫 `patch`、`read_file` 或 `execute_code`**。

---

## 🚫 寫入審查門禁 (Write Filter Guard)

- ❌ **嚴禁寫入**：Skill 已涵蓋的 SOP、一次性錯誤 Log、臨時測試變數、暫存路徑、對話流水帳。
- ✅ **允許寫入**：使用者個人專屬事實（統編、車號、持股成本常數）、系統層頂級不變配置。
