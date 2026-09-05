# 30_KnowledgeGC.md — HAOS 知識垃圾回收與壓縮器 (Knowledge Garbage Collector)

> **地位**：Cold Layer（知識壓縮、去重、瘦身與歸檔）。防止知識庫膨脹、檢索變慢與 Prompt 稀釋。

---

## 🧹 知識垃圾回收與壓縮機制 (Knowledge Garbage Collection)

```text
                           [ 現有知識與 Skill 庫 ]
                                      │
       ┌──────────────────────────────┼──────────────────────────────┐
       ▼                              ▼                              ▼
 [ 相似 Skill 80% 重複 ]    [ 超過 90 天未調用技能 ]        [ MEMORY.md 舊 Log / 冗餘 ]
       │                              │                              │
       ▼                              ▼                              ▼
  (Merge 擬合壓縮)              (Archive 移出 Context)         (Prune 刪除廢言)
```

---

## 📋 垃圾回收觸發條款 (Trigger Policies)

1. **技能擬合 (Skill Merge)**：
   - 若 Skill A 與 Skill B 步驟重複率 $> 80\%$，自動進行結構化合併，保留單一最優版本。
2. **過時歸檔 (Archive)**：
   - 滿 90 天未被調用且得分低於 60% 的 Skill，自動移至 `~/.hermes/skills/archive/`，不進入活躍載入清單。
3. **記憶瘦身 (Memory Pruning)**：
   - `MEMORY.md` 超過 50 行時，自動觸發壓縮修剪，移除非核心常數與過期資訊。
4. **決策日誌持久化**：
   - 僅精華架構選型與踩坑 SOP 留存於 [32_DecisionJournal.md](haos/32_DecisionJournal.md)，瑣碎的日常除錯日誌於 30 天後自動清除非必要 Traceback。
