# 10_KnowledgeManager.md — HAOS 知識生命週期管理器

> **地位**：Cold Layer（學習與知識分類）。負責知識的生命週期管理、去重、分層路由與防膨脹機制。

---

## 📚 知識生命週期 (Knowledge Lifecycle)

避免知識庫無限制膨脹導致檢索速度下降與 Context 浪費。所有知識必須經歷 5 階段生命週期：

```text
               [ 知識產生 / 任務復盤事實 ]
                           │
                           ▼
                    ┌──────────────┐
                    │  Temporary   │ (臨時日誌 / Session 過渡數據)
                    └──────┬───────┘
                           │ 驗證成功 >= 2 次
                           ▼
                    ┌──────────────┐
                    │ Frequently   │ (高頻使用知識 / 熱記憶)
                    │    Used      │
                    └──────┬───────┘
                           │ 使用超過 30 天且無衝突
                           ▼
                    ┌──────────────┐
                    │    Stable    │ (穩定知識 / 核心 SOP)
                    └──────┬───────┘
                           │ 發現過時 / 被新 Rule 替代
                           ▼
                    ┌──────────────┐
                    │  Deprecated  │ (棄用標記 / 暫停調用)
                    └──────┬───────┘
                           │ 滿 90 天未再使用
                           ▼
                    ┌──────────────┐
                    │   Archive    │ (歸檔至冷儲存 / 移出 Context)
                    └──────────────┘
```

---

## 🧭 知識路由規範 (Taxonomy Routing)

```text
                      [ 新知識點 (Learned Fact) ]
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
  [ 長期使用者事實 ]            [ 通用工具 SOP ]           [ 防坑策略條款 ]
        │                          │                          │
        ▼                          ▼                          ▼
 11_MemoryManager.md       12_SkillManager.md         02_Policy.md
 (MEMORY.md)               (skills/*.md)              (Policy Engine)
```

1. **使用者與系統常數** $\rightarrow$ 寫入 `~/.hermes/memories/MEMORY.md`（上限 50 行）。
2. **具體業務與執行步驟** $\rightarrow$ 提煉為標準 `~/.hermes/skills/[name]/SKILL.md`。
3. **架構選型與歷史踩坑** $\rightarrow$ 記錄於 [32_DecisionJournal.md](haos/32_DecisionJournal.md)。
4. **硬性安全防護與運行門禁** $\rightarrow$ 寫入 `~/.hermes/agent-production-rules.md`。
