# 31_CapabilityDiscovery.md — HAOS 能力動態探索與匹配 (Capability Discovery)

> **地位**：Warm Layer（任務能力需求感知與工具路由匹配）。

---

## 🧭 4 層動態能力匹配拓撲 (Capability Matching Hierarchy)

接收到任務時，Agent 自動自底向上掃描並匹配最佳工具鏈，拒絕盲目硬幹：

```text
  Task (使用者意圖解析)
         │
         ▼
  Capability Detection (系統當前能力探測：有無專用 Script / CLI / API)
         │
         ▼
  Skill Routing (檢索 ~/.hermes/skills/ 對應 SOP)
         │
         ▼
  Tool Execution (調用 Schema-First 驗證過之工具)
```

---

## 🚫 能力缺口處置 SOP (Missing Capability SOP)
1. 若當前環境缺乏相應依賴或 API，**明確向使用者說明缺口與建議依賴**。
2. 嚴禁憑空捏造不存在的命令列工具或假設虛構的 API 端點。
