# HAOS — Hermes Agent Operating System (v5.2.0 Hardened & Production Aligned)

> **HAOS** 是一套獨立於底層 LLM 模型的通用 Agent 作業系統架構。它將 LLM 從單純的「對話/指令執行者」提升為具備**最高憲法約束、嚴格策略門禁、防卡死/防漫遊工作流生命週期、與生產實戰高度對齊**的自主運算內核。

---

## 🏛️ 系統架構理念 (Architecture Philosophy)

```text
                        ┌─────────────────────────────┐
                        │      LLM Engine (Model)     │
                        │ (Hermes / Qwen / GLM / GPT) │
                        └──────────────▲──────────────┘
                                       │
                               HAOS Kernel Architecture
                                       │
     ┌──────────────────┬──────────────┴───┬──────────────────┐
     ▼                  ▼                  ▼                  ▼
Governance & Safety  Workflow & Tasks    Learning Engine    Operations & Perf
(Constitution/Policy)(Plan/Exec/Validate) (Memory/Knowledge) (Metrics/Recovery)
     └──────────────────┴──────────────┬───┴──────────────────┘
                                       │
                          ┌────────────▼────────────┐
                          │   HAOS CLI Helper Tool  │
                          │ (~/.hermes/scripts/haos)│
                          └─────────────────────────┘
```

### 1. 模型獨立性 (Model-Agnostic)
HAOS 不依賴任何單一 LLM 廠商的私有 API。不論底層搭配開源模型（Qwen、GLM、DeepSeek）或商用模型（Gemini、GPT、Claude），HAOS 內核規範、工作流與驗證邏輯均 100% 通用。

### 2. 證據驅動演進閉環 (Evidence-Based Evolution Cycle)
拒絕主觀的臆測修改，所有能力增強與規則演進必須遵循客觀證據閉環：
```text
Task ──► Evidence ──► 3-Tier Reflection ──► Hypothesis ──► Validation ──► Evolution
```

---

## 📁 核心模組全景導覽 (Core Modules Overview)

### 🏛️ 核心基石與安全治理 (Governance & Safety)
- **[00_Constitution.md](haos/00_Constitution.md)**：最高行為憲法（黃金 7 大不可變原則，Immutable Core）。
- **[01_Core.md](haos/01_Core.md)**：Agent OS 核心定位與繁中溝通契約。
- **[02_Policy.md](haos/02_Policy.md)**：策略引擎與執行不變量。
- **[19_Config.md](haos/19_Config.md)**：全域系統配置與環境常量。
- **[20_SecurityFilter.md](haos/20_SecurityFilter.md)**：敏感資訊與 Secret 自動脫敏器。
- **[27_SafetyPermission.md](haos/27_SafetyPermission.md)**：Level 0~7 漸進式權限矩陣與安全確認門禁。

### ⚡ 工作流與執行引擎 (Workflow & Execution Engine)
- **[03_Workflow.md](haos/03_Workflow.md)**：雙軌工作流（Fast-Path 直出 vs 標準 8 階段生命週期）。
- **[04_Planner.md](haos/04_Planner.md)**：結構化 YAML 任務規劃器（僅唯讀分析，不動手）。
- **[05_TaskManager.md](haos/05_TaskManager.md)**：狀態機轉換、超時與防死鎖管理器。
- **[06_Executor.md](haos/06_Executor.md)**：純粹執行器（最小影響半徑、精確區塊修改、寫前備份）。
- **[07_ToolManager.md](haos/07_ToolManager.md)**：能力路由、Schema-First、Path Sanitizer 與 Anti-Chaining 防漫遊門禁。
- **[08_Validator.md](haos/08_Validator.md)**：標準三態客觀結果驗證器 (`PASS` / `FAIL` / `UNKNOWN`)。
- **[14_ErrorRecovery.md](haos/14_ErrorRecovery.md)**：四階熔斷矩陣、生產環境故障復原與 Synology Chat Error 117 SOP。
- **[17_Checklists.md](haos/17_Checklists.md)**：實戰作業標準檢查清單庫。

### 🧠 知識、記憶與演化 (Learning & Memory)
- **[10_KnowledgeManager.md](haos/10_KnowledgeManager.md)**：結構化知識庫管理。
- **[11_MemoryManager.md](haos/11_MemoryManager.md)**：長短期記憶分層與精簡標準。
- **[12_SkillManager.md](haos/12_SkillManager.md)**：Skill 生命週期管理與手動技能保護。
- **[13_EvolutionManager.md](haos/13_EvolutionManager.md)**：自適應規則演進機制。
- **[32_DecisionJournal.md](haos/32_DecisionJournal.md)**：架構決策日誌（詳細記錄技術選型 WHY）。

### 🚀 運維與效能優化 (Operations & Performance)
- **[21_BenchmarkSandbox.md](haos/21_BenchmarkSandbox.md)**：沙盒評測機制。
- **[28_RollbackManager.md](haos/28_RollbackManager.md)**：快照自動回滾與復原協定。
- **[35_PerformanceOptimization.md](haos/35_PerformanceOptimization.md)**：0-Tool Fast-Path、日誌批次查詢與 Token 節流最佳實踐。
