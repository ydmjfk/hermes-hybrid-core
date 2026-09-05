# 12_SkillManager.md — HAOS 技能管理器與評分系統 (Skill Manager)

> **地位**：Cold Layer（技能生命週期、去重、修補與手動保護）。

---

## 🛡️ Skill 建立與演化四大防錯鐵律 (Anti-Hallucination & Deduplication)

為避免模型自主提煉 Skill 時產生重複、衝突與幻覺，所有 Skill 的建立與變更必須嚴格遵守以下流程：

### 1. 查重先行原則 (Deduplication Check First)
- 任何提煉或新建 Skill 前，**必須先檢索 `~/.hermes/skills/` 既有名稱與關鍵字**。
- 若已存在同領域或目標重疊之 Skill，**嚴禁**建立名稱相近或功能平行的重複模組。

### 2. 修補取代新建原則 (Patch Over New Policy)
- 當發現既有流程有新規則、例外狀況或參數調整時，**唯一允許的作法是直接修改擴充既有的 `SKILL.md`**，杜絕版本碎片化。

### 3. 手動創建技能保護 (Manual Skill Protection)
- 若技能為 `created_by=None` 或標記為手動創建，背景 Review 或自動化腳本**絕不可調用 `skill_manage` 強行 patch/edit**，僅可向使用者提出建議。

### 4. 實體驗證門檻 (Zero-Hallucination Gate)
- Skill 內部所引用的所有 Shell 指令、Python 腳本路徑（如 `~/.hermes/scripts/*.py`）、目錄名稱與 API 端點：
  - **建立前必須實際測試確認其「實體存在且執行無誤」**。
  - **嚴禁**在 Skill 中憑空捏造或猜測未經驗證的腳本檔名與參數。

---

## 📊 技能評分系統 (Skill Score Matrix)

系統定期追蹤每個 Skill 的執行成功率，自動識別低效或惡化的 Skill：

$$ \text{Skill Score} = \frac{\text{使用該 Skill 成功完成的任務數}}{\text{總調用次數}} \times 100\% $$

- **高分 Skill ($\ge 85\%$)**：維持使用，標記為穩定 SOP。
- **中分 Skill ($60\% \sim 84\%$)**：需加入警告條款與 Checkpoint。
- **低分 Skill ($< 60\%$)**：強制標記 `NEEDS_REFACTOR`，暫停自動調用，觸發技能重構程序。

---

## 📝 技能標準範本格式 (Standard Skill Template)

所有技能檔 (`~/.hermes/skills/[name]/SKILL.md`) 必須具備：
1. **Frontmatter**：`name`, `description`, `created_by`, `version`
2. **Prerequisites & Triggers**：觸發條件與適用場景
3. **Step-by-Step SOP**：清晰步驟指令
4. **Verification & Exit Criteria**：PASS 驗收條件
5. **Common Pitfalls & Warnings**：常見陷阱與避坑規範
