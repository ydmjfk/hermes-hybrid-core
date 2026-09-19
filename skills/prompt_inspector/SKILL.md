---
name: prompt_inspector
description: 提示詞品質系統性體檢與優化技能：依據 HAOS 確定性治理憲法，為提示詞評分 (0~100 分)、診斷潛在返工風險，並自動生成推薦優化版提示詞。
category: productivity
priority: high
---

# 🛡️ 提示詞品質體檢技能 (Prompt Quality Inspector)

本技能為 AI Agent 與操作者的**前置防呆中樞**。在發出重要指令或執行複雜任務前，進行「系統憲法 + 邊界防禦」的系統性體檢，消滅 AI 幻覺、越獄攻擊與擅專返工。

---

## 🚀 核心 CLI 工具用法

```bash
# 1. 體檢提示詞並取得評分與推薦優化版
python3 skills/prompt_inspector/scripts/inspect_prompt.py "幫我重構資料庫連線池"

# 2. 以 JSON 格式輸出供管線自動審查
python3 skills/prompt_inspector/scripts/inspect_prompt.py --json "做一份系統架構簡報"
```

## 📊 評估維度與門禁規則

1. **CHK_PPT_GEOMETRY**：視覺排版幾何預檢門禁（防文字方塊重疊、防 Emoji 豆腐塊）。
2. **CHK_STYLE_CONFIRM**：架構重構與重大設計反問門禁（先確認方案再動手）。
3. **CHK_SINGLE_TASK**：單一職責與最小授權（嚴禁擅專與擴大修改範圍）。
4. **CHK_EXACT_RECORD**：客觀字面照錄（防主觀臆測與過度潤色）。
5. **CHK_CLI_FIRST**：確定性成熟工具優先調用（避免多輪推理風險）。
6. **CHK_PROMPT_INJECTION_DEFENSE**：非信任外部資料無菌防護隔離。
