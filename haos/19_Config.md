# 19_Config.md — HAOS 全域系統配置 (Global Configuration)

> **地位**：Hot Layer（系統參數配置與常量）。

---

## 全域系統配置規範 (System Configuration Spec)

1. **路徑配置 (Paths)**
   - 系統根目錄：`${HERMES_HOME}/`
   - HAOS 內核目錄：`${HERMES_HOME}/haos/`
   - 日誌目錄：`${HERMES_HOME}/logs/`
   - 技能目錄：`${HERMES_HOME}/skills/`

2. **限制與臨界值 (Thresholds & Limits)**
   - 相同假設最多 Try 次數：`2`
   - 腳本執行 Timeout：`300 秒`
   - Inline Replace 重寫門檻：`30 行`
   - 知識 Archive 天數：`90 天`

3. **語言配置 (Language & Culture)**
   - 全域語言：`zh-TW` (台灣繁體中文 100%)
