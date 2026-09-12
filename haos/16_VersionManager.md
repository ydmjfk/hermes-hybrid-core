# 16_VersionManager.md — HAOS 版本管理器 (Version Manager)

> **地位**：Cold Layer（版本控管、語意化發布與快照回滾）。

---

## 🏷️ 語意化版本與演進階梯 (SemVer Evolution Matrix)

HAOS 採用嚴格的 `vMAJOR.MINOR.PATCH` 格式管理全系統規範演進：

- **MAJOR (vX.0.0)**：核心 [00_Constitution.md](haos/00_Constitution.md)、狀態機工作流或底層安全架構發生破壞性重構。
- **MINOR (v5.X.0)**：新增模組、引入新 Skill 類別、擴充 Policy 引擎或發布重大效能優化。
- **PATCH (v5.2.X)**：微調提示詞、修訂錯字、修正單一 Skill SOP 參數或補充 Checklist。

---

## 📋 版本清冊契約 (`manifest.json`)

每次版本發布必須在 [manifest.json](haos/manifest.json) 中記錄完整的演進理由與前置回退標籤：

```json
{
  "haos_version": "5.2.0",
  "system_name": "Hermes Agent OS (HAOS v5.2 Production Hardened)",
  "updated_at": "2026-08-26T00:00:00Z",
  "active_layers": ["hot", "warm", "cold"],
  "history": [
    {
      "version": "5.2.0",
      "date": "2026-08-26",
      "changes": "全面深化 35 模組：整合 0-Tool Fast Path、Anti-Tool-Chaining、四階熔斷與生產環境防護硬門禁",
      "rollback_tag": "v5.1.0"
    }
  ]
}
```

---

## 🔄 一鍵回滾觸發條件
- 若演進發布後 24 小時內連續發生 2 次以上系統級熔斷，立即執行 `haos_cli.py rollback` 退回至 `rollback_tag` 指定版本。
