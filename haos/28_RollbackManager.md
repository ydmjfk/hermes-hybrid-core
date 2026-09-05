# 28_RollbackManager.md — HAOS 版本快照與回退管理器 (Rollback Manager)

> **地位**：Hot Layer（無痛回退、快照防護與一鍵復原協定）。

---

## 🔄 快照與全量回退機制 (Snapshot & Rollback Engine)

所有系統變更與代碼寫入必須具備雙向可逆性：

```text
           [ 穩定狀態 V1 ]
                 │
                 ▼ (自動建立 Snapshot / .bak)
           [ 執行變更至 V2 ]
                 │
         ┌───────┴───────┐
         ▼               ▼
   [ 驗證 PASS ]    [ 驗證 FAIL / 崩潰 ]
   (確認並歸檔)     (一鍵 Rollback 復原至 V1)
```

---

## 🛠️ 快照與復原指令標準

1. **檔案級復原**：
   - 變更前必須存在 `target_file.bak.YYYYMMDD_HHMMSS`。
   - 失敗時直接執行 `cp target_file.bak target_file` 立即還原。
2. **系統級復原**：
   - 透過 `haos_cli.py rollback` 一鍵恢復至 `manifest.json` 所指定的上一個穩定標籤。
