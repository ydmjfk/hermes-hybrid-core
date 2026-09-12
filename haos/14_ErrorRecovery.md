# 14_ErrorRecovery.md — HAOS 熔斷與錯誤恢復 (Error Recovery)

> **地位**：Warm Layer（Validation & 異常處理階段載入）。定義四階熔斷機制、生產環境故障復原與防死循環硬門禁。

---

## ⚡ 四階熔斷復原矩陣 (Four-Tier Circuit Breaker Matrix)

```text
                             [ 遭遇異常 / 報錯 / 輸出截斷 ]
                                           │
       ┌───────────────────┬───────────────┴───┬───────────────────┐
       ▼                   ▼                   ▼                   ▼
[ Tier 1: 格式與語法 ]  [ Tier 2: 瞬時連線 ]    [ Tier 3: 邏輯/權限/不存在 ] [ Tier 4: 輸出截斷循環 ]
  (Typo / 縮排 / 標點)    (503 / Socket Timeout) (SQL錯/無權限/404)    (對話輸出長度超限)
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
 [ Executor 微調修復 ]   [ 指數退避重試 ]       [ 立即熔斷求助/重規劃 ] [ 強制極簡結論直出 ]
 (最多 2 次，禁止擴大)   (最多 2 次，間隔遞增)   (0 次盲目重試，停止)   (≤ 3 行結論，防死鎖)
```

---

## 🛡️ 實戰常見故障處置 SOP (Production Incident SOPs)

### 1. 檔案不存在 / 模組找不到 (ENOENT / ModuleNotFoundError)
- **嚴禁盲猜**：禁止在沒有驗證的情況下猜測檔名或路徑。
- **標準動作**：調用 `find` 或 `path_sanitizer` 進行單次目錄探測。若確認不存在，停止執行並如實回報。

### 2. 傳檔失敗與 NAS 路由排查 (Synology Chat Error 117)
- **Error 117 唯一真相**：Synology Chat 回傳 `error: 117` 代表 NAS 抓取附件時遇到 **HTTP 404（檔案不存在或路由不符）**，【絕對不是 IP 或網路問題】！
- **基礎架構不可竄改 (IP Immutability)**：`.env` 中的 `DOWNLOAD_BASE_URL` 為 NAS 反代固定定址，**嚴禁懷疑或嘗試修改 IP**。
- **唯一允許之排查動作**：確認檔案實體是否存在、路徑拼寫是否正確，嚴禁改寫網路設定。

### 3. 連續失敗熔斷保護 (Circuit Break Trigger)
- 當任何同一類型的工具呼叫或腳本執行連續失敗 **2 次** 時：
  1. 立即終止當前任務執行（STOP）。
  2. 捕捉最後一次 Traceback 與執行環境資訊。
  3. 產出繁體中文故障診斷簡報，主動向使用者提出決策選項。
