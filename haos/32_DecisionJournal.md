# 32_DecisionJournal.md — HAOS 決策日誌與理由記錄 (Decision Journal)

> **地位**：Cold Layer（記錄重要技術決策理由「WHY」而非僅記錄「WHAT」）。供未來遇到類似技術選型或架構問題時參考。

---

## 決策日誌結構化範式 (Decision Journal Schema)

記錄「為什麼做這個決定」，供未來遇到類似技術選型或架構問題時參考：

```yaml
decision_journal_entry:
  decision_id: "DEC-20260808-01"
  problem: "選擇本機量化模型參數 (Q5_K_M vs Q6_K)"
  options_considered:
    - "Q6_K: 精確度較高，但 VRAM 佔用接近臨界值"
    - "Q5_K_M: 速度極快，記憶體保留充裕"
  selected_option: "Q5_K_M"
  rationale_why: "考量多 Tool 呼叫時需保留足夠 VRAM 給 KV Cache，防死鎖"
  observed_result: "系統穩定運行 48 小時無 VRAM 溢位"
  future_takeaway: "優先選用 Q5_K_M 量化版本"
  timestamp: "2026-08-08T03:34:00Z"
```

---

## DEC-20260826-01：HAOS 全量 35 模組實戰強化與生產門禁對齊

```yaml
decision_journal_entry:
  decision_id: "DEC-20260826-01"
  problem: "HAOS 既有 35 個 Markdown 模組多數篇幅過短，存在形式化空泛與缺乏具體防卡死/防漫遊約束的問題"
  evidence:
    - "多數模組僅有抽象概念描述，缺乏明確 Schema、防連環呼叫限制與錯誤處理 SOP"
    - "生產環境需要成熟的 Fast Path 0-Tool 直出、Schema-First 與客觀驗證排障規則"
  options_considered:
    - "方案 A: 僅更新 00_Constitution，其餘模組維持原狀"
    - "方案 B: 大幅刪減模組檔案"
    - "方案 C: 對全量可寫模組進行深度重構、充實具體 SOP 並與生產門禁全面對齊"
  selected_option: "方案 C"
  rationale_why: "確保 Guardian Daemon 零告警相容性的同時，徹底消除形式主義，將實戰防護邏輯注入全量模組，大幅提升 Agent 執行確定性與 Token 效率"
  implementation:
    - "升級 00_Constitution 為黃金七大不變原則"
    - "全面重構 03~35 可寫模組，填入具體 Schema、防漫遊門禁、三態驗證與四階熔斷矩陣"
    - "更新 manifest.json 至 v5.2.0"
  observed_result: "全量 35 模組規範結構完備，haos-guardian 服務持續 active 穩定運行"
  future_takeaway: "所有 Agent 規範文件必須具備可執行的具體邊界條件，杜絕純概念空泛描述"
  approved_by: "System Architect"
  timestamp: "2026-08-26T00:15:00+08:00"
```

---

## DEC-20260823-01：Context 與常駐 Prompt 精簡優化

```yaml
decision_journal_entry:
  decision_id: "DEC-20260823-01"
  problem: "效能分析發現長上下文對話中 Token 消耗過高，需針對 Context 與常駐 Prompt 精簡優化"
  evidence:
    - "常駐基底約佔 13k-16k tokens，對話歷史與工具輸出是 context 膨脹主因"
    - "動態 Skill 載入已實作：SKILL 完整內容非常駐，僅名稱+描述索引常駐"
    - "過度砍除工具輸出截斷會觸發重讀反效果 (re-read penalty)"
  options_considered:
    - "方案 A: 系統提示詞去重精簡"
    - "方案 B: 大幅砍除 tool_output.max_bytes"
    - "方案 C: 提示詞去重 + 保留適度工具輸出門檻"
  selected_option: "方案 C"
  rationale_why: "系統提示詞去重零風險且能穩定省 token；維持適當的工具輸出長度可避免 Agent 重複讀取關鍵檔案，淨效果最優"
  implementation:
    - "系統提示詞結構去重與精簡"
    - "落實動態技能索引與依需載入"
  observed_result: "Token 消耗降低，回應速度提升且無截斷重讀問題"
  future_takeaway: "效能優化應優先管理對話歷史與索引結構，避免過度截斷工具輸出"
  approved_by: "System Architect"
  timestamp: "2026-08-23T10:10:00+08:00"
```

---

## DEC-20260823-02：Agent 模組單一職責與程式強制架構

```yaml
decision_journal_entry:
  decision_id: "DEC-20260823-02"
  problem: "避免技能模組過於厚重導致 Context 浪費與 LLM 脆弱推理問題"
  principles_applied:
    - "單一職責: 一個模組專注一項核心能力"
    - "正文精簡: 刪除陳腐說明，正文只保留路由分流、防呆紅線與執行 SOP"
    - "詳細參考外置: 將龐大規格表移至 references/ 檔案，依需讀取"
    - "脆弱步驟程式強制: 複雜運算與正則比對 100% 由 Python 腳本接管，禁止 LLM 空想"
  actions_taken:
    - "全面推行輕量化技能結構規範"
    - "建立精確工具執行與驗證管線"
  observed_result: "模組載入 Token 消耗顯著降低，計算與格式輸出 100% 零誤差"
  future_takeaway: "所有涉及精確計算與規格比對之業務，由專用腳本處理；LLM 只作高階路由與語義理解"
```

---

## DEC-20260907-01：沙盒深度改造為寬鬆生產模式（Permissive Production Sandbox Mode）

```yaml
decision_journal_entry:
  decision_id: "DEC-20260907-01"
  problem: "裝設嚴格沙盒後 Agent 頻繁卡住、延遲暴增與多項指令阻斷（Read-only file system, Network unreachable, SYNTAX_REJECTED）"
  evidence:
    - "curl/sleep/python3 -c 等標準指令遭 SyntaxGuard/ASTClassifier 拋出 SYNTAX_REJECTED"
    - "網路全面被 --unshare-net 隔離，本機/局域網模型 API 測速斷線"
    - "~/.hermes 唯讀阻斷 SQLite WAL 寫入與附件排隊"
    - "/snap 未掛載導致 Headless Chromium 報錯"
    - "連續錯誤資訊汙染對話上下文，使雙 RTX 5070 Ti 的 KV-cache 命中率由 99.6% 暴跌至 39%，Prompt 評估延遲從 1s 暴增至 40~80s，觸發 30s 逾時中斷"
  options_considered:
    - "方案 A: 完全移除沙盒（退回裸機執行，失去安全邊界）"
    - "方案 B: 僅手動追加白名單（治標不治本，未來遇到新工具依舊報錯）"
    - "方案 C: 保留沙盒骨架並深度改造為寬鬆生產模式（開放網路、開放 ~/.hermes 可控讀寫、掛載 /snap、放寬語法守衛但嚴守 sudo/eval 底線）"
  selected_option: "方案 C"
  rationale_why: "架構決策採方案 C：在維持真實惡意攻擊阻斷（sudo/su、eval、curl|bash、base64 混淆）的前提下，徹底釋放 Agent 正常運算、測速與轉檔能力，消弭報錯引發的 KV-cache 失效與延遲雪崩"
  implementation:
    - "BwrapExecutor: 移除 --unshare-net 開放宿主網路，掛載 /snap, /var/lib/snapd, /opt，實裝 allow_hermes_rw（讀寫 ~/.hermes 同時嚴格唯讀 security/ 與 .env）"
    - "SyntaxGuard: 新增 permissive_mode，放寬 python3 -c, 變數展開與 nested shell，嚴格阻斷 PRIVILEGE_ESCALATION 與 eval/管道直譯"
    - "ASTClassifier: 擴編 L0/L1/L2 目錄，未編目命令平滑回退至 L2 沙盒隔離，嚴格拒絕 sudo/su"
    - "HermesAdapter: 讀取 permissive_mode 與 sandbox_allow_network，動態配置策略合約"
    - "生產設定: ~/.hermes/config.yaml 開啟 permissive_mode: true 與 sandbox_allow_network: true"
    - "測試套件: hermes_v3_staging 全量 96 項測試 100% 通過，重啟 hermes-gateway.service 順暢運作"
  observed_result: "指令不再阻斷，網路與資料庫正常運作，消除報錯文字對上下文快取的侵蝕，推論恢復 78+ t/s 高速響應"
  future_takeaway: "安全機制必須與生產環境真實工具鏈緊密適配；沙盒邊界應採『嚴格封鎖真特權、寬鬆容納工具鏈』的生產型設計"
  approved_by: "System Architect (User Decision)"
  timestamp: "2026-09-07T17:30:00+08:00"
```

