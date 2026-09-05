# ⚡ Hermes Hybrid Core — 工業級 AI Agent 極速加速與確定性治理 SDK

[![授權協議: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 版本: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![能力庫健全度: 6/6 全綠](https://img.shields.io/badge/Capabilities-6%2F6%20Promoted-success.svg)]()
[![單元測試: 100% 通過](https://img.shields.io/badge/Tests-100%25%20PASS-brightgreen.svg)]()
[![安全基線: Public Release Ready](https://img.shields.io/badge/Security%20Baseline-Public%20Release%20Ready-blue.svg)](SECURITY.md)

**Hermes Hybrid Core** 是一套專為高可靠生產環境、工控自動化與大語言模型（LLM）工作流打造的**工業級 AI Agent 極速加速與確定性治理 SDK**。

可直接無縫外掛至 Hermes 或任何基於 Python 的 AI Agent 執行環境，提供 **<5ms 語意快取直出**、**<50ms 骨架流式秒回**、**微秒級樂觀平行預取**、**6 大官方工業級能力庫（CAP-001~006）** 以及 **HAOS 5.2 確定性安全治理憲法**。

---

## 🛡️ 工業級四大零容忍核心保證 (Industrial-Grade Guarantees)

* 🔒 **0 死循環（Zero Infinite Loops）**：有界 2 次修復狀態機與熔斷機制，徹底杜絕無效空轉；Fast Path 中文比對採用 $O(N)$ 演算法，徹底杜絕 ReDoS 貪婪回溯。
* 🔒 **0 假完工（Zero Hallucinated Completion）**：客觀 Exit Code / AST 語法檢驗與 Evidence Ledger 證據帳本審查（POSIX 0600 安全存取與 WAL 高並發）。
* 🔒 **沙盒防禦（Sandbox Defense）**：對抗性目錄穿越攔截、CAP-006 沙盒 MCP 隔離、Unicode NFKC 正規化與 32-hop 符號連結防穿越。
* 🔒 **0 逾時死局（Zero Timeout Hangs）**：Runtime Control 資源盾牌，大輸出物理裁剪 94%，快取長度限制 16KB，消滅長任務逾時與記憶體耗盡。

---

## 🏛️ 八層混合自主閉環架構 (Eight-Stage Hybrid Master Architecture)

```text
[ 使用者輸入 / Gateway 訊息 ]
     │
     ▼
【1. Fast Path 極速分流】(L0~L3) ──► (L0 文字問答: 物理移除所有 Tools，0.14ms 極速分流判定，直出 LLM 流式生成！)
     │ (L1 唯讀 / L2 標準 / L3 高風險)
     ▼
【2. 條件式規劃狀態機】(Conditional DAG Planner) ──► 鎖定當前 Step，隨 Verifier PASS 自動推進
     │
     ▼
【3. HAOS 安全閘門】(HAOS Safety Gate) ──► 多階對抗性攻擊防護，高風險強制審批
     │ (安全操作放行)
     ▼
【4. 實體工具執行】(Tools & Sandboxed MCP Bridge) ──► CAP-006 沙盒隔離，防禦目錄穿越與命令注入
     │
     ▼
【5. Runtime Control 資源盾牌 & 三重響應層】(hermes_core)
     │ • 方案 3 (語意快取層): semantic_cache.py   ──(高頻查詢 <5ms 直出，防快取投毒，自動脫敏)
     │ • 方案 4 (模板骨架秒回): skeleton_streamer.py ──(<50ms 貼心骨架，體感 0 延遲)
     │ • 方案 5 (樂觀預先執行): speculative_executor.py ──(平行預跑，微秒級提取)
     │ • 安全治理套件: path_sanitizer.py / security_filter.py / config_loader.py / db_pool.py
     │ • 大輸出物理裁剪 (>4KB 裁剪 94%) ──(保護 KV Cache，徹底消滅逾時)
     ▼
【6. Objective Verifier 客觀物理驗證】──► Exit Code / AST 語法檢驗 (鐵律: UNKNOWN ≠ PASS)
     │                                     (有界修復：最多 2 次上限，超限轉交人類)
     ▼
【7. Task Reviewer 完工審查】──► 調閱 Evidence Ledger 客觀證據帳本，杜絕模型假完工
     │
     ▼
【8. Skill Learning 經驗沉澱】──► 提煉標準 YAML SOP 技能，人類審批簽核落盤！
```

> **📌 本 SDK 模組與八層架構映射說明**：
> * **⚡ `hermes_core/`**：實裝 **Stage 5** 之「語意快取直出（<5ms）」、「骨架秒回流式器（<50ms）」、「樂觀平行預取管線（0.01ms）」、「SQLite WAL 安全連線池」、「任務層級熔斷器」與「企業級五大安全防禦套件」。
> * **📦 `capabilities/`**：實裝 **CAP-001 ~ CAP-006** 六大能力引擎（AST 行內補丁、DAG 狀態機重規劃、有限修復狀態機、擴展註冊隔離、Cron 死信探針、沙盒化 MCP 橋接器）。
> * **🛡️ `haos/`**：實裝 **Stage 3** 之 HAOS 5.2 確定性治理憲法與 13 種對抗性攻擊安全過濾。
> * **🔗 宿主整合**：上述模組提供統一 Python SDK 介面（`import hermes_core`），可直接無縫外掛至 Hermes 或任何 Python Agent 主迴圈，一鍵賦能完整八層自主閉環！

---

## 🚀 核心優化成果與基準測試指標 (Benchmarks)

| 核心能力模組 | 所在層級 | 實測效能指標 | 相較於原始 LLM 之效益 |
| :--- | :--- | :--- | :--- |
| **語意快取直出 (Semantic Cache)** | `hermes_core` | **< 5 ms 記憶體快取命中** | **大幅加速（0 GPU 算力負擔，自動脫敏防投毒）** |
| **骨架流式秒回 (Skeleton Streamer)** | `hermes_core` | **< 50 ms 視覺模板即時預覽** | **智慧縮退（短語自動靜默，思考氣泡精簡）** |
| **樂觀平行預取 (Speculative Prefetch)** | `hermes_core` | **0.01 ms 記憶體提取** | **底層 I/O 查詢平行預跑，零等待直取** |
| **路徑穿越防禦 (Path Sanitizer)** | `hermes_core` | **32 跳迴圈防禦 / NFKC 正規化** | **阻絕 28+ 種敏感隱藏目錄與金鑰檔案洩漏** |
| **SQL 注入防禦 (DB Pool)** | `hermes_core` | **五層安全防禦架構** | **阻斷多語句堆疊與高危 PRAGMA 攻擊 (SEC-007 驗證)** |
| **Fast-Path 0-Tool 直出 (L0~L3)** | `agent` | **1.4s 0-Tool 秒回 (提速 96.1%)** | **物理裁剪工具列表，ReDoS 免疫，根絕偽寫入** |
| **ToolLoop 防死循環斷路器** | `agent` | **連續 2 次同參數硬熔斷＋工具遮蔽** | **根治 Agent 重複工具空轉與漫遊死循環** |
| **Smart Approval 逾時防禦** | `agent` | **120s 快速拒絕 (節省 66.7% 等待)** | **無人值守時杜絕 180 秒連環卡死** |
| **行內程式碼補丁 (Inline Patch)** | `CAP-001` | **44 tokens vs 18,418 tokens** | **節省 98.50% ~ 99.8% Token 消耗** |
| **DAG 狀態機重規劃 (Planner Recovery)** | `CAP-002` | **0.01 ms 重規劃，步驟精確複用** | **零多餘重複執行，精確恢復斷點** |
| **有限次數循環修復 (Loop Recovery)** | `CAP-003` | **嚴格 2 次上限與特徵降級** | **徹底杜絕無效空轉與死循環** |
| **動態擴展註冊隔離 (Extension Layer)** | `CAP-004` | **微秒級異常隔離與自癒復原** | **確保外掛插件系統高可用彈性** |
| **Cron 死信熔斷防護 (Dead-Letter Guard)** | `CAP-005` | **3 次失敗隔離與慢速探針** | **防止排程任務崩潰引發連鎖雪崩** |
| **沙盒化 MCP 適配 (Sandboxed MCP)** | `CAP-006` | **測試基準 8/8 種攻擊向量全數阻斷** | **遞迴驗證路徑穿越、命令注入與變更性 SQL (SEC-005~007 驗證)** |

---

## 📦 專案目錄結構

```text
hermes-hybrid-core/
├── README.md                  # 專案架構說明書、Python SDK 調用範例與效能指標
├── LICENSE                    # MIT 開源授權條款
├── SECURITY.md                # 專案安全與隱私漏洞回報政策
├── config.example.yaml        # 標準設定檔範本
├── .env.example               # 環境變數範本 (嚴格權限防護)
├── requirements.txt           # Python 依賴套件清單 (經 pip-audit 弱點稽核無已知 CVE)
├── requirements.lock          # 鎖定依賴版本清單 (Reproducible Build Baseline)
├── install.sh                 # 一鍵自動化安裝與自我檢測腳本
├── check_security.py          # 零外洩自動化安全與隱私掃描工具 (支援 Git 歷史審計)
│
├── agent/                     # 🧠 Stage 1 分流與 Stage 5 運行控制
│   ├── __init__.py            # 模組統一匯入
│   ├── fast_path.py           # Fast-Path L0~L3 動態分級 (ReDoS 免疫架構)
│   └── runtime_control.py     # ToolLoopDetector 斷路器與預算監控
│
├── hermes_core/               # ⚡ 極速三重響應引擎與安全治理核心模組
│   ├── __init__.py            # 統一 SDK 入口 (import hermes_core)
│   ├── path_sanitizer.py      # 路徑穿越防禦、32 跳符號連結迴圈阻斷與敏感目錄黑名單
│   ├── security_filter.py     # 敏感憑證自動脫敏 (API Key、Bearer Token、URL 帳密過濾)
│   ├── config_loader.py       # 安全環境變數載入與 POSIX 0600 檔案權限嚴格校驗
│   ├── semantic_cache.py      # 語意快取層 (<5ms 直出、呼叫者權限驗證與 16KB 上限保護)
│   ├── skeleton_streamer.py   # 模板骨架流式器 (<50ms 貼心預覽，支援智慧縮退)
│   ├── speculative_executor.py# 樂觀平行預取執行管線
│   ├── db_pool.py             # SQLite WAL 高效連線池與 SQL 注入五層防護
│   ├── circuit_breaker.py     # 任務層級熔斷器、負向快取與死信防護
│   ├── evidence_logger.py     # 結構化客觀審計與證據日誌 (POSIX 0600 + WAL + 10,000 筆自動滾動)
│   ├── async_attachment_worker.py # 異步附件安全背景處理器
│   └── chat_client.py         # 通用通知客戶端適配器 (強制 SSL 憑證校驗與 SSRF 防禦)
│
├── docs/                      # 📚 系統架構、性能優化與安全治理技術白皮書
│   ├── 01_system_architecture_spec.md        # 系統架構技術規格書 (Master Spec)
│   ├── 02_latency_optimization_guide.md      # 極速三重響應引擎優化指南
│   ├── 03_runtime_control_and_circuit_breaker.md # 工具調用診斷與防死循環白皮書
│   ├── 04_context_hygiene_guide.md           # 上下文健康診斷與防頻繁壓縮優化指南
│   └── 05_security_governance_and_best_practices.md # 安全治理白皮書與生產防禦指南
│
├── capabilities/              # 📦 6 大官方工業級能力庫 (CAP-001~006)
│   ├── inline_patch/          # CAP-001: AST 行內補丁引擎
│   ├── planner_recovery/      # CAP-002: DAG 狀態機局部重規劃器
│   ├── agent_loop_recover/    # CAP-003: 錯誤特徵提取與循環修復
│   ├── extension_layer/       # CAP-004: 動態擴展註冊表與隔離機制
│   ├── operator_deadletter/   # CAP-005: Cron 任務死信隊列與熔斷器
│   ├── sandboxed_mcp/         # CAP-006: 沙盒化安全 MCP 適配器 (路徑沙盒化防禦)
│   └── verify_all_capabilities.py # 能力全域健康度總驗收腳本
│
├── haos/                      # 🛡️ HAOS 5.2 確定性治理憲法條文
├── tests/                     # 🧪 自動化能力與安全治理單元測試套件
│   ├── test_hermes_core.py    # 核心加速與緩存單元測試
│   └── test_security_governance.py # 安全治理五大防線 31 項測試
└── mock_data/                 # 📋 示範任務資料 (開箱即用)
```

---

## 🛠️ 快速上手指南 (Quick Start)

### 1. 系統需求
- Python 3.10+
- Linux / macOS / Windows WSL2

### 2. 下載與安裝
```bash
git clone https://github.com/ydmjfk/hermes-hybrid-core.git
cd hermes-hybrid-core

chmod +x install.sh
./install.sh
```

### 3. Python SDK 使用範例
```python
import hermes_core
from hermes_core.path_sanitizer import sanitize_path
from hermes_core.security_filter import sanitize_secrets

# 1. 語意快取直出 (<5ms 命中，具備自動脫敏與防快取投毒)
hermes_core.set_cached_response("查詢伺服器健康狀態", "伺服器集群健康運作中：0 錯誤")
cached = hermes_core.get_cached_response("查詢伺服器健康狀態")
print(cached["response_text"])

# 2. 骨架秒回流式預覽 (<50ms)
skeleton = hermes_core.generate_instant_skeleton("分析最近的系統日誌")
print(skeleton)

# 3. 敏感資訊自動脫敏過濾
text_with_secret = "連線金鑰: sk-ant-api03-mock-key-example-1234567890abcdef"
print(sanitize_secrets(text_with_secret))
# 輸出: 連線金鑰: [REDACTED]

# 4. 安全路徑防遍歷檢驗 (阻擋 .. 與敏感檔案)
try:
    safe_path = sanitize_path("../.env", base_dir="/safe/workspace")
except PermissionError as e:
    print("安全閘門成功攔截非法存取:", e)
```

### 4. 執行全域自動化驗證
```bash
source venv/bin/activate

# 1. 驗證 6 大官方能力庫
python3 capabilities/verify_all_capabilities.py

# 2. 驗證極速響應核心引擎
python3 -m unittest discover tests/

# 3. 驗證安全治理五大防線規格 (31 項單元測試)
pytest tests/test_security_governance.py

# 4. 執行全專案零私密資訊與隱私掃描 (100% 通過)
python3 check_security.py
```

---

## 📄 開源授權條款 (License)
本專案採用 [MIT 授權協議](LICENSE) 開源發布。
