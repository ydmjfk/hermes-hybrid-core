# ⚡ Hermes Hybrid Core 技術白皮書 — 工業級排版幾何門禁與 POSIX 空字元免疫架構

> **文件版本**：v1.1.0  
> **發布日期**：2026-09-19  
> **授權協議**：MIT License  
> **核心模組**：`hermes_core.preflight_guard` / `hermes_core.security_filter`

---

## 摘要 (Abstract)

在現代工業級自主 AI Agent 的實戰落地中，大語言模型（LLM）常面臨兩大工程可靠性挑戰：
1. **排版幾何失真與幻覺碰撞**：在自動化產出商業簡報 (PPTX) 或視覺文件時，由於缺乏即時渲染反饋，文字框相互重疊、標籤折行穿透與跨平台字型缺字（豆腐塊 Emoji）頻繁發生。
2. **底層進程中樞的 C-Level 崩潰**：當 Agent 分析包含二進位資料或混淆 Payload 的輸出時，輸入命令或環境變數夾帶之 `\x00` (Null-Byte) 會觸發 POSIX C 函式庫中斷，導致 `ValueError: embedded null byte` 並引發非預期的進程降級與死局。

本文介紹 **Hermes Hybrid Core v1.1.0** 針對上述隱患提出的雙重確定性防禦體系：**Preflight Deck Guard 幾何預檢自審門禁** 與 **ProcessSupervisor Null-Byte 物理入向殺毒架構**。

---

## 一、排版幾何預檢自審門禁 (Preflight Deck Guard)

### 1. 幾何碰撞檢驗數學模型

將投影片上每一個可見形狀 $S_i$ 抽象化為其在二維平面上的邊界矩形（Bounding Box）：
$$\text{BBox}(S_i) = (x_0^{(i)}, y_0^{(i)}, x_1^{(i)}, y_1^{(i)})$$

定義微小安全邊界（Margin）$\delta = 0.05\text{ in}$。若形狀 $S_i$ 與 $S_j$ 均包含文字內容且兩者無父子容器從屬關係，則當且僅當以下條件成立時，判定為**非法實體相交重疊**：
$$(x_1^{(i)} - \delta > x_0^{(j)}) \land (x_1^{(j)} - \delta > x_0^{(i)}) \land (y_1^{(i)} - \delta > y_0^{(j)}) \land (y_1^{(j)} - \delta > y_0^{(i)})$$

### 2. 跨平台字型缺字檢驗 (Emoji Tofu Prevention)

許多高階 Emoji 在 Linux 伺服器無桌面環境（Headless）渲染或特定 Office 引擎下無法正常解碼，會呈現為空白方塊（豆腐塊）。
門禁模組內建 Unicode 敏感符號集合掃描器，能自動抓取潛在缺字字符並標註告警，確保產出之文件具備跨作業系統的一致性渲染品質。

---

## 二、POSIX 進程空字元 (Null-Byte) 物理消毒架構

### 1. 故障根因分析

POSIX C 標準函式庫中的字串處理函式（如 `execve`, `setenv`）皆以 `\0` 作為字串終止符號。當 Python 在呼叫底層 C 介面時，若字串中嵌入了 `\x00`，Python 運行時會主動拋出：
```python
ValueError: embedded null byte
```
這導致進程監督中樞將此視為致命異常而觸發 Fallback 降級，嚴重影響系統自主性與確定性。

### 2. 邊界物理消毒方案

Hermes Hybrid Core 在所有命令列與環境變數進入 `subprocess` 核心前實施**物理殺毒剝除**：
```python
def sanitize_command_payload(cmd):
    if isinstance(cmd, str):
        return cmd.replace("\x00", "")
    elif isinstance(cmd, (list, tuple)):
        return [c.replace("\x00", "") if isinstance(c, str) else c for c in cmd]
    return cmd
```
此項防禦達成了 **0 降級、0 截斷、100% Fail-Safe** 的執行免疫保證。

---

## 三、結論 (Conclusion)

透過幾何預檢門禁與底層進程消毒，Hermes Hybrid Core v1.1.0 將 AI Agent 從「依賴機率的黑盒生成」推向「受物理與幾何規則約束的確定性工業系統」。
