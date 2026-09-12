# 29_PerformanceManager.md — HAOS 效能與遙測管理器 (Performance Telemetry)

> **地位**：Cold Layer（效能分析、Token 消耗統計與資源監控）。

---

## 📈 效能遙測指標矩陣 (Performance Telemetry Schema)

每一次任務執行完成後，系統記錄資源消耗數據以利持續優化：

```yaml
performance_telemetry:
  task_id: "TASK-YYYYMMDD-SEQ"
  input_tokens: 12500
  output_tokens: 1400
  tool_calls_count: 2 # 嚴格受限於 Anti-Tool-Chaining 門禁
  retry_count: 0
  execution_duration_sec: 3.2
  peak_memory_mb: 48.5
  overall_status: "SUCCESS"
```

---

## 🚨 效能預警與自動優化建議
- **Tool 呼叫超標警告**：若單一互動 Tool 呼叫超過 2 輪，標記 `CHURN_WARNING`，提示應整合為 One-Shot 專用腳本。
- **過慢腳本標記**：若特定操作耗時 $> 15$ 秒，觸發效能分析並評估加入本機 SQLite 快取。
