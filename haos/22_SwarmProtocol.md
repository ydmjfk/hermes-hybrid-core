# 22_SwarmProtocol.md — HAOS 多 Agent 協同通訊協定 (Swarm Protocol)

> **地位**：Warm Layer（Subagent 派生、多代理人任務分工與通訊標準）。

---

## 🏛️ 多 Agent 團隊協同拓撲 (Multi-Agent Swarm Topology)

當主代理人（Orchestrator）派生專門 Subagent 處理複雜長流程任務時，必須遵守標準 Swarm 分工協定：

```text
               ┌───────────────────────────────┐
               │  Master Agent (Orchestrator)  │
               └───────────────┬───────────────┘
                               │ (Task Delegation)
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
 ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
 │ Subagent:    │       │ Subagent:    │       │ Subagent:    │
 │ Planner Spec │       │ CodeExecutor │       │ QA & Security│
 └──────────────┘       └──────────────┘       └──────────────┘
```

---

## 📡 結構化交接通訊契約 (Inter-Agent Message Schema)

Agent 之間透過結構化事件通訊，嚴禁傳遞模糊自然語言：

```json
{
  "swarm_event": "TASK_DELEGATION",
  "task_id": "SWARM-20260826-01",
  "sender_agent": "Orchestrator",
  "receiver_agent": "Code_Executor_Subagent",
  "payload": {
    "subtask_id": 1,
    "instruction": "修復 /path/to/target.py 中 KeyError 異常",
    "constraints": [
      "遵守 00_Constitution.md 最小爆炸半徑",
      "精確區塊替換，嚴禁全檔覆寫",
      "寫入前必須先建立 .bak 備份"
    ],
    "verification_command": "python3 /path/to/test_target.py"
  },
  "reply_channel": "session_event_bus"
}
```

---

## 🛡️ Swarm 協同安全防護
1. **沙盒隔離**：Subagent 無權修改全域 Constitution 或變更非授權工作區。
2. **通訊超時**：Subagent 若超過 120 秒未回傳狀態，Orchestrator 強制回收控制權。
