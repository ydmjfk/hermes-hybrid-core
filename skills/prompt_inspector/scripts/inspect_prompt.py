#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inspect_prompt.py — 開源版提示詞品質系統性檢查與優化器
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
用途：
輸入即將發給 AI Agent 的提示詞，以「HAOS 確定性治理憲政 + 動態檢查項」進行全方位體檢。
輸出：
1. 品質評分（0~100 分）
2. 命中規則與風險標記
3. 【推薦優化版提示詞】：一鍵複製即可精確執行，徹底消滅 AI 幻覺與擅專返工。
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path

# 動態定位檢查庫路徑（優先讀取同技能目錄下的 data/dynamic_checklists.json）
CURRENT_DIR = Path(__file__).resolve().parent
DEFAULT_CHECKLIST_PATH = CURRENT_DIR.parent / "data" / "dynamic_checklists.json"


def load_checklists(db_path: Path = DEFAULT_CHECKLIST_PATH) -> dict:
    if db_path.exists():
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"rules": []}


def inspect_prompt(prompt_text: str, db_path: Path = DEFAULT_CHECKLIST_PATH) -> dict:
    prompt = (prompt_text or "").strip()
    if not prompt:
        return {
            "score": 0,
            "status": "EMPTY",
            "warnings": ["提示詞為空"],
            "optimized_prompt": ""
        }

    db = load_checklists(db_path)
    rules = db.get("rules", [])

    score = 100
    matched_rules = []
    warnings = []
    enhancements = []

    prompt_lower = prompt.lower()

    for r in rules:
        r_id = r.get("id", "")
        name = r.get("name", "")
        patterns = r.get("trigger_patterns", [])
        must_any = r.get("must_contain_any", [])
        neg_patterns = r.get("negative_patterns", [])
        risk = r.get("risk_description", "")
        learned_from = r.get("learned_from", "")
        snippet = r.get("auto_fix_snippet", "")
        penalty = r.get("penalty", 15)

        # 1. 檢查是否觸發此規則領域
        triggered = any(pat.lower() in prompt_lower for pat in patterns)
        if not triggered:
            continue

        # 2. 檢查是否已經包含必要門禁約束
        has_guardrail = any(kw.lower() in prompt_lower for kw in must_any)

        # 3. 檢查是否有反向負面模式
        has_negative = any(neg.lower() in prompt_lower for neg in neg_patterns)

        if not has_guardrail or has_negative:
            score -= penalty
            warnings.append({
                "rule_id": r_id,
                "rule_name": name,
                "risk": risk,
                "learned_from": learned_from,
                "penalty": penalty
            })
            if snippet:
                enhancements.append(snippet)
        else:
            matched_rules.append({
                "rule_id": r_id,
                "rule_name": name,
                "status": "PASS"
            })

    score = max(0, min(100, score))

    # 組合優化版提示詞
    if enhancements:
        optimized = prompt + "\n\n" + "\n".join(enhancements)
    else:
        optimized = prompt

    status = "PASS" if score >= 85 else ("WARN" if score >= 60 else "FAIL")

    return {
        "score": score,
        "status": status,
        "warnings": warnings,
        "passed_rules": matched_rules,
        "original_prompt": prompt,
        "optimized_prompt": optimized
    }


def format_cli_report(res: dict) -> str:
    lines = []
    score = res["score"]
    status = res["status"]

    if status == "PASS":
        status_icon = "🟢"
    elif status == "WARN":
        status_icon = "🟡"
    else:
        status_icon = "🔴"

    lines.append(f"\n{status_icon} 提示詞品質體檢報告 (Score: {score}/100 [{status}])")
    lines.append("━" * 56)

    if res["warnings"]:
        lines.append("⚠️  檢測到之潛在風險與缺失門禁：")
        for w in res["warnings"]:
            lines.append(f"  • [{w['rule_name']}] (-{w['penalty']}分)")
            lines.append(f"    風險: {w['risk']}")
            lines.append(f"    依據: {w['learned_from']}")
        lines.append("━" * 56)
        lines.append("💡 【推薦優化版提示詞（補齊防呆約束）】：")
        lines.append("```markdown")
        lines.append(res["optimized_prompt"])
        lines.append("```")
    else:
        lines.append("✅ 提示詞結構完整，已包含必要邊界約束與安全防呆門禁，可安心交付 Agent 執行！")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="提示詞品質系統性檢查與優化工具")
    parser.add_argument("prompt", nargs="?", default="", help="欲體檢之提示詞內容")
    parser.add_argument("--json", action="store_true", help="以 JSON 格式輸出")
    parser.add_argument("--checklist-path", default=None, help="自訂 dynamic_checklists.json 路徑")

    args = parser.parse_args()

    prompt = args.prompt
    if not prompt and not sys.stdin.isatty():
        prompt = sys.stdin.read().strip()

    if not prompt:
        parser.print_help()
        sys.exit(1)

    db_p = Path(args.checklist_path) if args.checklist_path else DEFAULT_CHECKLIST_PATH
    res = inspect_prompt(prompt, db_path=db_p)

    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(format_cli_report(res))


if __name__ == "__main__":
    main()
