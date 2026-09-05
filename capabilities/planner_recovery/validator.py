#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Health Validator for CAP-002 Planner Recovery Capability
"""

import sys
from typing import Tuple

try:
    from .planner_recovery_engine import PlanStateMachine, TaskStatus
except ImportError:
    from planner_recovery_engine import PlanStateMachine, TaskStatus


def validate_capability() -> Tuple[bool, str]:
    """Perform self-diagnostic check on the planner_recovery capability."""
    try:
        sm = PlanStateMachine("DIAG-PLAN-001", "驗證子任務狀態機自檢")
        t1 = sm.add_task("T1", "步驟 1")
        t2 = sm.add_task("T2", "步驟 2", dependencies=["T1"])

        # Execute T1
        sm.start_task("T1")
        sm.mark_completed("T1", evidence={"ok": True})

        # T2 fail and partial replan
        sm.start_task("T2")
        sm.mark_failed("T2", "模擬測試失敗")

        replan = sm.partial_replan("T2", [{"task_id": "T2_ALT", "title": "替代步驟"}])
        if replan["status"] != "REPLAN_SUCCESS":
            return False, f"Replan failed: {replan}"

        # T1 must remain COMPLETED
        if sm.tasks["T1"].status != TaskStatus.COMPLETED:
            return False, "Self-test failed: T1 state corrupted after replan."

        # Execute T2_ALT
        sm.start_task("T2_ALT")
        sm.mark_completed("T2_ALT")

        if not sm.is_all_completed():
            return False, "Self-test failed: Plan not marked completed."

        return True, "CAP-002 Planner Recovery Capability is healthy and operational."
    except Exception as e:
        return False, f"Exception during validation: {e}"


if __name__ == "__main__":
    ok, msg = validate_capability()
    print(f"Status: {'PASS' if ok else 'FAIL'} | Message: {msg}")
    sys.exit(0 if ok else 1)
