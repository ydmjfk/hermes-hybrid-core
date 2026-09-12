#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAP-002: OpenHands-Style Sub-Task State Machine & Partial Re-Plan Engine (Promoted Capability)
=============================================================================================
A deterministic, zero-dependency DAG-based sub-task state machine.
Features:
  1. Immutable Completed Step Protection (Preserves completed work upon failure).
  2. Dynamic Partial Re-Planning (Replaces only failed branches & downstream dependencies).
  3. Bounded Re-Plan Limiter (Max 2 re-plans per step, then ESCALATES).
  4. Full State Ledger & Checkpoint Export (Audit-ready JSON serialization).
"""

import time
import json
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NEEDS_REPLAN = "NEEDS_REPLAN"
    SKIPPED = "SKIPPED"
    ESCALATED = "ESCALATED"


@dataclass
class SubTask:
    task_id: str
    title: str
    description: str = ""
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    replan_count: int = 0
    max_replans: int = 2
    evidence: Dict[str, Any] = field(default_factory=dict)
    error_history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SubTask":
        d = data.copy()
        d["status"] = TaskStatus(d["status"])
        return cls(**d)


class PlanStateMachine:
    """
    Sub-task DAG Coordinator with Partial Re-Planning capabilities.
    """

    def __init__(self, plan_id: str, goal: str = ""):
        self.plan_id = plan_id
        self.goal = goal
        self.tasks: Dict[str, SubTask] = {}
        self.created_at = time.time()
        self.updated_at = time.time()

    def add_task(
        self,
        task_id: str,
        title: str,
        description: str = "",
        dependencies: Optional[List[str]] = None,
        max_replans: int = 2
    ) -> SubTask:
        """Add a new subtask to the DAG."""
        if task_id in self.tasks:
            raise ValueError(f"Task ID already exists: {task_id}")

        deps = dependencies or []
        if task_id in deps:
            raise ValueError(f"Task cannot depend on itself: {task_id}")

        task = SubTask(
            task_id=task_id,
            title=title,
            description=description,
            dependencies=deps,
            status=TaskStatus.PENDING,
            max_replans=max_replans
        )
        self.tasks[task_id] = task
        self._refresh_task_states()
        self.updated_at = time.time()
        return task

    def _refresh_task_states(self) -> None:
        """Update PENDING tasks to READY if all their dependencies are COMPLETED."""
        for t in self.tasks.values():
            if t.status == TaskStatus.PENDING:
                all_deps_satisfied = True
                for dep_id in t.dependencies:
                    dep = self.tasks.get(dep_id)
                    if not dep or dep.status != TaskStatus.COMPLETED:
                        all_deps_satisfied = False
                        break
                if all_deps_satisfied:
                    t.status = TaskStatus.READY
                    t.updated_at = time.time()

    def get_ready_tasks(self) -> List[SubTask]:
        """Get all tasks currently READY to be executed."""
        self._refresh_task_states()
        return [t for t in self.tasks.values() if t.status == TaskStatus.READY]

    def start_task(self, task_id: str) -> SubTask:
        """Mark a READY task as RUNNING."""
        task = self._get_task(task_id)
        if task.status != TaskStatus.READY:
            raise ValueError(f"Cannot start task {task_id}: status is {task.status.value}, expected READY")
        task.status = TaskStatus.RUNNING
        task.updated_at = time.time()
        self.updated_at = time.time()
        return task

    def mark_completed(self, task_id: str, evidence: Optional[Dict[str, Any]] = None) -> SubTask:
        """Mark a RUNNING task as COMPLETED and attach evidence."""
        task = self._get_task(task_id)
        if task.status not in (TaskStatus.RUNNING, TaskStatus.READY):
            raise ValueError(f"Cannot complete task {task_id}: status is {task.status.value}")
        task.status = TaskStatus.COMPLETED
        task.evidence = evidence or {}
        task.updated_at = time.time()
        self._refresh_task_states()
        self.updated_at = time.time()
        return task

    def mark_failed(self, task_id: str, error_detail: str) -> Dict[str, Any]:
        """
        Mark a RUNNING task as FAILED.
        If replan_count < max_replans, transitions to NEEDS_REPLAN.
        Otherwise transitions to ESCALATED (requires human intervention).
        """
        task = self._get_task(task_id)
        task.error_history.append({
            "timestamp": time.time(),
            "attempt": task.replan_count + 1,
            "error": error_detail
        })
        task.updated_at = time.time()

        if task.replan_count < task.max_replans:
            task.status = TaskStatus.NEEDS_REPLAN
            action = "TRIGGER_REPLAN"
        else:
            task.status = TaskStatus.ESCALATED
            action = "ESCALATE_TO_HUMAN"

        self.updated_at = time.time()
        return {
            "task_id": task_id,
            "status": task.status.value,
            "action": action,
            "replan_count": task.replan_count,
            "max_replans": task.max_replans,
            "error": error_detail
        }

    def partial_replan(
        self,
        failed_task_id: str,
        replacement_subtasks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Dynamically replan a failed branch:
        1. Preserves all existing COMPLETED tasks intact.
        2. Replaces failed_task_id with one or more replacement_subtasks.
        3. Updates downstream dependencies pointing to failed_task_id to depend on the last replacement task.
        """
        failed_task = self._get_task(failed_task_id)
        if failed_task.status != TaskStatus.NEEDS_REPLAN:
            raise ValueError(f"Task {failed_task_id} is in status {failed_task.status.value}, expected NEEDS_REPLAN")

        failed_task.replan_count += 1
        original_deps = list(failed_task.dependencies)

        # Remove the failed task and insert replacements
        del self.tasks[failed_task_id]

        new_ids = []
        prev_id = None

        for idx, item in enumerate(replacement_subtasks):
            new_id = item.get("task_id", f"{failed_task_id}_alt_{failed_task.replan_count}_{idx+1}")
            title = item.get("title", f"Alternative step for {failed_task.title}")
            desc = item.get("description", "")
            
            if idx == 0:
                deps = item.get("dependencies", original_deps)
            else:
                deps = item.get("dependencies", [prev_id])

            new_task = SubTask(
                task_id=new_id,
                title=title,
                description=desc,
                dependencies=deps,
                status=TaskStatus.PENDING,
                replan_count=failed_task.replan_count,
                max_replans=failed_task.max_replans
            )
            self.tasks[new_id] = new_task
            new_ids.append(new_id)
            prev_id = new_id

        # Update downstream tasks that depended on failed_task_id
        if prev_id:
            for t in self.tasks.values():
                if t.task_id not in new_ids and failed_task_id in t.dependencies:
                    t.dependencies = [prev_id if d == failed_task_id else d for d in t.dependencies]

        self._refresh_task_states()
        self.updated_at = time.time()

        return {
            "status": "REPLAN_SUCCESS",
            "failed_task_id": failed_task_id,
            "replan_count": failed_task.replan_count,
            "injected_task_ids": new_ids,
            "total_tasks": len(self.tasks),
            "completed_tasks": len([t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED])
        }

    def is_all_completed(self) -> bool:
        """Check if all tasks in the DAG are COMPLETED."""
        if not self.tasks:
            return False
        return all(t.status == TaskStatus.COMPLETED for t in self.tasks.values())

    def is_blocked(self) -> bool:
        """Check if any task is ESCALATED or in deadlock."""
        return any(t.status == TaskStatus.ESCALATED for t in self.tasks.values())

    def export_ledger(self) -> Dict[str, Any]:
        """Export full execution state ledger for audit and resumption."""
        completed = [t.task_id for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]
        pending = [t.task_id for t in self.tasks.values() if t.status in (TaskStatus.PENDING, TaskStatus.READY)]
        failed = [t.task_id for t in self.tasks.values() if t.status in (TaskStatus.FAILED, TaskStatus.NEEDS_REPLAN, TaskStatus.ESCALATED)]

        return {
            "plan_id": self.plan_id,
            "goal": self.goal,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "is_completed": self.is_all_completed(),
            "is_blocked": self.is_blocked(),
            "summary": {
                "total": len(self.tasks),
                "completed": len(completed),
                "pending": len(pending),
                "failed_or_escalated": len(failed)
            },
            "tasks": {k: v.to_dict() for k, v in self.tasks.items()}
        }

    def _get_task(self, task_id: str) -> SubTask:
        if task_id not in self.tasks:
            raise KeyError(f"Task not found: {task_id}")
        return self.tasks[task_id]
