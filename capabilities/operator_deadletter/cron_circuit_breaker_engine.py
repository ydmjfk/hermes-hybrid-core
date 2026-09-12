#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAP-005: OpenClaw-Style Cron Dead Letter Queue & Circuit Breaker Engine (Promoted Capability)
=============================================================================================
A self-healing task-level circuit breaker for Cron jobs.
Features:
  1. Failure Threshold Counter (Trips to DEGRADED_QUARANTINED after 3 consecutive failures).
  2. Single Deduplicated Alert Trigger (Prevents alert storming).
  3. Slow Probe Auto-Recovery (Allows periodic canary probes to detect service revival).
  4. Non-Destructive State Isolation (Preserves original jobs.json intact).
"""

import os
import sys
import time
import json
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple


class BreakerState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED_QUARANTINED = "DEGRADED_QUARANTINED"
    SLOW_PROBING = "SLOW_PROBING"


@dataclass
class JobBreakerEntry:
    job_id: str
    job_name: str = ""
    consecutive_failures: int = 0
    state: BreakerState = BreakerState.HEALTHY
    last_error: str = ""
    last_failure_time: float = 0.0
    quarantine_time: float = 0.0
    last_probe_time: float = 0.0
    probe_interval_seconds: int = 300  # Default 5 minutes for probe
    alert_sent: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobBreakerEntry":
        d = data.copy()
        d["state"] = BreakerState(d.get("state", "HEALTHY"))
        return cls(**d)


class CronCircuitBreakerEngine:
    """
    OpenClaw-style Cron circuit breaker and dead letter queue manager.
    """

    FAILURE_THRESHOLD = 3

    def __init__(self, state_file: str = "breaker_state.json"):
        self.state_file = Path(state_file).expanduser().resolve()
        self.breakers: Dict[str, JobBreakerEntry] = {}
        self.load_state()

    def should_allow_execution(self, job_id: str) -> Tuple[bool, str]:
        """
        Check if job execution is allowed based on circuit breaker status.
        Returns: (is_allowed, reason)
        """
        entry = self.breakers.get(job_id)
        if not entry or entry.state == BreakerState.HEALTHY:
            return True, "Job is healthy"

        if entry.state == BreakerState.DEGRADED_QUARANTINED:
            now = time.time()
            if now - entry.last_probe_time >= entry.probe_interval_seconds:
                entry.state = BreakerState.SLOW_PROBING
                entry.last_probe_time = now
                self.save_state()
                return True, "Slow canary probe allowed for recovery test"
            else:
                remaining_s = int(entry.probe_interval_seconds - (now - entry.last_probe_time))
                return False, f"Job in Dead Letter Quarantine (連續失敗 {entry.consecutive_failures} 次)。距下次慢探針重試尚餘 {remaining_s} 秒。"

        if entry.state == BreakerState.SLOW_PROBING:
            return True, "Slow probe currently executing"

        return True, "Allowed"

    def record_result(self, job_id: str, success: bool, error_msg: str = "", job_name: str = "") -> Dict[str, Any]:
        """
        Record result of a cron job run.
        """
        now = time.time()
        if job_id not in self.breakers:
            self.breakers[job_id] = JobBreakerEntry(job_id=job_id, job_name=job_name)

        entry = self.breakers[job_id]
        if job_name:
            entry.job_name = job_name

        alert_needed = False

        if success:
            was_degraded = (entry.state in (BreakerState.DEGRADED_QUARANTINED, BreakerState.SLOW_PROBING))
            entry.consecutive_failures = 0
            entry.state = BreakerState.HEALTHY
            entry.last_error = ""
            entry.alert_sent = False
            self.save_state()
            return {
                "job_id": job_id,
                "status": "HEALTHY",
                "was_recovered": was_degraded,
                "alert_needed": False,
                "consecutive_failures": 0
            }
        else:
            entry.consecutive_failures += 1
            entry.last_error = error_msg
            entry.last_failure_time = now

            if entry.consecutive_failures >= self.FAILURE_THRESHOLD:
                if entry.state != BreakerState.DEGRADED_QUARANTINED:
                    entry.state = BreakerState.DEGRADED_QUARANTINED
                    entry.quarantine_time = now
                    entry.last_probe_time = now
                    if not entry.alert_sent:
                        alert_needed = True
                        entry.alert_sent = True
                else:
                    entry.state = BreakerState.DEGRADED_QUARANTINED
                    entry.last_probe_time = now

            self.save_state()
            return {
                "job_id": job_id,
                "status": entry.state.value,
                "consecutive_failures": entry.consecutive_failures,
                "alert_needed": alert_needed,
                "quarantined": entry.state == BreakerState.DEGRADED_QUARANTINED,
                "last_error": error_msg
            }

    def get_dead_letter_queue(self) -> List[Dict[str, Any]]:
        """Return list of all quarantined dead-letter jobs."""
        return [
            entry.to_dict()
            for entry in self.breakers.values()
            if entry.state == BreakerState.DEGRADED_QUARANTINED
        ]

    def reset_breaker(self, job_id: str) -> bool:
        """Manually reset a job back to HEALTHY state."""
        if job_id in self.breakers:
            self.breakers[job_id].consecutive_failures = 0
            self.breakers[job_id].state = BreakerState.HEALTHY
            self.breakers[job_id].alert_sent = False
            self.save_state()
            return True
        return False

    def load_state(self) -> None:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.breakers = {k: JobBreakerEntry.from_dict(v) for k, v in data.items()}
            except Exception:
                self.breakers = {}

    def save_state(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.state_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump({k: v.to_dict() for k, v in self.breakers.items()}, f, ensure_ascii=False, indent=2)
            os.replace(temp_file, self.state_file)
        except Exception:
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
