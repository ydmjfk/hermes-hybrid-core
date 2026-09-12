#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Health Validator for CAP-005 Operator Dead Letter Capability
"""

import sys
from pathlib import Path
from typing import Tuple

try:
    from .cron_circuit_breaker_engine import CronCircuitBreakerEngine, BreakerState
except ImportError:
    from cron_circuit_breaker_engine import CronCircuitBreakerEngine, BreakerState


def validate_capability() -> Tuple[bool, str]:
    """Perform self-diagnostic check on the operator_deadletter capability."""
    temp_state = Path(".diag_state.json")
    try:
        if temp_state.exists():
            temp_state.unlink()

        engine = CronCircuitBreakerEngine(str(temp_state))
        
        # Test 3 failures trip to quarantine
        for i in range(3):
            engine.record_result("diag_job", False, "Simulated network timeout")

        if engine.breakers["diag_job"].state != BreakerState.DEGRADED_QUARANTINED:
            return False, "Self-test failed: Breaker did not trip to DEGRADED_QUARANTINED on 3 failures."

        allow, _ = engine.should_allow_execution("diag_job")
        if allow:
            return False, "Self-test failed: Quarantined job was incorrectly allowed to run."

        # Recover
        engine.record_result("diag_job", True)
        if engine.breakers["diag_job"].state != BreakerState.HEALTHY:
            return False, "Self-test failed: Breaker did not recover to HEALTHY on success."

        return True, "CAP-005 Operator Dead Letter Capability is healthy and operational."
    except Exception as e:
        return False, f"Exception during validation: {e}"
    finally:
        if temp_state.exists():
            temp_state.unlink(missing_ok=True)


if __name__ == "__main__":
    ok, msg = validate_capability()
    print(f"Status: {'PASS' if ok else 'FAIL'} | Message: {msg}")
    sys.exit(0 if ok else 1)
