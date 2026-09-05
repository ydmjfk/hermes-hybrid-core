#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Planner Recovery Tool Entrypoint for Hermes Capability Library
"""

from typing import Dict, Any, List, Optional

try:
    from .planner_recovery_engine import PlanStateMachine, TaskStatus
except ImportError:
    from planner_recovery_engine import PlanStateMachine, TaskStatus


def create_plan_coordinator(plan_id: str, goal: str = "") -> PlanStateMachine:
    """Create a new Sub-Task State Machine coordinator instance."""
    return PlanStateMachine(plan_id=plan_id, goal=goal)
