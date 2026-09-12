#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Operator Dead Letter Tool Entrypoint for Hermes Capability Library
"""

from typing import Dict, Any, List, Optional
try:
    from .cron_circuit_breaker_engine import CronCircuitBreakerEngine
except ImportError:
    from cron_circuit_breaker_engine import CronCircuitBreakerEngine


def get_cron_circuit_breaker(state_file: str = "breaker_state.json") -> CronCircuitBreakerEngine:
    """Get initialized CronCircuitBreakerEngine instance."""
    return CronCircuitBreakerEngine(state_file)
