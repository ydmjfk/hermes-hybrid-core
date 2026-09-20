# -*- coding: utf-8 -*-
"""
hermes_core/gates — Domain Execution Gates (Phase 4.1 / Phase 5.1 Architecture)
Unskippable physical choke points for process, storage, and network execution.
"""

from hermes_core.gates.process_gate import (
    ProcessGate,
    ProcessExecutionResult,
    GateAccessDeniedError,
)
from hermes_core.gates.storage_gate import (
    StorageGate,
    StorageExecutionResult,
)
from hermes_core.gates.network_gate import (
    NetworkGate,
    NetworkExecutionResult,
)
from hermes_core.gates.adapter import (
    UnifiedExecutionAdapter,
)

__all__ = [
    "ProcessGate",
    "ProcessExecutionResult",
    "GateAccessDeniedError",
    "StorageGate",
    "StorageExecutionResult",
    "NetworkGate",
    "NetworkExecutionResult",
    "UnifiedExecutionAdapter",
]
