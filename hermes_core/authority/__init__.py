# -*- coding: utf-8 -*-
"""
hermes_core/authority/__init__.py — Authority Broker and IPC Infrastructure (Slice 1)
"""

from .models import (
    ProvenanceContext,
    TaskManifest,
    FullExecutionSemantics,
    CapabilityRequest,
    HumanApprovalProof,
    CapabilityGrant,
    FailureCode,
    AuthorityError,
    BrokerUnavailableError,
    CapabilityDeniedError,
)
from .broker import AuthorityBroker
from .client import AgentAuthorityClient

__all__ = [
    "ProvenanceContext",
    "TaskManifest",
    "FullExecutionSemantics",
    "CapabilityRequest",
    "HumanApprovalProof",
    "CapabilityGrant",
    "FailureCode",
    "AuthorityError",
    "BrokerUnavailableError",
    "CapabilityDeniedError",
    "AuthorityBroker",
    "AgentAuthorityClient",
]
