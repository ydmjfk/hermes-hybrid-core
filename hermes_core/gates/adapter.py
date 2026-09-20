# -*- coding: utf-8 -*-
"""
hermes_core/gates/adapter.py — Unified Execution Adapter for Domain Gates (Slice 6)

Architecture Principles:
1. Canonical Trust Chain Integration:
   Ingress (Signed Provenance) ➔ Task Manifest Anchor ➔ CAS Human Approval (if required)
   ➔ Authority Broker (Signed CapabilityGrant across UDS IPC)
   ➔ Physical Domain Gate (ProcessGate, StorageGate, NetworkGate)
   ➔ Bounded, Audited Execution Result.
2. Zero Private Keys: The Adapter operates in the unprivileged Agent Runtime and possesses 0 private keys.
3. Fail-Closed Paradigm: Any error during authority request or gate execution returns an explicit failed result.
4. Clean Decoupled Interface: Exposes standard unified execution methods for process, storage, and network.
"""

import os
import time
import uuid
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from hermes_core.authority.models import (
    ProvenanceContext,
    FullExecutionSemantics,
    HumanApprovalProof,
    CapabilityGrant,
    CapabilityRequest,
    FailureCode,
    AuthorityError,
)
from hermes_core.authority.client import AgentAuthorityClient
from hermes_core.gates.process_gate import ProcessGate, ProcessExecutionResult
from hermes_core.gates.storage_gate import StorageGate, StorageExecutionResult
from hermes_core.gates.network_gate import NetworkGate, NetworkExecutionResult

logger = logging.getLogger("hermes_core.gates.adapter")


class UnifiedExecutionAdapter:
    """
    Unified Execution Adapter orchestrating authority verification and physical gate execution.
    Acts as the single bridge between Agent tools/skills and the domain execution gates.
    """

    def __init__(
        self,
        authority_client: AgentAuthorityClient,
        process_gate: ProcessGate,
        storage_gate: StorageGate,
        network_gate: NetworkGate,
    ):
        self._client = authority_client
        self._process_gate = process_gate
        self._storage_gate = storage_gate
        self._network_gate = network_gate

    @property
    def client(self) -> AgentAuthorityClient:
        return self._client

    @property
    def process_gate(self) -> ProcessGate:
        return self._process_gate

    @property
    def storage_gate(self) -> StorageGate:
        return self._storage_gate

    @property
    def network_gate(self) -> NetworkGate:
        return self._network_gate

    def execute_process(
        self,
        task_id: str,
        provenance: ProvenanceContext,
        semantics: FullExecutionSemantics,
        human_approval: Optional[HumanApprovalProof] = None,
        timeout: float = 30.0,
    ) -> ProcessExecutionResult:
        """
        Request capability grant from Authority Broker and execute command via ProcessGate.
        """
        start_time = time.time()
        try:
            req = CapabilityRequest(
                request_id=str(uuid.uuid4()),
                task_id=task_id,
                requested_primitive="PROCESS_EXECUTE",
                provenance=provenance,
                untrusted_semantics=semantics,
                human_approval=human_approval,
            )
            grant = self._client.request_capability(req)
        except AuthorityError as ae:
            return ProcessExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(ae),
                execution_hash=semantics.compute_canonical_hash(),
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=getattr(ae, "code", FailureCode.DENY_UNKNOWN_STATE),
                error_message=str(ae),
            )
        except Exception as exc:
            return ProcessExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Authority client IPC failure: {exc}",
                execution_hash=semantics.compute_canonical_hash(),
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_BROKER_OFFLINE,
                error_message=str(exc),
            )

        # Execute through physical ProcessGate
        return self._process_gate.execute(grant, semantics, timeout=timeout)

    def write_file(
        self,
        task_id: str,
        provenance: ProvenanceContext,
        target_path: str,
        content: Union[str, bytes],
        mode: str = "w",
        human_approval: Optional[HumanApprovalProof] = None,
    ) -> StorageExecutionResult:
        """
        Request capability grant from Authority Broker and write file via StorageGate.
        """
        start_time = time.time()
        # Construct synthetic semantics for storage write
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path=target_path,
            script_hash="",
            argv=(),
            cwd=os.path.dirname(os.path.abspath(target_path)),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        try:
            req = CapabilityRequest(
                request_id=str(uuid.uuid4()),
                task_id=task_id,
                requested_primitive="STORAGE_WRITE",
                provenance=provenance,
                untrusted_semantics=semantics,
                human_approval=human_approval,
            )
            grant = self._client.request_capability(req)
        except AuthorityError as ae:
            return StorageExecutionResult(
                success=False,
                operation="write",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=getattr(ae, "code", FailureCode.DENY_UNKNOWN_STATE),
                error_message=str(ae),
            )
        except Exception as exc:
            return StorageExecutionResult(
                success=False,
                operation="write",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_BROKER_OFFLINE,
                error_message=str(exc),
            )

        # Execute through physical StorageGate
        return self._storage_gate.write_file(grant, target_path, content, mode=mode)

    def delete_file(
        self,
        task_id: str,
        provenance: ProvenanceContext,
        target_path: str,
        expected_inode: Optional[int] = None,
        human_approval: Optional[HumanApprovalProof] = None,
    ) -> StorageExecutionResult:
        """
        Request capability grant from Authority Broker and delete file via StorageGate.
        """
        start_time = time.time()
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path=target_path,
            script_hash="",
            argv=(),
            cwd=os.path.dirname(os.path.abspath(target_path)),
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="DENY_ALL",
        )

        try:
            req = CapabilityRequest(
                request_id=str(uuid.uuid4()),
                task_id=task_id,
                requested_primitive="STORAGE_DELETE",
                provenance=provenance,
                untrusted_semantics=semantics,
                human_approval=human_approval,
            )
            grant = self._client.request_capability(req)
        except AuthorityError as ae:
            return StorageExecutionResult(
                success=False,
                operation="delete",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=getattr(ae, "code", FailureCode.DENY_UNKNOWN_STATE),
                error_message=str(ae),
            )
        except Exception as exc:
            return StorageExecutionResult(
                success=False,
                operation="delete",
                target_path=target_path,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_BROKER_OFFLINE,
                error_message=str(exc),
            )

        # Execute through physical StorageGate
        return self._storage_gate.delete_file(grant, target_path, expected_inode=expected_inode)

    def send_network_request(
        self,
        task_id: str,
        provenance: ProvenanceContext,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
        timeout: float = 15.0,
        human_approval: Optional[HumanApprovalProof] = None,
        mock_response: Optional[Tuple[int, Dict[str, str], str]] = None,
    ) -> NetworkExecutionResult:
        """
        Request capability grant from Authority Broker and send network request via NetworkGate.
        """
        start_time = time.time()
        semantics = FullExecutionSemantics(
            interpreter_path="",
            interpreter_hash="",
            script_path="",
            script_hash="",
            argv=(),
            cwd="",
            env_allowlist=(),
            sandbox_profile="DEFAULT",
            network_policy="ALLOW_EGRESS",
        )

        try:
            req = CapabilityRequest(
                request_id=str(uuid.uuid4()),
                task_id=task_id,
                requested_primitive="NETWORK_REQUEST",
                provenance=provenance,
                untrusted_semantics=semantics,
                human_approval=human_approval,
            )
            grant = self._client.request_capability(req)
        except AuthorityError as ae:
            return NetworkExecutionResult(
                success=False,
                status_code=-1,
                headers={},
                body="",
                target_url=url,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=getattr(ae, "code", FailureCode.DENY_UNKNOWN_STATE),
                error_message=str(ae),
            )
        except Exception as exc:
            return NetworkExecutionResult(
                success=False,
                status_code=-1,
                headers={},
                body="",
                target_url=url,
                duration_ms=(time.time() - start_time) * 1000.0,
                error_code=FailureCode.DENY_BROKER_OFFLINE,
                error_message=str(exc),
            )

        # Execute through physical NetworkGate
        return self._network_gate.send_request(
            grant=grant,
            url=url,
            method=method,
            headers=headers,
            data=data,
            timeout=timeout,
            mock_response=mock_response,
        )
