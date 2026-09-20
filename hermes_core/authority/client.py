# -*- coding: utf-8 -*-
"""
hermes_core/authority/client.py — Agent IPC Client for Authority Broker (Slice 1)
"""

import json
import socket
import logging
from typing import Optional

from .models import (
    CapabilityRequest,
    CapabilityGrant,
    FailureCode,
    BrokerUnavailableError,
    CapabilityDeniedError,
)

logger = logging.getLogger("hermes_core.authority.client")


class AgentAuthorityClient:
    """
    Lightweight Agent client communicating with Authority Broker over UNIX Domain Socket.
    Strictly fails closed: any connection error or denial raises an explicit exception.
    """

    def __init__(self, socket_path: str, timeout: float = 3.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def request_capability(self, request: CapabilityRequest) -> CapabilityGrant:
        """
        Send a CapabilityRequest to Authority Broker and await CapabilityGrant.
        
        Raises:
            CapabilityDeniedError: If the Broker denies the request with a policy failure code.
            BrokerUnavailableError: If the Broker cannot be contacted or times out (Fail-Closed).
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)

            payload = json.dumps(request.to_dict()).encode("utf-8") + b"\n"
            sock.sendall(payload)

            raw_resp = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw_resp += chunk
                if b"\n" in chunk:
                    break

            if not raw_resp:
                raise BrokerUnavailableError("Authority Broker closed connection without response")

            resp_dict = json.loads(raw_resp.strip().decode("utf-8"))
            status = resp_dict.get("status")

            if status == "GRANTED":
                grant_dict = resp_dict.get("grant", {})
                return CapabilityGrant.from_dict(grant_dict)
            elif status == "DENIED":
                code_str = resp_dict.get("code", FailureCode.DENY_UNKNOWN_STATE.value)
                msg = resp_dict.get("message", "Request denied by broker")
                try:
                    code = FailureCode(code_str)
                except ValueError:
                    code = FailureCode.DENY_UNKNOWN_STATE
                raise CapabilityDeniedError(code, msg)
            else:
                raise CapabilityDeniedError(
                    FailureCode.DENY_UNKNOWN_STATE,
                    f"Unrecognized broker response status: '{status}'",
                )

        except (socket.error, OSError) as e:
            logger.error("Failed to connect to Authority Broker at %s: %s", self.socket_path, e)
            raise BrokerUnavailableError(f"Authority Broker is unavailable: {e}") from e
        except json.JSONDecodeError as e:
            logger.error("Failed to decode Authority Broker response: %s", e)
            raise BrokerUnavailableError(f"Corrupted broker response payload: {e}") from e
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
