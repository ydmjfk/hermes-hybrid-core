#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Health Validator for CAP-004 Extension Layer Capability
"""

import sys
from pathlib import Path
from typing import Tuple

try:
    from .extension_registry_engine import ExtensionRegistryEngine
except ImportError:
    from extension_registry_engine import ExtensionRegistryEngine


def validate_capability() -> Tuple[bool, str]:
    """Perform self-diagnostic check on the extension_layer capability."""
    try:
        caps_dir = Path(__file__).resolve().parent.parent
        engine = ExtensionRegistryEngine(str(caps_dir))
        res = engine.discover_and_register_all()
        if res.get("status") != "DISCOVERY_COMPLETE":
            return False, f"Discovery failed with status: {res.get('status')}"

        if res.get("total_active", 0) < 3:
            return False, f"Expected at least 3 active capabilities, found {res.get('total_active')}"

        return True, f"CAP-004 Extension Layer Capability is healthy. ({res.get('total_active')} active extensions, {res.get('total_tools')} tools)"
    except Exception as e:
        return False, f"Exception during validation: {e}"


if __name__ == "__main__":
    ok, msg = validate_capability()
    print(f"Status: {'PASS' if ok else 'FAIL'} | Message: {msg}")
    sys.exit(0 if ok else 1)
