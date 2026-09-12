#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extension Layer Tool Entrypoint for Hermes Capability Library
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
try:
    from .extension_registry_engine import ExtensionRegistryEngine
except ImportError:
    from extension_registry_engine import ExtensionRegistryEngine


def get_extension_registry(capabilities_dir: Optional[str] = None) -> ExtensionRegistryEngine:
    """Get initialized ExtensionRegistryEngine instance."""
    if capabilities_dir is None:
        capabilities_dir = str(Path(__file__).resolve().parent.parent)
    engine = ExtensionRegistryEngine(capabilities_dir)
    engine.discover_and_register_all()
    return engine
