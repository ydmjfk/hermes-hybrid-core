# -*- coding: utf-8 -*-
"""
hermes_core/provenance — Ingress Provenance & Taint Tracking Engine (Slice 2)
"""

from .signer import (
    IngressProvenanceSigner,
    ProvenanceVerifier,
    compute_provenance_digest,
)

__all__ = [
    "IngressProvenanceSigner",
    "ProvenanceVerifier",
    "compute_provenance_digest",
]
