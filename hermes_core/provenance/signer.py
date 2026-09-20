# -*- coding: utf-8 -*-
"""
hermes_core/provenance/signer.py — Ingress Provenance Signer & Verifier (Slice 2)
"""

import json
import base64
import hashlib
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from hermes_core.authority.models import ProvenanceContext


def compute_provenance_digest(caller_id: str, origin_source: str, taint_tag: str) -> bytes:
    """
    Compute deterministic canonical digest for ingress provenance authentication.
    """
    canonical_payload = {
        "caller_id": caller_id.strip(),
        "origin_source": origin_source.strip(),
        "taint_tag": taint_tag.strip(),
    }
    raw_bytes = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw_bytes).digest()


class IngressProvenanceSigner:
    """
    Ingress Gateway component that holds Key_Provenance (Ed25519 private key)
    and signs incoming requests at the boundary before passing to the Agent.
    """

    def __init__(self, private_key: Optional[Union[ed25519.Ed25519PrivateKey, bytes]] = None):
        if private_key is None:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        elif isinstance(private_key, bytes):
            if len(private_key) == 32:
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            else:
                # Seed derivation
                seed = hashlib.sha256(private_key).digest()
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        else:
            self._private_key = private_key

        self._public_key = self._private_key.public_key()

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._public_key

    def get_public_key(self) -> bytes:
        """Return raw 32 bytes public key for verifiers"""
        return self._public_key.public_bytes_raw()

    def sign_provenance(
        self,
        caller_id: str,
        origin_source: str,
        taint_tag: str,
    ) -> ProvenanceContext:
        """
        Sign provenance attributes at Ingress boundary.
        Produces an immutable ProvenanceContext with Ed25519 signature.
        """
        digest = compute_provenance_digest(caller_id, origin_source, taint_tag)
        sig_bytes = self._private_key.sign(digest)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        return ProvenanceContext(
            caller_id=caller_id,
            origin_source=origin_source,
            taint_tag=taint_tag,
            ingress_signature=sig_b64,
        )


class ProvenanceVerifier:
    """
    Offline verification component holding ONLY Key_Provenance_Public.
    Used by Authority Broker to verify ingress signatures without possessing private keys.
    """

    def __init__(self, public_key: Union[ed25519.Ed25519PublicKey, bytes]):
        if isinstance(public_key, bytes):
            self._public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        else:
            self._public_key = public_key

    def verify_provenance(self, context: ProvenanceContext) -> bool:
        """
        Verify that the Ingress signature on the ProvenanceContext is valid and authentic.
        """
        if not context.ingress_signature:
            return False

        try:
            sig_bytes = base64.b64decode(context.ingress_signature)
            digest = compute_provenance_digest(
                context.caller_id,
                context.origin_source,
                context.taint_tag,
            )
            self._public_key.verify(sig_bytes, digest)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
