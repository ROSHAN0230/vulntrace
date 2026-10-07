"""
VulnTrace Cryptographic Evidence Package (Spec §4.11)
"""

from vulntrace.evidence.canonical import canonical_json_bytes, compute_canonical_hash
from vulntrace.evidence.signing import EvidenceSigner, KeyManager

__all__ = [
    "canonical_json_bytes",
    "compute_canonical_hash",
    "EvidenceSigner",
    "KeyManager",
]
