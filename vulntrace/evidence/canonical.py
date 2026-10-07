"""
VulnTrace Canonical JSON Serialization & Hashing (Spec §4.11)
Implements deterministic JSON canonicalization (RFC 8785 compatible) and SHA-256 fingerprinting.
"""

import json
import hashlib
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Serializes a Python object to canonical JSON bytes:
    - Dict keys sorted recursively in lexicographical order.
    - Strict compact separators (no whitespace after ':' or ',').
    - Floats and ints formatted deterministically.
    - UTF-8 encoded without BOM.
    """
    def _normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {k: _normalize(v) for k, v in sorted(item.items(), key=lambda pair: pair[0])}
        elif isinstance(item, (list, tuple)):
            return [_normalize(x) for x in item]
        return item

    normalized = _normalize(obj)
    json_str = json.dumps(
        normalized,
        sort_keys=True,
        ensure_ascii=False,
        separators=(',', ':')
    )
    return json_str.encode("utf-8")


def compute_canonical_hash(obj: Any) -> str:
    """
    Computes the hex-encoded SHA-256 fingerprint of the canonically serialized object.
    """
    data = canonical_json_bytes(obj)
    return hashlib.sha256(data).hexdigest()
