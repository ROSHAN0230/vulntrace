"""
VulnTrace Cryptographic Evidence Signing & Bundle Verification (Spec §4.11 / §6 AC4)
Implements RFC 8032 pure-Python Ed25519 digital signatures and tamper-evident verification.
Guarantees:
1. Local private key generation and secure filesystem persistence (~/.vulntrace/keys/).
2. Canonical JSON payload signing.
3. Strict single-byte tamper detection.
4. CLI verification interface: `vulntrace verify-bundle bundle.json`.
"""

import os
import hashlib
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from vulntrace.evidence.canonical import canonical_json_bytes


# ---------------------------------------------------------------------------
# Pure-Python RFC 8032 Ed25519 Implementation (Zero External C-Dependencies)
# ---------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _point_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    denom_x = (1 + D * x1 * x2 * y1 * y2) % P
    denom_y = (1 - D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + y1 * x2) * pow(denom_x, P - 2, P)) % P
    y3 = ((y1 * y2 + x1 * x2) * pow(denom_y, P - 2, P)) % P
    return (x3, y3)


def _point_mul(s, p):
    q = (0, 1)  # Neutral element
    b = p
    while s > 0:
        if s & 1:
            q = _point_add(q, b)
        b = _point_add(b, b)
        s >>= 1
    return q


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = ((y * y - 1) * pow(D * y * y + 1, P - 2, P)) % P
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * SQRT_M1) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


# Base point B
_By = (4 * pow(5, P - 2, P)) % P
_Bx = _recover_x(_By, 0)
B = (_Bx, _By)


def _encode_point(p):
    x, y = p
    s = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        s[31] |= 0x80
    return bytes(s)


def _decode_point(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y)


def ed25519_public_key(secret_key_bytes: bytes) -> bytes:
    """Derives 32-byte Ed25519 public key from 32-byte private seed."""
    h = hashlib.sha512(secret_key_bytes).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar = int.from_bytes(a, "little")
    A = _point_mul(scalar, B)
    return _encode_point(A)


def ed25519_sign(secret_key_bytes: bytes, message: bytes) -> bytes:
    """Signs message using 32-byte Ed25519 private key seed. Returns 64-byte signature."""
    h = hashlib.sha512(secret_key_bytes).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar_a = int.from_bytes(a, "little")

    prefix = h[32:]
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    R = _point_mul(r, B)
    R_bytes = _encode_point(R)

    pub_bytes = _encode_point(_point_mul(scalar_a, B))
    k = int.from_bytes(hashlib.sha512(R_bytes + pub_bytes + message).digest(), "little") % L
    S = (r + k * scalar_a) % L
    return R_bytes + S.to_bytes(32, "little")


def ed25519_verify(public_key_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    """Verifies 64-byte signature against 32-byte public key and message."""
    if len(signature_bytes) != 64 or len(public_key_bytes) != 32:
        return False
    R_bytes = signature_bytes[:32]
    S = int.from_bytes(signature_bytes[32:], "little")
    if S >= L:
        return False

    R = _decode_point(R_bytes)
    A = _decode_point(public_key_bytes)
    if R is None or A is None:
        return False

    k = int.from_bytes(hashlib.sha512(R_bytes + public_key_bytes + message).digest(), "little") % L

    SB = _point_mul(S, B)
    kA = _point_mul(k, A)
    R_plus_kA = _point_add(R, kA)
    return SB == R_plus_kA


# ---------------------------------------------------------------------------
# Key Storage & Management
# ---------------------------------------------------------------------------

KEY_DIR = Path.home() / ".vulntrace" / "keys"


class KeyManager:
    """Manages local Ed25519 key generation and retrieval."""

    @classmethod
    def get_or_create_keys(cls, key_dir: Optional[Path] = None) -> Tuple[bytes, bytes]:
        """
        Retrieves or initializes local Ed25519 signing keypair.
        Never commits keys; stores locally in ~/.vulntrace/keys/.
        """
        target_dir = Path(key_dir or KEY_DIR)
        target_dir.mkdir(parents=True, exist_ok=True)
        priv_path = target_dir / "ed25519_private.hex"
        pub_path = target_dir / "ed25519_public.hex"

        if priv_path.exists() and pub_path.exists():
            priv_hex = priv_path.read_text(encoding="utf-8").strip()
            pub_hex = pub_path.read_text(encoding="utf-8").strip()
            return bytes.fromhex(priv_hex), bytes.fromhex(pub_hex)

        # Generate new random 32-byte seed
        priv_bytes = os.urandom(32)
        pub_bytes = ed25519_public_key(priv_bytes)

        priv_path.write_text(priv_bytes.hex(), encoding="utf-8")
        pub_path.write_text(pub_bytes.hex(), encoding="utf-8")

        # Set restrictive permissions where supported
        try:
            priv_path.chmod(0o600)
        except Exception:
            pass

        return priv_bytes, pub_bytes


# ---------------------------------------------------------------------------
# Bundle Signing and Verification Engine
# ---------------------------------------------------------------------------

class EvidenceSigner:
    """Signs and cryptographically verifies VulnTrace evidence bundles."""

    @classmethod
    def compute_fingerprint(cls, pub_bytes: bytes) -> str:
        """SHA-256 fingerprint of the public key bytes."""
        return hashlib.sha256(pub_bytes).hexdigest()

    @classmethod
    def sign_bundle(
        cls,
        bundle_dict: Dict[str, Any],
        private_key: Optional[bytes] = None,
        public_key: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Canonicalizes bundle content without 'signature', signs it with Ed25519,
        and returns the signed bundle dict including the signature metadata.
        """
        if not private_key or not public_key:
            priv_b, pub_b = KeyManager.get_or_create_keys()
        else:
            priv_b, pub_b = private_key, public_key

        # Prepare payload without signature block
        clean_bundle = {k: v for k, v in bundle_dict.items() if k != "signature"}
        canonical_bytes = canonical_json_bytes(clean_bundle)
        canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        # Sign the canonical byte stream
        sig_bytes = ed25519_sign(priv_b, canonical_bytes)
        fingerprint = cls.compute_fingerprint(pub_b)

        clean_bundle["signature"] = {
            "alg": "Ed25519",
            "public_key_fingerprint": fingerprint,
            "public_key": pub_b.hex(),
            "canonical_sha256": canonical_sha256,
            "sig": sig_bytes.hex()
        }
        return clean_bundle

    @classmethod
    def verify_bundle(cls, bundle_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verifies that an evidence bundle has not been tampered with:
        1. Validates signature block structure.
        2. Validates public key fingerprint matches public key.
        3. Strips signature block, reconstructs canonical bytes.
        4. Recomputes canonical SHA-256 and verifies Ed25519 signature.
        Fails if even a single byte has changed.
        """
        sig_block = bundle_dict.get("signature")
        if not sig_block:
            return False, "Missing 'signature' block in evidence bundle."

        alg = sig_block.get("alg")
        if alg != "Ed25519":
            return False, f"Unsupported signature algorithm '{alg}'. Expected 'Ed25519'."

        pub_hex = sig_block.get("public_key")
        fp = sig_block.get("public_key_fingerprint")
        sig_hex = sig_block.get("sig")

        if not pub_hex or not fp or not sig_hex:
            return False, "Malformed signature block: missing public_key, public_key_fingerprint, or sig."

        try:
            pub_bytes = bytes.fromhex(pub_hex)
            sig_bytes = bytes.fromhex(sig_hex)
        except Exception as e:
            return False, f"Hex decode failure in signature block: {e}"

        # Fingerprint match check
        computed_fp = cls.compute_fingerprint(pub_bytes)
        if computed_fp != fp:
            return False, f"Public key fingerprint mismatch. Declared '{fp}' != computed '{computed_fp}'."

        # Canonicalize payload without signature
        clean_bundle = {k: v for k, v in bundle_dict.items() if k != "signature"}
        canonical_bytes = canonical_json_bytes(clean_bundle)
        computed_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

        declared_sha256 = sig_block.get("canonical_sha256")
        if declared_sha256 and declared_sha256 != computed_sha256:
            return False, (
                f"Canonical SHA-256 mismatch: bundle content has been modified. "
                f"Declared '{declared_sha256}' != computed '{computed_sha256}'."
            )

        # Ed25519 cryptographic signature check
        is_valid = ed25519_verify(pub_bytes, canonical_bytes, sig_bytes)
        if not is_valid:
            return False, "Cryptographic signature verification failed: signature does not match bundle content."

        return True, "VERIFICATION_SUCCESSFUL"
