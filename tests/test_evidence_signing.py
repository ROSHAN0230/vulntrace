"""
Acceptance Tests for VulnTrace Evidence Schema v1 & Cryptographic Signing (Spec §4.11, AC4).
Covers:
1. Deterministic canonical JSON serialization and hashing (RFC 8785).
2. Pure-Python Ed25519 key generation, signing, and verification.
3. Schema v1 evidence bundle creation and signing.
4. Tamper detection: Flipping a single byte in any payload section causes verification to fail.
5. CLI `vulntrace verify-bundle` returns 0 on authentic bundles and 1 on tampered bundles.
"""

import json
from pathlib import Path

from vulntrace.evidence.canonical import canonical_json_bytes, compute_canonical_hash
from vulntrace.evidence.signing import KeyManager, EvidenceSigner, ed25519_sign, ed25519_verify
from vulntrace.cli import main as cli_main


SAMPLE_SCHEMA_V1_PAYLOAD = {
    "run_id": "run_test_884920482910",
    "created_at": "2026-10-07T12:00:00Z",
    "tool_versions": {
        "vulntrace": "0.1.0",
        "python": "3.11.9"
    },
    "python_version": "3.11.9",
    "source": {
        "type": "github",
        "url": "https://github.com/example/target-repo",
        "upload_sha256": None,
        "commit": "a1b2c3d4"
    },
    "sandbox": {
        "tier": "TIER_1_ROOTLESS_CONTAINER",
        "limits": {
            "memory": "512m",
            "cpus": "1.0",
            "pids_limit": 128,
            "timeout_sec": 10.0
        },
        "network_policy": "NONE"
    },
    "intel": {
        "status": "enriched",
        "queries": ["CVE-2018-1000851 fast-json vulnerable parser"],
        "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000851"],
        "response_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    },
    "analysis": {
        "findings": [{"cve": "CVE-2018-1000851", "sink": "yaml.load"}],
        "reachability": {
            "paths": ["REACHABLE_CONFIRMED"],
            "blind_spots": []
        },
        "baseline_tests": {"passed": True, "test_count": 12}
    },
    "spec": {
        "requirement": "Surgically patch arbitrary YAML deserialization in parse_config",
        "parsed_spec": {
            "must_fix": "CVE-2018-1000851",
            "must_preserve": ["regression tests"],
            "constraints": ["diff_budget <= 30 lines", "max_files <= 3"],
            "out_of_scope": ["refactoring"]
        },
        "acceptance_tests": [
            {"name": "test_cve_exploit_blocked", "harness_sha256": "abcdef1234567890"}
        ]
    },
    "llm": {
        "calls": [
            {
                "stage": "THREAT_INTEL",
                "model": "google/gemini-2.5-flash",
                "prompt_tokens": 150,
                "completion_tokens": 40,
                "reasoning_tokens": 0,
                "latency_ms": 210.5
            },
            {
                "stage": "REMEDIATION_ULTRA",
                "model": "nvidia/nemotron-3-ultra",
                "prompt_tokens": 420,
                "completion_tokens": 95,
                "reasoning_tokens": 20,
                "latency_ms": 612.0
            }
        ]
    },
    "verification": {
        "harness_sha256": "abcdef1234567890",
        "red_runs": [{"exit_code": 0, "sentinel_created": True}],
        "green_runs": [{"exit_code": 1, "sentinel_created": False}],
        "positive_control": {"status": "PASSED"},
        "regression": {"passed": True, "test_count": 12}
    },
    "attempts": [
        {
            "diff": "--- a/config.py\n+++ b/config.py\n@@ -1 +1 @@\n-yaml.load(s)\n+yaml.safe_load(s)\n",
            "gates": {"syntax_parse": True, "plan_scope": True, "ast_denylist": True, "diff_budget": True},
            "result": {"success": True, "engine": "NVIDIA_NEMOTRON_3_ULTRA", "validation_status": "APPROVED"}
        }
    ],
    "verdict": "GREEN_STATE_VERIFIED",
    "limitations": [
        "Static AST reachability cannot analyze dynamic reflection.",
        "Executed in Tier-1 rootless container sandbox with zero network."
    ]
}


def test_canonical_json_deterministic_ordering():
    """Proves dictionary key insertion order does not affect canonical representation or hash."""
    dict_a = {"z": 1, "a": {"d": 4, "c": 3}, "m": "hello"}
    dict_b = {"m": "hello", "a": {"c": 3, "d": 4}, "z": 1}

    bytes_a = canonical_json_bytes(dict_a)
    bytes_b = canonical_json_bytes(dict_b)

    assert bytes_a == bytes_b
    assert compute_canonical_hash(dict_a) == compute_canonical_hash(dict_b)
    # Ensure compact separators: no spaces after colon or comma
    assert b": " not in bytes_a
    assert b", " not in bytes_a


def test_ed25519_pure_python_sign_and_verify(tmp_path: Path):
    """Proves RFC 8032 pure-Python implementation accurately signs and verifies data."""
    priv_bytes, pub_bytes = KeyManager.get_or_create_keys(key_dir=tmp_path / "keys")
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    message = b"Canonical test payload for VulnTrace verification"
    signature = ed25519_sign(priv_bytes, message)
    assert len(signature) == 64

    # Verification must succeed
    assert ed25519_verify(pub_bytes, message, signature) is True

    # Modified message must fail verification
    assert ed25519_verify(pub_bytes, message + b"!", signature) is False

    # Modified signature must fail verification
    corrupt_sig = bytearray(signature)
    corrupt_sig[0] ^= 0x01
    assert ed25519_verify(pub_bytes, message, bytes(corrupt_sig)) is False


def test_fresh_bundle_signing_and_verification(tmp_path: Path):
    """Proves a freshly signed evidence bundle succeeds under EvidenceSigner verification."""
    priv_bytes, pub_bytes = KeyManager.get_or_create_keys(key_dir=tmp_path / "keys")

    signed_bundle = EvidenceSigner.sign_bundle(
        SAMPLE_SCHEMA_V1_PAYLOAD,
        private_key=priv_bytes,
        public_key=pub_bytes
    )

    assert "signature" in signed_bundle
    sig = signed_bundle["signature"]
    assert sig["alg"] == "Ed25519"
    assert sig["public_key"] == pub_bytes.hex()
    assert sig["public_key_fingerprint"] == EvidenceSigner.compute_fingerprint(pub_bytes)

    valid, reason = EvidenceSigner.verify_bundle(signed_bundle)
    assert valid is True
    assert reason == "VERIFICATION_SUCCESSFUL"


def test_bundle_tamper_single_byte_fails_verification(tmp_path: Path):
    """Proves flipping even a single byte in any payload field causes verification to fail."""
    priv_bytes, pub_bytes = KeyManager.get_or_create_keys(key_dir=tmp_path / "keys")

    signed_bundle = EvidenceSigner.sign_bundle(
        SAMPLE_SCHEMA_V1_PAYLOAD,
        private_key=priv_bytes,
        public_key=pub_bytes
    )

    # 1. Tamper with the verdict string: change GREEN_STATE_VERIFIED to RED_STATE_CONFIRMED
    tampered_bundle = json.loads(json.dumps(signed_bundle))
    tampered_bundle["verdict"] = "RED_STATE_CONFIRMED"

    valid, reason = EvidenceSigner.verify_bundle(tampered_bundle)
    assert valid is False
    assert "Canonical SHA-256 mismatch" in reason or "verification failed" in reason

    # 2. Tamper with a single character in the diff
    tampered_diff_bundle = json.loads(json.dumps(signed_bundle))
    tampered_diff_bundle["attempts"][0]["diff"] = tampered_diff_bundle["attempts"][0]["diff"].replace("yaml", "yml")

    valid, reason = EvidenceSigner.verify_bundle(tampered_diff_bundle)
    assert valid is False
    assert "Canonical SHA-256 mismatch" in reason or "verification failed" in reason

    # 3. Tamper with LLM token count
    tampered_llm_bundle = json.loads(json.dumps(signed_bundle))
    tampered_llm_bundle["llm"]["calls"][0]["prompt_tokens"] += 1

    valid, reason = EvidenceSigner.verify_bundle(tampered_llm_bundle)
    assert valid is False
    assert "Canonical SHA-256 mismatch" in reason or "verification failed" in reason


def test_cli_verify_bundle_fresh_and_tampered(tmp_path: Path):
    """Proves `vulntrace verify-bundle` CLI returns 0 on fresh bundle and 1 on tampered bundle."""
    bundle_path = tmp_path / "bundle.json"
    priv_bytes, pub_bytes = KeyManager.get_or_create_keys(key_dir=tmp_path / "keys")

    signed_bundle = EvidenceSigner.sign_bundle(
        SAMPLE_SCHEMA_V1_PAYLOAD,
        private_key=priv_bytes,
        public_key=pub_bytes
    )
    bundle_path.write_text(json.dumps(signed_bundle, indent=2), encoding="utf-8")

    # CLI verification on valid bundle
    exit_code = cli_main(["verify-bundle", str(bundle_path)])
    assert exit_code == 0

    # Flip 1 byte in the JSON file
    raw_text = bundle_path.read_text(encoding="utf-8")
    tampered_text = raw_text.replace("3.11.9", "3.11.8")
    bundle_path.write_text(tampered_text, encoding="utf-8")

    # CLI verification on tampered bundle
    exit_code_tampered = cli_main(["verify-bundle", str(bundle_path)])
    assert exit_code_tampered == 1


def test_rfc8032_known_test_vectors():
    """
    Validates pure-Python Ed25519 implementation against official RFC 8032 Section 7.1 test vectors:
    - Test 1 (0 bytes message)
    - Test 2 (1 byte message)
    - Test 3 (2 bytes message)
    """
    from vulntrace.evidence.signing import ed25519_public_key

    vectors = [
        {
            "name": "RFC 8032 Test 1 (0 bytes)",
            "secret": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "message": b"",
            "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        {
            "name": "RFC 8032 Test 2 (1 byte)",
            "secret": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "message": bytes.fromhex("72"),
            "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
        {
            "name": "RFC 8032 Test 3 (2 bytes)",
            "secret": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "message": bytes.fromhex("af82"),
            "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        }
    ]

    for v in vectors:
        sec = bytes.fromhex(v["secret"])
        expected_pub = bytes.fromhex(v["public"])
        msg = v["message"]
        expected_sig = bytes.fromhex(v["signature"])

        # 1. Public key derivation check
        derived_pub = ed25519_public_key(sec)
        assert derived_pub == expected_pub, f"Public key derivation mismatch for {v['name']}"

        # 2. Signing check
        computed_sig = ed25519_sign(sec, msg)
        assert computed_sig == expected_sig, f"Signature mismatch for {v['name']}"

        # 3. Verification check
        assert ed25519_verify(expected_pub, msg, expected_sig) is True, f"Verification failed for {v['name']}"

        # 4. Tamper check: flip last byte of message or signature
        tampered_msg = msg + b"\x01" if msg else b"\x01"
        assert ed25519_verify(expected_pub, tampered_msg, expected_sig) is False


def test_ed25519_cross_verification_with_cryptography():
    """
    Cross-checks the custom pure-Python Ed25519 implementation against the vetted
    `cryptography` library implementation:
    - Derives matching public key bytes from raw private seed.
    - Generates matching 64-byte signature bit-for-bit.
    - Pure-Python verifies cryptography signatures.
    - Cryptography verifies pure-Python signatures.
    - Verifies public key SHA-256 fingerprint consistency.
    """
    import os
    import hashlib
    import pytest
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        pytest.skip("cryptography library not installed")

    from vulntrace.evidence.signing import ed25519_public_key

    for _ in range(3):
        seed = os.urandom(32)
        message = os.urandom(128)

        # 1. Key derivation cross-check
        py_pub = ed25519_public_key(seed)
        cr_priv = crypto_ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        cr_pub_bytes = cr_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        assert py_pub == cr_pub_bytes, "Public key mismatch between pure-Python and cryptography"

        # 2. Fingerprint consistency
        fp_py = EvidenceSigner.compute_fingerprint(py_pub)
        fp_cr = hashlib.sha256(cr_pub_bytes).hexdigest()
        assert fp_py == fp_cr, "Fingerprint mismatch"

        # 3. Signing cross-check (RFC 8032 is deterministic, signatures must be identical)
        py_sig = ed25519_sign(seed, message)
        cr_sig = cr_priv.sign(message)
        assert py_sig == cr_sig, "Signature mismatch between pure-Python and cryptography"

        # 4. Bidirectional verification
        assert ed25519_verify(cr_pub_bytes, message, cr_sig) is True
        assert ed25519_verify(py_pub, message, py_sig) is True

        cr_priv.public_key().verify(py_sig, message)

        # 5. Tamper detection cross-check
        tampered_sig = bytearray(py_sig)
        tampered_sig[0] ^= 0xFF
        assert ed25519_verify(py_pub, message, bytes(tampered_sig)) is False

