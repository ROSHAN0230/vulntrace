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
