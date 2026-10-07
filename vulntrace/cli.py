"""
VulnTrace Studio Command-Line Interface (Spec §4.11 / §6 AC4)
Provides `vulntrace verify-bundle <bundle.json>` for cryptographic verification.
"""

import sys
import json
import argparse
from pathlib import Path
from vulntrace import __version__
from vulntrace.evidence.signing import EvidenceSigner


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    """Verifies a signed evidence bundle JSON file."""
    bundle_path = Path(args.bundle_file)
    if not bundle_path.exists():
        print(f"[FAIL] Bundle file does not exist: {bundle_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(bundle_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[FAIL] Failed to parse JSON bundle: {e}", file=sys.stderr)
        return 1

    valid, reason = EvidenceSigner.verify_bundle(data)
    if not valid:
        print("[FAIL] Cryptographic verification failed!", file=sys.stderr)
        print(f"Reason: {reason}", file=sys.stderr)
        return 1

    sig = data.get("signature", {})
    print("[OK] Evidence Bundle verified successfully!")
    print(f"  Run ID:              {data.get('run_id')}")
    print(f"  Verdict:             {data.get('verdict')}")
    print(f"  Algorithm:           {sig.get('alg')}")
    print(f"  Signer Fingerprint:  {sig.get('public_key_fingerprint')}")
    print(f"  Canonical SHA-256:   {sig.get('canonical_sha256')}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulntrace",
        description="VulnTrace Studio — Autonomous Vulnerability Reproduction & Verified Patching"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    verify_parser = subparsers.add_parser(
        "verify-bundle",
        help="Recompute canonical hashes and verify Ed25519 signature of an evidence bundle"
    )
    verify_parser.add_argument(
        "bundle_file",
        help="Path to the evidence bundle JSON file"
    )
    verify_parser.set_defaults(func=cmd_verify_bundle)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
