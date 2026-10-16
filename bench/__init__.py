"""
VulnTrace Bench Package.
Provides canonical 3-repeat benchmark orchestration, protocol conformance validation,
deterministic evidence generation, and README table drift checks (Spec §3.1, §4.15, §5.1, §5.2).
"""

from bench.run import (
    evaluate_three_repeat_verdict,
    validate_record_protocol_conformance,
    main_cli,
)

__all__ = [
    "evaluate_three_repeat_verdict",
    "validate_record_protocol_conformance",
    "main_cli",
]
