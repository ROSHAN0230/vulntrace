"""
VulnTrace Anti-Gaming Verifier (Spec §4.4)
"""

from vulntrace.verifier.anti_gaming import (
    PatchDenylistResult,
    PatchDenylistValidator,
    IntegrityAuditor,
)
from vulntrace.verifier.runner import (
    SingleRunResult,
    AntiGamingAuditSummary,
    AntiGamingVerifier,
)

__all__ = [
    "PatchDenylistResult",
    "PatchDenylistValidator",
    "IntegrityAuditor",
    "SingleRunResult",
    "AntiGamingAuditSummary",
    "AntiGamingVerifier",
]
