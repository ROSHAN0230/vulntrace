"""
VulnTrace Core Architecture Package (P0.6/P0.7)
Execution backend abstractions, isolation tiers, attestation, factories, and security policy.
"""

from vulntrace.core.backend import (
    IsolationTier,
    BackendCapabilities,
    ExecutionAttestation,
    ExecutionCommandResult,
    ExecutionBackend
)
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.container_backend import ContainerExecutionBackend
from vulntrace.core.factory import BackendFactory
from vulntrace.core.policy import (
    ExecutionOperation,
    AssuranceLevel,
    PolicyDecision,
    SecurityPolicyEngine
)

__all__ = [
    "IsolationTier",
    "BackendCapabilities",
    "ExecutionAttestation",
    "ExecutionCommandResult",
    "ExecutionBackend",
    "LocalSubprocessBackend",
    "ContainerExecutionBackend",
    "BackendFactory",
    "ExecutionOperation",
    "AssuranceLevel",
    "PolicyDecision",
    "SecurityPolicyEngine"
]
