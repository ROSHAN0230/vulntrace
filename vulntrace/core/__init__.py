"""
VulnTrace Core Architecture Package (P0.6)
Execution backend abstractions, isolation tiers, attestation, and factories.
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

__all__ = [
    "IsolationTier",
    "BackendCapabilities",
    "ExecutionAttestation",
    "ExecutionCommandResult",
    "ExecutionBackend",
    "LocalSubprocessBackend",
    "ContainerExecutionBackend",
    "BackendFactory"
]
