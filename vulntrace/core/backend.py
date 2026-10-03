"""
VulnTrace Core Execution Backend Abstraction (P0.6)
Decouples verification logic, behavioral oracle, AST analysis, and verdict engine
from execution runtime substrate (Subprocess, Container, WSL2, MicroVM).
"""

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from pydantic import BaseModel, Field


class IsolationTier(str, Enum):
    LOCAL_SUBPROCESS_FALLBACK = "LOCAL_SUBPROCESS_FALLBACK"
    WSL2_JAILED_CONTAINMENT = "WSL2_JAILED_CONTAINMENT"
    OCI_CONTAINER_ISOLATED = "OCI_CONTAINER_ISOLATED"
    REMOTE_MICROVM_ISOLATED = "REMOTE_MICROVM_ISOLATED"


class BackendCapabilities(BaseModel):
    """
    Explicit, testable security and containment properties of an execution backend.
    Never relies on vague labels such as 'secure' or 'production-grade'.
    """
    tier: IsolationTier
    filesystem_jailed: bool = False
    host_fs_hidden: bool = False
    network_kernel_denied: bool = False
    process_tree_contained: bool = False
    resource_limits_enforced: bool = False
    host_identity_isolated: bool = False
    hardware_virtualized: bool = False
    description: str
    boundary_caveats: List[str] = Field(default_factory=list)


class ExecutionAttestation(BaseModel):
    """
    Parent-generated cryptographic/runtime attestation record.
    Generated exclusively by the trusted parent orchestrator; never by child stdout.
    """
    backend_tier: IsolationTier
    runtime_engine: str
    runtime_version: str
    workspace_id: str
    container_id: Optional[str] = None
    image_digest: Optional[str] = None
    network_mode: str
    mounts: List[str] = Field(default_factory=list)
    capabilities: BackendCapabilities
    attestation_timestamp: float
    verified_by_parent: bool = True
    boundary_caveats: List[str] = Field(default_factory=list)


class ExecutionCommandResult(BaseModel):
    """
    Standardized result emitted by an execution backend.
    """
    exit_code: int
    stdout: str
    stderr: str
    latency_ms: float
    timed_out: bool = False
    sentinel_created: bool = False
    reproduction_state: str = "UNKNOWN"
    assertion_result: Optional[str] = None
    exception_type: Optional[str] = None
    structured_evidence: Optional[Dict[str, Any]] = None
    parent_validated: bool = False
    validation_notes: Optional[str] = None
    attestation: Optional[ExecutionAttestation] = None
    error: Optional[str] = None


class ExecutionBackend(ABC):
    """
    Abstract Execution Backend Interface.
    Orchestrates workspace lifecycle, dependency provisioning, and isolated execution.
    """

    @property
    @abstractmethod
    def capabilities(self) -> BackendCapabilities:
        """Returns the specific enforceable security capabilities of this backend."""
        pass

    @abstractmethod
    async def initialize_workspace(self, source_repo: Path) -> str:
        """
        Clones or stages source files into an isolated workspace.
        Returns a backend-specific workspace identifier.
        """
        pass

    @abstractmethod
    async def provision_dependencies(
        self,
        workspace_id: str,
        manifest_dependencies: List[str],
        timeout: float = 90.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        """
        Provisions target dependencies in a controlled stage.
        """
        pass

    @abstractmethod
    async def execute_script(
        self,
        workspace_id: str,
        script_name: str,
        timeout: float = 10.0,
        sentinel_filename: Optional[str] = None,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        """
        Executes a verification harness in the isolated backend under network denial.
        """
        pass

    @abstractmethod
    async def check_sentinel_marker(self, workspace_id: str, sentinel_filename: str) -> bool:
        """
        Independently probes the isolated workspace for physical sentinel creation.
        """
        pass

    @abstractmethod
    async def run_regression_suite(
        self,
        workspace_id: str,
        timeout: float = 30.0,
        test_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes regression tests (pytest) inside the isolated backend.
        """
        pass

    @abstractmethod
    async def cleanup_workspace(self, workspace_id: str) -> None:
        """
        Destroys the isolated workspace, container, or temporary files.
        """
        pass

    @abstractmethod
    def generate_attestation(self, workspace_id: str) -> ExecutionAttestation:
        """
        Generates a trusted execution attestation record for evidence and verdicts.
        """
        pass
