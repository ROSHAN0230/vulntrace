"""
VulnTrace Core Execution Backend Abstraction (P0.6)
Decouples verification logic, behavioral oracle, AST analysis, and verdict engine
from execution runtime substrate (Subprocess, Container, WSL2, MicroVM).
"""

import os
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Set, Union, Tuple
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
    read_only_rootfs: bool = False
    tmpfs_scratch: bool = False
    non_root_user: bool = False
    description: str
    boundary_caveats: List[str] = Field(default_factory=list)


def _is_path_within_root(target: Path, root: Path) -> bool:
    """Checks whether target equals root or is located within root (safe against casing/separators)."""
    try:
        if target == root:
            return True
        if target.is_relative_to(root):
            return True
    except (ValueError, TypeError):
        pass
    # Case-normalized fallback for Windows / macOS
    try:
        target_norm = os.path.normcase(os.path.abspath(target))
        root_norm = os.path.normcase(os.path.abspath(root))
        if target_norm == root_norm:
            return True
        root_norm_sep = root_norm if root_norm.endswith(os.sep) else root_norm + os.sep
        if target_norm.startswith(root_norm_sep):
            return True
    except Exception:
        pass
    return False


class TrustedFixtureRegistry:
    """
    Deterministic, auditable trusted fixture registry grounded in
    application-controlled configuration (Spec §4.6 Strict Zero-Trust).

    Maintains the authoritative allowlist of approved developer fixtures and
    benchmark repositories eligible for Tier 0 (LocalSubprocess) execution.
    Untrusted, ambiguous, or out-of-registry paths fail closed and mandate Tier 1.
    """
    _registered_roots: Set[Path] = set()

    # Canonical relative paths of approved developer fixtures & benchmarks
    CANONICAL_FIXTURE_RELPATHS: Tuple[str, ...] = (
        # Phase 3 / P0.6 Curated Benchmark Scenarios (Spec §4.14, BENCHMARK_SCENARIOS)
        "benchmarks/contextual_reasoning",
        "benchmarks/deep_callchain",
        "benchmarks/unreachable_dead_code",
        "benchmarks/regression_sensitive",
        "benchmarks/inconclusive_guard",
        # Curated Developer & Oracle Test Fixtures (Spec §4.6, SAFETY.md §4)
        "tests/fixtures/sample_repo",
        "tests/fixtures/deserialization/pickle_fixed",
        "tests/fixtures/deserialization/pickle_vulnerable",
        "tests/fixtures/deserialization/yaml_fixed",
        "tests/fixtures/deserialization/yaml_vulnerable",
    )

    @classmethod
    def _is_forbidden_or_broad_root(cls, path: Path) -> bool:
        """
        Validates that a candidate root is not a dangerous broad root,
        filesystem anchor, project root, system temp root, home directory,
        or real_world_eval repository.
        """
        try:
            p_res = path.resolve()
        except (OSError, ValueError):
            return True

        # Filesystem anchor / drive root (e.g. C:\ or /)
        if p_res == Path(p_res.anchor) or p_res == p_res.parent:
            return True

        project_root = Path(__file__).resolve().parent.parent.parent
        # Disallow project root or anything above it
        if p_res == project_root or _is_path_within_root(project_root, p_res):
            return True

        # Disallow real-world evaluation directory or subdirectories
        real_world_eval_root = (project_root / "real_world_eval").resolve()
        if p_res == real_world_eval_root or _is_path_within_root(p_res, real_world_eval_root):
            return True

        # Disallow system temp directory root
        try:
            sys_temp = Path(tempfile.gettempdir()).resolve()
            if p_res == sys_temp:
                return True
        except Exception:
            pass

        # Disallow user home directory
        try:
            user_home = Path.home().resolve()
            if p_res == user_home:
                return True
        except Exception:
            pass

        return False

    @classmethod
    def get_canonical_fixtures(cls) -> Set[Path]:
        """Returns the canonical resolved absolute paths of application-controlled fixtures."""
        project_root = Path(__file__).resolve().parent.parent.parent
        canonical: Set[Path] = set()
        for rel in cls.CANONICAL_FIXTURE_RELPATHS:
            p = (project_root / rel).resolve()
            if p.exists() and p.is_dir() and not cls._is_forbidden_or_broad_root(p):
                canonical.add(p)
        return canonical

    @classmethod
    def get_all_approved_roots(cls) -> Set[Path]:
        """Returns all approved fixture roots combining canonical locations and dynamic registrations."""
        roots = set(cls.get_canonical_fixtures())
        for r in cls._registered_roots:
            if not cls._is_forbidden_or_broad_root(r):
                roots.add(r)
        return roots

    @classmethod
    def register_trusted_fixture(cls, path: Union[str, Path]) -> None:
        """
        Explicitly registers an application- or test-controlled directory as a trusted fixture.
        Rejects forbidden broad roots, real-world eval locations, non-existent paths, or non-directories.
        """
        try:
            p = Path(path).resolve()
        except Exception:
            return
        if not p.exists() or not p.is_dir():
            return
        if cls._is_forbidden_or_broad_root(p):
            return
        cls._registered_roots.add(p)

    @classmethod
    def unregister_trusted_fixture(cls, path: Union[str, Path]) -> None:
        """Removes an explicitly registered fixture directory."""
        try:
            p = Path(path).resolve()
            cls._registered_roots.discard(p)
        except Exception:
            pass

    @classmethod
    def clear_dynamic_registrations(cls) -> None:
        """Clears all dynamically registered fixture locations."""
        cls._registered_roots.clear()

    @classmethod
    @contextmanager
    def temporary_trusted_fixture(cls, path: Union[str, Path]):
        """Context manager temporarily registering a trusted fixture location."""
        try:
            p = Path(path).resolve()
        except Exception:
            p = None
        if p and not cls._is_forbidden_or_broad_root(p) and p.exists() and p.is_dir():
            cls.register_trusted_fixture(p)
            try:
                yield p
            finally:
                cls.unregister_trusted_fixture(p)
        else:
            yield path


def is_curated_fixture(repo_path: Any) -> bool:
    """
    Determines whether a repository path is an approved curated developer fixture
    (permitted to execute under Tier 0 LocalSubprocess) or a real/non-curated repository
    (which mandates Tier 1 rootless container isolation under Spec §4.6).

    Replaces self-declared marker files (.vulntrace_curated_fixture) and broad path substrings
    with deterministic, auditable verification grounded in TrustedFixtureRegistry.
    Fails closed for unknown, ambiguous, non-existent, and aliased paths.
    """
    if repo_path is None:
        return False

    try:
        raw_path = Path(repo_path)
    except Exception:
        return False

    if str(repo_path).strip() == "":
        return False

    try:
        if not raw_path.exists() or not raw_path.is_dir():
            return False
    except (OSError, ValueError):
        return False

    project_root = Path(__file__).resolve().parent.parent.parent
    real_world_eval_root = (project_root / "real_world_eval").resolve()

    try:
        resolved_path = raw_path.resolve()
        unresolved_abs = Path(os.path.abspath(raw_path))
    except (OSError, ValueError):
        return False

    # Strictly reject untrusted real-world evaluation repositories unconditionally
    if _is_path_within_root(resolved_path, real_world_eval_root) or _is_path_within_root(unresolved_abs, real_world_eval_root):
        return False

    # Strictly reject forbidden or broad roots
    if TrustedFixtureRegistry._is_forbidden_or_broad_root(resolved_path) or TrustedFixtureRegistry._is_forbidden_or_broad_root(unresolved_abs):
        return False

    approved_roots = TrustedFixtureRegistry.get_all_approved_roots()

    # 1. Resolved canonical path MUST reside within an approved fixture root
    resolved_match = any(_is_path_within_root(resolved_path, root) for root in approved_roots)
    if not resolved_match:
        return False

    # 2. Input path before symlink/junction resolution MUST ALSO reside within an approved fixture root.
    # This prevents external repositories from aliasing into an approved location using junctions/symlinks.
    unresolved_match = any(_is_path_within_root(unresolved_abs, root) for root in approved_roots)
    if not unresolved_match:
        return False

    return True



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

    def is_available(self) -> bool:
        """Checks whether this execution backend is available on the current host."""
        return True

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
