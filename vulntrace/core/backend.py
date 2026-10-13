"""
VulnTrace Core Execution Backend Abstraction (P0.6)
Decouples verification logic, behavioral oracle, AST analysis, and verdict engine
from execution runtime substrate (Subprocess, Container, WSL2, MicroVM).
"""

import os
import stat
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Set, Union, Tuple
from pydantic import BaseModel, Field

# Canonical project root used as trust anchor for application-controlled fixtures
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent


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


def _is_symlink_or_junction(p: Path) -> bool:
    """
    Checks whether a path is a symbolic link, NTFS junction, or reparse point.

    On Windows (os.name == 'nt'), preserves standard-library checks (Path.is_junction
    on Python 3.12+, os.path.isjunction, p.is_symlink, os.path.islink) and includes
    an os.lstat() fallback for Python 3.11 compatibility.

    Rejecting all reparse points (stat.FILE_ATTRIBUTE_REPARSE_POINT or non-zero
    st_reparse_tag) is an intentional conservative policy for trusted fixture paths.
    If path metadata cannot be inspected safely, fails closed by returning True.
    """
    try:
        # Standard library checks available on Python 3.12+ and POSIX
        if p.is_symlink():
            return True
        if hasattr(p, "is_junction") and p.is_junction():
            return True
        if hasattr(os.path, "isjunction") and os.path.isjunction(str(p)):
            return True
        if os.path.islink(str(p)):
            return True

        # Windows reparse point fallback for Python 3.11 and custom mount points
        if os.name == "nt":
            # If the Windows reparse attribute constant is unavailable, fail closed
            if not hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT"):
                return True

            st = os.lstat(str(p))

            # If required metadata fields on the stat struct are unavailable, fail closed
            if not hasattr(st, "st_file_attributes"):
                return True
            if not hasattr(st, "st_reparse_tag"):
                return True

            if st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
            if st.st_reparse_tag != 0:
                return True
    except (OSError, ValueError, AttributeError):
        # Fail closed: treat inaccessible, broken, or ambiguous paths as unsafe
        return True
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

    # Broad in-project container directories that must never qualify as individual fixture roots
    FORBIDDEN_BROAD_IN_PROJECT_RELPATHS: Tuple[str, ...] = (
        "benchmarks",
        "tests",
        "tests/fixtures",
        "tests/fixtures/deserialization",
        "vulntrace",
        "ui",
        "docs",
        "real_world_eval",
        "verification_screenshots",
    )

    @classmethod
    def _is_forbidden_or_broad_root(cls, path: Path) -> bool:
        """
        Validates that a candidate root is not a dangerous broad root,
        filesystem anchor, project root, system temp root, home directory,
        broad in-project directory, or real_world_eval repository.
        """
        try:
            p_res = path.resolve()
        except (OSError, ValueError):
            return True

        # Filesystem anchor / drive root (e.g. C:\ or /)
        if p_res == Path(p_res.anchor) or p_res == p_res.parent:
            return True

        project_root = PROJECT_ROOT
        # Disallow project root or anything above it
        if p_res == project_root or _is_path_within_root(project_root, p_res):
            return True

        # Disallow broad in-project container directories
        for broad in cls.FORBIDDEN_BROAD_IN_PROJECT_RELPATHS:
            broad_res = (project_root / broad).resolve()
            if p_res == broad_res:
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
    def _validate_dynamic_root(cls, path: Union[str, Path]) -> Optional[Path]:
        """
        Validates a candidate path for dynamic registration (Amendment A).
        Rejects registration if:
        1. Non-existent or non-directory.
        2. Either the original absolute path or its resolved destination lies within PROJECT_ROOT.
        3. Path is a broad root, drive anchor, temp root, user home, or real_world_eval.
        4. Path is redirected through a symlink/junction targeting an unapproved location.
        Returns the resolved Path if valid, otherwise None.
        """
        try:
            raw_path = Path(path)
            unresolved_abs = Path(os.path.abspath(raw_path))
            resolved_path = raw_path.resolve()
        except (OSError, ValueError, TypeError):
            return None

        try:
            if not raw_path.exists() or not raw_path.is_dir():
                return None
            if not resolved_path.exists() or not resolved_path.is_dir():
                return None
        except (OSError, ValueError):
            return None

        project_root = PROJECT_ROOT

        # Amendment A.1: Reject if EITHER the original absolute path OR its resolved destination lies within PROJECT_ROOT
        if _is_path_within_root(unresolved_abs, project_root) or _is_path_within_root(resolved_path, project_root):
            return None

        # Reject broad roots, filesystem anchors, etc.
        if cls._is_forbidden_or_broad_root(resolved_path) or cls._is_forbidden_or_broad_root(unresolved_abs):
            return None

        return resolved_path

    @classmethod
    def get_canonical_fixtures(cls) -> Set[Path]:
        """
        Returns the canonical resolved absolute paths of application-controlled fixtures.
        Enforces Amendment B and ancestor-link integrity:
        - Originates from exact relative allowlist (no absolute paths, no .. traversal)
        - Sequentially inspects every path component from the trusted project root
          to each canonical fixture, rejecting symlinks, NTFS junctions, and unsafe redirections
          at any intermediate level
        - Verifies canonical containment after component validation
        - Cannot be redirected through an ancestor or leaf link
        """
        project_root = PROJECT_ROOT
        canonical: Set[Path] = set()
        for rel in cls.CANONICAL_FIXTURE_RELPATHS:
            rel_path = Path(rel)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                continue

            # Sequentially validate every component from project_root to leaf directory
            curr = project_root
            has_unsafe_component = False
            for part in rel_path.parts:
                curr = curr / part
                try:
                    if not curr.exists() or not curr.is_dir():
                        has_unsafe_component = True
                        break
                    if _is_symlink_or_junction(curr):
                        has_unsafe_component = True
                        break
                except (OSError, ValueError):
                    has_unsafe_component = True
                    break

            if has_unsafe_component:
                continue

            try:
                resolved_path = curr.resolve()

                # Must resolve inside project_root
                if not _is_path_within_root(resolved_path, project_root):
                    continue

                if cls._is_forbidden_or_broad_root(resolved_path):
                    continue

                canonical.add(resolved_path)
            except (OSError, ValueError):
                continue
        return canonical

    @classmethod
    def get_all_approved_roots(cls) -> Set[Path]:
        """
        Returns all approved fixture roots combining canonical locations and dynamic registrations.
        Independently re-validates all dynamic roots on every call (Amendment A.3).
        """
        roots = set(cls.get_canonical_fixtures())
        for r in list(cls._registered_roots):
            valid = cls._validate_dynamic_root(r)
            if valid is not None:
                roots.add(valid)
        return roots

    @classmethod
    def register_trusted_fixture(cls, path: Union[str, Path]) -> None:
        """
        Explicitly registers an external test-controlled directory as a trusted fixture.
        Rejects forbidden broad roots, real-world eval locations, non-existent paths,
        non-directories, and any path originating or resolving within PROJECT_ROOT (Amendment A).
        """
        valid = cls._validate_dynamic_root(path)
        if valid is not None:
            cls._registered_roots.add(valid)

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
        """
        Context manager temporarily registering an external trusted fixture location.
        Enforces dynamic registration validation (Amendment A).
        """
        valid = cls._validate_dynamic_root(path)
        if valid is not None:
            cls._registered_roots.add(valid)
            try:
                yield valid
            finally:
                cls._registered_roots.discard(valid)
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

    project_root = PROJECT_ROOT
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
