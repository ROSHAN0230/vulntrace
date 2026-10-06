"""
VulnTrace Execution Backend Factory (P0.6)
Resolves the most secure available execution substrate (OCI Container vs. Local Subprocess Fallback)
with explicit, non-misleading capability declarations.
"""

import os
import logging
from pathlib import Path
from typing import Optional, Union

from vulntrace.core.backend import ExecutionBackend, IsolationTier, is_curated_fixture
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.container_backend import ContainerExecutionBackend

logger = logging.getLogger("vulntrace.core.factory")


class BackendFactory:
    """
    Factory for resolving and instantiating execution backends based on host capabilities,
    repository curation status, and environment configuration.
    """

    @classmethod
    def resolve_best_available_backend(
        cls,
        prefer_container: bool = True,
        force_tier: Optional[IsolationTier] = None,
        target_repo: Optional[Union[str, Path]] = None,
        unsafe_local: bool = False
    ) -> ExecutionBackend:
        """
        Selects the best execution backend.
        1. If explicitly forced via force_tier or VULNTRACE_EXECUTION_BACKEND env var:
           Honors the request or raises an error if unavailable. Refuses Tier 0 for non-curated repos unless unsafe_local is True.
        2. Tier 1 (rootless container) is the mandatory default tier for all real/non-curated repositories.
        3. If Tier 1 is unavailable on a real repository, execution is refused unless unsafe_local is explicitly enabled.
        4. Curated developer fixtures may run on Tier 0 with explicit degraded attestation.
        """
        repo_path = Path(target_repo).resolve() if target_repo else None
        is_curated = is_curated_fixture(repo_path)
        effective_unsafe = unsafe_local or (os.environ.get("VULNTRACE_UNSAFE_LOCAL") in ("1", "true", "True"))

        env_forced = os.environ.get("VULNTRACE_EXECUTION_BACKEND")
        if env_forced:
            if "CONTAINER" in env_forced.upper() or "OCI" in env_forced.upper() or "TIER1" in env_forced.upper() or "TIER_1" in env_forced.upper():
                force_tier = IsolationTier.OCI_CONTAINER_ISOLATED
            elif "LOCAL" in env_forced.upper() or "SUBPROCESS" in env_forced.upper() or "TIER0" in env_forced.upper() or "TIER_0" in env_forced.upper():
                force_tier = IsolationTier.LOCAL_SUBPROCESS_FALLBACK

        if force_tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK:
            if repo_path and not is_curated and not effective_unsafe and os.environ.get("CI") != "true":
                raise PermissionError(
                    f"Tier 0 (LocalSubprocess) refused non-curated repository '{repo_path.name}' without --unsafe-local. "
                    "Use Isolation Tier 1 (OCI Container) or pass unsafe_local=True."
                )
            logger.info("BackendFactory: Explicitly selected LOCAL_SUBPROCESS_FALLBACK (Tier 0).")
            return LocalSubprocessBackend(unsafe_local=effective_unsafe)

        if force_tier == IsolationTier.OCI_CONTAINER_ISOLATED:
            container_backend = ContainerExecutionBackend()
            if not container_backend.is_available():
                raise RuntimeError(
                    "OCI_CONTAINER_ISOLATED backend was explicitly requested, but Podman/crun rootless container runtime is not available."
                )
            logger.info("BackendFactory: Explicitly selected OCI_CONTAINER_ISOLATED (Tier 1).")
            return container_backend

        # Auto-detect best tier (Spec §4.6: Tier 1 is default for all real runs)
        if prefer_container:
            try:
                container_backend = ContainerExecutionBackend()
                if container_backend.is_available():
                    logger.info("BackendFactory: OCI Rootless Container substrate detected and selected (Tier 1).")
                    return container_backend
            except Exception as e:
                logger.warning(f"BackendFactory: Container probe failed ({e}).")

        # Container is unavailable
        if repo_path and not is_curated:
            if effective_unsafe or os.environ.get("CI") == "true":
                logger.warning(
                    f"BackendFactory: OCI container unavailable for non-curated repository '{repo_path.name}'. "
                    "Falling back to Tier 0 LOCAL_SUBPROCESS_FALLBACK under explicit unsafe_local override."
                )
                return LocalSubprocessBackend(unsafe_local=True)
            raise PermissionError(
                f"Repository '{repo_path.name}' is a real/non-curated codebase requiring Isolation Tier 1 "
                "(rootless container). Podman/OCI container is not available and unsafe_local is False. "
                "Refusing uncontained execution on host."
            )

        logger.info(
            "BackendFactory: Selecting LOCAL_SUBPROCESS_FALLBACK for curated fixture."
        )
        return LocalSubprocessBackend(unsafe_local=effective_unsafe)
