"""
VulnTrace Execution Backend Factory (P0.6)
Resolves the most secure available execution substrate (OCI Container vs. Local Subprocess Fallback)
with explicit, non-misleading capability declarations.
"""

import os
import logging
from typing import Optional

from vulntrace.core.backend import ExecutionBackend, IsolationTier
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.container_backend import ContainerExecutionBackend

logger = logging.getLogger("vulntrace.core.factory")


class BackendFactory:
    """
    Factory for resolving and instantiating execution backends based on host capabilities
    and environment configuration.
    """

    @classmethod
    def resolve_best_available_backend(
        cls,
        prefer_container: bool = True,
        force_tier: Optional[IsolationTier] = None
    ) -> ExecutionBackend:
        """
        Selects the best execution backend.
        1. If explicitly forced via force_tier or VULNTRACE_EXECUTION_BACKEND env var:
           Honors the request or raises an error if unavailable.
        2. Otherwise, probes for OCI container availability (Podman/crun rootless).
        3. If unavailable, falls back to LocalSubprocessBackend with explicit caveats.
        """
        env_forced = os.environ.get("VULNTRACE_EXECUTION_BACKEND")
        if env_forced:
            if "CONTAINER" in env_forced.upper() or "OCI" in env_forced.upper():
                force_tier = IsolationTier.OCI_CONTAINER_ISOLATED
            elif "LOCAL" in env_forced.upper() or "SUBPROCESS" in env_forced.upper():
                force_tier = IsolationTier.LOCAL_SUBPROCESS_FALLBACK

        if force_tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK:
            logger.info("BackendFactory: Explicitly selected LOCAL_SUBPROCESS_FALLBACK.")
            return LocalSubprocessBackend()

        if force_tier == IsolationTier.OCI_CONTAINER_ISOLATED:
            container_backend = ContainerExecutionBackend()
            if not container_backend.is_available():
                raise RuntimeError(
                    "OCI_CONTAINER_ISOLATED backend was explicitly requested, but Podman/crun is not available."
                )
            logger.info("BackendFactory: Explicitly selected OCI_CONTAINER_ISOLATED.")
            return container_backend

        # Auto-detect best tier
        if prefer_container:
            try:
                container_backend = ContainerExecutionBackend()
                if container_backend.is_available():
                    logger.info("BackendFactory: OCI Rootless Container substrate detected and selected (Tier 1).")
                    return container_backend
            except Exception as e:
                logger.warning(f"BackendFactory: Container probe failed ({e}); falling back to local subprocess.")

        logger.info(
            "BackendFactory: Selecting LOCAL_SUBPROCESS_FALLBACK (Win32 Job Object, memory caps, sanitized env)."
        )
        return LocalSubprocessBackend()
