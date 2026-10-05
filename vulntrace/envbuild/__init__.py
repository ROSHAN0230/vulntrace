"""
VulnTrace Dedicated Target Environment Builder (Spec §4.5)
Provides per-case isolated virtual environment provisioning, wheel caching,
deterministic Python version selection, manifest-based dependency installation,
and truthful ENV_BUILD_FAILED failure classification.
"""

from vulntrace.envbuild.builder import (
    EnvironmentBuilder,
    EnvironmentBuildResult,
)

__all__ = [
    "EnvironmentBuilder",
    "EnvironmentBuildResult",
]
