"""
VulnTrace Security Capability Policy Engine (P0.7)
Evaluates BackendCapabilities against enforceable operational security policies.
Ensures that weak backends (LOCAL_SUBPROCESS_FALLBACK) cannot silently claim
high-assurance containment, and that operations enforce required capability boundaries.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from vulntrace.core.backend import BackendCapabilities, IsolationTier


class ExecutionOperation(str, Enum):
    """Lifecycle verification operations governed by security policy."""
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DEPENDENCY_PROVISIONING = "DEPENDENCY_PROVISIONING"
    EXPLOIT_REPRODUCTION = "EXPLOIT_REPRODUCTION"
    REMEDIATION_VERIFICATION = "REMEDIATION_VERIFICATION"
    REGRESSION_VERIFICATION = "REGRESSION_VERIFICATION"
    HIGH_ASSURANCE_FINAL_VERDICT = "HIGH_ASSURANCE_FINAL_VERDICT"


class AssuranceLevel(str, Enum):
    """
    Concrete capability-derived assurance classifications.
    Never uses vague or unproven labels like 'secure' or 'production-grade'.
    """
    HIGH_ASSURANCE_CONTAINED = "HIGH_ASSURANCE_CONTAINED"
    DEGRADED_LOCAL_FALLBACK = "DEGRADED_LOCAL_FALLBACK"
    INSUFFICIENT_ISOLATION = "INSUFFICIENT_ISOLATION"


class PolicyDecision(BaseModel):
    """
    Audit record generated when evaluating an operation against backend capabilities.
    """
    allowed: bool
    operation: ExecutionOperation
    assurance_level: AssuranceLevel
    backend_tier: IsolationTier
    missing_capabilities: List[str] = Field(default_factory=list)
    policy_violations: List[str] = Field(default_factory=list)
    boundary_caveats: List[str] = Field(default_factory=list)
    rationale: str


class SecurityPolicyEngine:
    """
    Evaluates and enforces security policies based on backend capabilities.
    """

    REQUIRED_CONTAINED_CAPS = [
        "filesystem_jailed",
        "host_fs_hidden",
        "network_kernel_denied",
        "process_tree_contained",
        "resource_limits_enforced",
        "host_identity_isolated"
    ]

    REQUIRED_SUBPROCESS_CAPS = [
        "process_tree_contained",
        "resource_limits_enforced"
    ]

    @classmethod
    def evaluate_backend_assurance(cls, capabilities: BackendCapabilities) -> AssuranceLevel:
        """
        Derives concrete assurance level strictly from verified capability flags.
        """
        # 1. Check for OCI Container / MicroVM / WSL2 Jailed isolation
        if capabilities.tier in [IsolationTier.OCI_CONTAINER_ISOLATED, IsolationTier.REMOTE_MICROVM_ISOLATED, IsolationTier.WSL2_JAILED_CONTAINMENT]:
            missing = [
                cap for cap in cls.REQUIRED_CONTAINED_CAPS
                if not getattr(capabilities, cap, False)
            ]
            if not missing:
                return AssuranceLevel.HIGH_ASSURANCE_CONTAINED
            return AssuranceLevel.INSUFFICIENT_ISOLATION

        # 2. Check for Local Subprocess Fallback
        if capabilities.tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK:
            missing = [
                cap for cap in cls.REQUIRED_SUBPROCESS_CAPS
                if not getattr(capabilities, cap, False)
            ]
            if not missing:
                return AssuranceLevel.DEGRADED_LOCAL_FALLBACK
            return AssuranceLevel.INSUFFICIENT_ISOLATION

        return AssuranceLevel.INSUFFICIENT_ISOLATION

    @classmethod
    def enforce_operation_policy(
        cls,
        operation: ExecutionOperation,
        capabilities: BackendCapabilities,
        require_high_assurance: bool = False
    ) -> PolicyDecision:
        """
        Enforces minimum capability policies for a specific lifecycle operation.
        """
        assurance = cls.evaluate_backend_assurance(capabilities)
        missing_caps: List[str] = []
        violations: List[str] = []

        # High-assurance requirement policy gate
        if require_high_assurance:
            if assurance != AssuranceLevel.HIGH_ASSURANCE_CONTAINED:
                missing = [
                    cap for cap in cls.REQUIRED_CONTAINED_CAPS
                    if not getattr(capabilities, cap, False)
                ]
                return PolicyDecision(
                    allowed=False,
                    operation=operation,
                    assurance_level=assurance,
                    backend_tier=capabilities.tier,
                    missing_capabilities=missing,
                    policy_violations=[
                        f"Operation '{operation.value}' requires HIGH_ASSURANCE_CONTAINED; "
                        f"backend tier '{capabilities.tier.value}' is classified as {assurance.value}."
                    ],
                    boundary_caveats=capabilities.boundary_caveats,
                    rationale=f"High-assurance gate failed: missing required isolation capabilities: {', '.join(missing) if missing else 'None'}."
                )

        # Operation-specific policy rules
        if operation == ExecutionOperation.STATIC_ANALYSIS:
            # AST parsing runs in-process on host code copy; always permitted
            return PolicyDecision(
                allowed=True,
                operation=operation,
                assurance_level=assurance,
                backend_tier=capabilities.tier,
                boundary_caveats=[],
                rationale="Static analysis is read-only and AST-contained."
            )

        if operation == ExecutionOperation.HIGH_ASSURANCE_FINAL_VERDICT:
            # Final high-assurance verdict requires contained isolation
            if assurance == AssuranceLevel.HIGH_ASSURANCE_CONTAINED:
                return PolicyDecision(
                    allowed=True,
                    operation=operation,
                    assurance_level=assurance,
                    backend_tier=capabilities.tier,
                    boundary_caveats=capabilities.boundary_caveats,
                    rationale="High-assurance verdict validated by full kernel/container containment."
                )
            else:
                if require_high_assurance:
                    return PolicyDecision(
                        allowed=False,
                        operation=operation,
                        assurance_level=assurance,
                        backend_tier=capabilities.tier,
                        missing_capabilities=[cap for cap in cls.REQUIRED_CONTAINED_CAPS if not getattr(capabilities, cap, False)],
                        policy_violations=[
                            f"Cannot issue HIGH_ASSURANCE_FINAL_VERDICT on {capabilities.tier.value}. "
                            "Substrate is operating in DEGRADED_LOCAL_FALLBACK mode."
                        ],
                        boundary_caveats=capabilities.boundary_caveats,
                        rationale="Weak backend cannot claim high-assurance verdict."
                    )
                return PolicyDecision(
                    allowed=True,
                    operation=operation,
                    assurance_level=assurance,
                    backend_tier=capabilities.tier,
                    missing_capabilities=[cap for cap in cls.REQUIRED_CONTAINED_CAPS if not getattr(capabilities, cap, False)],
                    policy_violations=[],
                    boundary_caveats=capabilities.boundary_caveats,
                    rationale=f"Verdict permitted under degraded fallback policy ({assurance.value})."
                )

        # Standard lifecycle operations (PROVISIONING, REPRODUCTION, VERIFICATION, REGRESSION)
        if assurance == AssuranceLevel.INSUFFICIENT_ISOLATION:
            return PolicyDecision(
                allowed=False,
                operation=operation,
                assurance_level=assurance,
                backend_tier=capabilities.tier,
                missing_capabilities=[cap for cap in cls.REQUIRED_SUBPROCESS_CAPS if not getattr(capabilities, cap, False)],
                policy_violations=["Backend lacks minimal process tree containment and memory caps."],
                boundary_caveats=capabilities.boundary_caveats,
                rationale="Execution blocked due to insufficient isolation capabilities."
            )

        return PolicyDecision(
            allowed=True,
            operation=operation,
            assurance_level=assurance,
            backend_tier=capabilities.tier,
            boundary_caveats=capabilities.boundary_caveats,
            rationale=f"Operation permitted under {assurance.value} policy."
        )

    @classmethod
    def audit_verdict_assurance(
        cls,
        capabilities: BackendCapabilities,
        terminal_state: str
    ) -> Dict[str, Any]:
        """
        Computes formal assurance metadata to attach to FinalVerdictRecord.
        """
        assurance = cls.evaluate_backend_assurance(capabilities)
        is_hardened = (assurance == AssuranceLevel.HIGH_ASSURANCE_CONTAINED)

        return {
            "assurance_level": assurance.value,
            "is_hardened_container": is_hardened,
            "policy_status": "ENFORCED_PASS" if is_hardened else "DEGRADED_FALLBACK_ACTIVE",
            "required_capabilities_met": is_hardened,
            "backend_tier": capabilities.tier.value,
            "assurance_caveats": capabilities.boundary_caveats
        }
