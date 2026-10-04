"""
VulnTrace Security Capability Policy Tests (P0.7)
Verifies:
1. Capability-derived AssuranceLevel classification (HIGH_ASSURANCE_CONTAINED vs DEGRADED_LOCAL_FALLBACK vs INSUFFICIENT_ISOLATION).
2. Anti-spoofing capability checks (missing containment capabilities demote to INSUFFICIENT_ISOLATION).
3. Enforcement gates across all verification operations.
4. Policy integration in VerdictEngine and VerificationPipeline.
"""

import pytest

from vulntrace.core.backend import (
    IsolationTier,
    BackendCapabilities
)
from vulntrace.core.policy import (
    ExecutionOperation,
    AssuranceLevel,
    SecurityPolicyEngine
)
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.container_backend import ContainerExecutionBackend
from vulntrace.models import (
    RepositoryEvidence,
    AdvisoryEvidence,
    ReachabilityEvidence,
    BehaviorEvidence,
    PatchEvidence,
    RegressionEvidence,
    ExecutionEvidence,
    VerificationPipelineRequest
)
from vulntrace.engine.verdict_engine import VerdictEngine
from vulntrace.sandbox.pipeline import VerificationPipeline


class TestSecurityCapabilityPolicy:
    """Verifies the core SecurityPolicyEngine classification and enforcement rules."""

    def test_oci_container_classified_as_high_assurance(self):
        backend = ContainerExecutionBackend()
        assurance = SecurityPolicyEngine.evaluate_backend_assurance(backend.capabilities)
        assert assurance == AssuranceLevel.HIGH_ASSURANCE_CONTAINED

    def test_local_subprocess_classified_as_degraded_fallback(self):
        backend = LocalSubprocessBackend()
        assurance = SecurityPolicyEngine.evaluate_backend_assurance(backend.capabilities)
        assert assurance == AssuranceLevel.DEGRADED_LOCAL_FALLBACK

    def test_capabilities_tampering_demotes_to_insufficient_isolation(self):
        # Even if tier claims OCI_CONTAINER_ISOLATED, if host_fs_hidden is False, demoted!
        tampered_caps = BackendCapabilities(
            tier=IsolationTier.OCI_CONTAINER_ISOLATED,
            filesystem_jailed=True,
            host_fs_hidden=False,  # TAMPERED
            network_kernel_denied=True,
            process_tree_contained=True,
            resource_limits_enforced=True,
            host_identity_isolated=True,
            hardware_virtualized=False,
            description="Tampered container capabilities"
        )
        assurance = SecurityPolicyEngine.evaluate_backend_assurance(tampered_caps)
        assert assurance == AssuranceLevel.INSUFFICIENT_ISOLATION

        # If network_kernel_denied is False, demoted!
        tampered_caps2 = BackendCapabilities(
            tier=IsolationTier.OCI_CONTAINER_ISOLATED,
            filesystem_jailed=True,
            host_fs_hidden=True,
            network_kernel_denied=False,  # TAMPERED
            process_tree_contained=True,
            resource_limits_enforced=True,
            host_identity_isolated=True,
            hardware_virtualized=False,
            description="Tampered container capabilities"
        )
        assert SecurityPolicyEngine.evaluate_backend_assurance(tampered_caps2) == AssuranceLevel.INSUFFICIENT_ISOLATION

    def test_subprocess_tampering_demotes_to_insufficient_isolation(self):
        # If local fallback lacks process tree containment, demoted to INSUFFICIENT
        tampered_local = BackendCapabilities(
            tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            filesystem_jailed=False,
            host_fs_hidden=False,
            network_kernel_denied=False,
            process_tree_contained=False,  # TAMPERED
            resource_limits_enforced=True,
            host_identity_isolated=False,
            hardware_virtualized=False,
            description="Tampered local capabilities"
        )
        assurance = SecurityPolicyEngine.evaluate_backend_assurance(tampered_local)
        assert assurance == AssuranceLevel.INSUFFICIENT_ISOLATION

    def test_static_analysis_always_allowed(self):
        backend = LocalSubprocessBackend()
        decision = SecurityPolicyEngine.enforce_operation_policy(
            ExecutionOperation.STATIC_ANALYSIS,
            backend.capabilities
        )
        assert decision.allowed is True
        assert decision.operation == ExecutionOperation.STATIC_ANALYSIS

    def test_high_assurance_gate_blocks_local_fallback(self):
        backend = LocalSubprocessBackend()
        decision = SecurityPolicyEngine.enforce_operation_policy(
            ExecutionOperation.HIGH_ASSURANCE_FINAL_VERDICT,
            backend.capabilities,
            require_high_assurance=True
        )
        assert decision.allowed is False
        assert decision.assurance_level == AssuranceLevel.DEGRADED_LOCAL_FALLBACK
        assert len(decision.missing_capabilities) > 0
        assert "filesystem_jailed" in decision.missing_capabilities
        assert "host_fs_hidden" in decision.missing_capabilities
        assert "network_kernel_denied" in decision.missing_capabilities
        assert len(decision.policy_violations) == 1

    def test_degraded_fallback_permitted_when_high_assurance_not_required(self):
        backend = LocalSubprocessBackend()
        decision = SecurityPolicyEngine.enforce_operation_policy(
            ExecutionOperation.HIGH_ASSURANCE_FINAL_VERDICT,
            backend.capabilities,
            require_high_assurance=False
        )
        assert decision.allowed is True
        assert decision.assurance_level == AssuranceLevel.DEGRADED_LOCAL_FALLBACK
        assert len(decision.policy_violations) == 0

    def test_insufficient_isolation_blocks_all_execution_ops(self):
        bad_caps = BackendCapabilities(
            tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            filesystem_jailed=False,
            host_fs_hidden=False,
            network_kernel_denied=False,
            process_tree_contained=False,  # INSUFFICIENT
            resource_limits_enforced=False,
            host_identity_isolated=False,
            hardware_virtualized=False,
            description="Insufficient isolation backend"
        )
        ops_to_test = [
            ExecutionOperation.DEPENDENCY_PROVISIONING,
            ExecutionOperation.EXPLOIT_REPRODUCTION,
            ExecutionOperation.REMEDIATION_VERIFICATION,
            ExecutionOperation.REGRESSION_VERIFICATION
        ]
        for op in ops_to_test:
            decision = SecurityPolicyEngine.enforce_operation_policy(op, bad_caps)
            assert decision.allowed is False
            assert decision.assurance_level == AssuranceLevel.INSUFFICIENT_ISOLATION


class TestVerdictEnginePolicyIntegration:
    """Verifies that VerdictEngine records concrete assurance level and caveats."""

    def test_verdict_engine_derives_degraded_fallback_assurance(self):
        local_backend = LocalSubprocessBackend()
        exec_ev = ExecutionEvidence(
            sandbox_engine="LOCAL_SUBPROCESS_FALLBACK",
            cloud_status="PERMISSION_DENIED (HTTP 403)",
            isolation_tier="LOCAL_SUBPROCESS_FALLBACK",
            capabilities=local_backend.capabilities.model_dump(),
            parent_audit_passed=True
        )
        verdict = VerdictEngine.evaluate(
            cve_id="CVE-2020-14343",
            repo_path="test_scenarios/cve_2020_14343_pyyaml",
            repo_ev=RepositoryEvidence(repo_path="test"),
            advisory_ev=AdvisoryEvidence(cve_id="CVE-2020-14343", found=True, summary="test", source_url="test"),
            reach_ev=ReachabilityEvidence(
                target_symbol="yaml.load",
                discovered_call_sites_count=1,
                reachable_vulnerabilities_count=1,
                unreachable_dead_code_count=0,
                verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
            ),
            behavior_ev=BehaviorEvidence(
                pre_patch_exit_code=0,
                pre_patch_sentinel_observed=True,
                pre_patch_state="RED_STATE_REPRODUCED",
                post_patch_exit_code=42,
                post_patch_sentinel_observed=False,
                post_patch_state="GREEN_STATE_BLOCKED",
                parent_validated=True
            ),
            patch_ev=PatchEvidence(
                engine="NVIDIA_NEMOTRON_3_ULTRA",
                target_file="vuln_app.py",
                diff="diff",
                validation_status="ACCEPTED",
                latency_ms=10.0,
                success=True
            ),
            regression_ev=RegressionEvidence(executed=True, passed=True, test_count=3, latency_ms=10.0),
            exec_ev=exec_ev
        )

        assert verdict.terminal_state == "GREEN_STATE_VERIFIED"
        assert verdict.assurance_level == "DEGRADED_LOCAL_FALLBACK"
        assert verdict.policy_audit["is_hardened_container"] is False
        assert verdict.policy_audit["policy_status"] == "DEGRADED_FALLBACK_ACTIVE"
        assert verdict.evidence_summary["assurance_level"] == "DEGRADED_LOCAL_FALLBACK"

    def test_verdict_engine_derives_high_assurance_contained(self):
        container_backend = ContainerExecutionBackend()
        exec_ev = ExecutionEvidence(
            sandbox_engine="OCI_CONTAINER_ISOLATED",
            cloud_status="PERMISSION_DENIED (HTTP 403)",
            isolation_tier="OCI_CONTAINER_ISOLATED",
            capabilities=container_backend.capabilities.model_dump(),
            parent_audit_passed=True
        )
        verdict = VerdictEngine.evaluate(
            cve_id="CVE-2020-14343",
            repo_path="test_scenarios/cve_2020_14343_pyyaml",
            repo_ev=RepositoryEvidence(repo_path="test"),
            advisory_ev=AdvisoryEvidence(cve_id="CVE-2020-14343", found=True, summary="test", source_url="test"),
            reach_ev=ReachabilityEvidence(
                target_symbol="yaml.load",
                discovered_call_sites_count=1,
                reachable_vulnerabilities_count=1,
                unreachable_dead_code_count=0,
                verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
            ),
            behavior_ev=BehaviorEvidence(
                pre_patch_exit_code=0,
                pre_patch_sentinel_observed=True,
                pre_patch_state="RED_STATE_REPRODUCED",
                post_patch_exit_code=42,
                post_patch_sentinel_observed=False,
                post_patch_state="GREEN_STATE_BLOCKED",
                parent_validated=True
            ),
            patch_ev=PatchEvidence(
                engine="NVIDIA_NEMOTRON_3_ULTRA",
                target_file="vuln_app.py",
                diff="diff",
                validation_status="ACCEPTED",
                latency_ms=10.0,
                success=True
            ),
            regression_ev=RegressionEvidence(executed=True, passed=True, test_count=3, latency_ms=10.0),
            exec_ev=exec_ev
        )

        assert verdict.terminal_state == "GREEN_STATE_VERIFIED"
        assert verdict.assurance_level == "HIGH_ASSURANCE_CONTAINED"
        assert verdict.policy_audit["is_hardened_container"] is True
        assert verdict.policy_audit["policy_status"] == "ENFORCED_PASS"
        assert verdict.evidence_summary["assurance_level"] == "HIGH_ASSURANCE_CONTAINED"


class TestPipelinePolicyGating:
    """Verifies that VerificationPipeline actively enforces policy gates."""

    @pytest.mark.asyncio
    async def test_pipeline_rejects_local_backend_when_high_assurance_requested(self):
        local_backend = LocalSubprocessBackend()
        req = VerificationPipelineRequest(
            repo_path="test_scenarios/cve_2020_14343_pyyaml",
            cve_id="CVE-2020-14343",
            target_file="vuln_app.py",
            target_function="load_config",
            vulnerable_symbol="yaml.load",
            use_nemotron=False,
            query_tavily=False,
            require_high_assurance=True  # Strictly requires HIGH_ASSURANCE_CONTAINED!
        )

        with pytest.raises(PermissionError) as exc_info:
            await VerificationPipeline.run_pipeline(req=req, backend=local_backend)

        assert "Execution policy violation" in str(exc_info.value)
        assert "DEGRADED_LOCAL_FALLBACK" in str(exc_info.value)
