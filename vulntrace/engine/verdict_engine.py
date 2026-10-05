"""
VulnTrace Formal Verdict Engine
Derives final behavioral verdicts strictly from independent, observable evidence layers:
RepositoryEvidence, AdvisoryEvidence, ReachabilityEvidence, BehaviorEvidence,
PatchEvidence, RegressionEvidence, and ExecutionEvidence.
"""

import time
from vulntrace.models import (
    RepositoryEvidence,
    AdvisoryEvidence,
    ReachabilityEvidence,
    BehaviorEvidence,
    PatchEvidence,
    RegressionEvidence,
    ExecutionEvidence,
    FinalVerdictRecord
)

class VerdictEngine:
    """Formal, centralized resolver deriving terminal verdicts from evidence objects."""

    @classmethod
    def evaluate(
        cls,
        cve_id: str,
        repo_path: str,
        repo_ev: RepositoryEvidence,
        advisory_ev: AdvisoryEvidence,
        reach_ev: ReachabilityEvidence,
        behavior_ev: BehaviorEvidence,
        patch_ev: PatchEvidence,
        regression_ev: RegressionEvidence,
        exec_ev: ExecutionEvidence
    ) -> FinalVerdictRecord:
        """
        Computes formal FinalVerdictRecord.
        Evidence derives the verdict; verdict NEVER derives or overrides evidence.
        """
        # 1. Unreachable False Positive / Dead Code check
        if reach_ev.verdict == "UNREACHABLE_FALSE_POSITIVE" or reach_ev.reachable_vulnerabilities_count == 0:
            terminal_state = "UNREACHABLE_FALSE_POSITIVE"
            reason = "Zero incoming execution edges from analyzed entrypoints; false positive suppressed."

        # 2. Parent-Side Verification Trust Boundary Check
        elif behavior_ev.pre_patch_state == "VERIFICATION_REJECTED" or behavior_ev.post_patch_state == "VERIFICATION_REJECTED":
            terminal_state = "VERIFICATION_REJECTED"
            reason = f"Parent trust boundary rejected child assertion: {behavior_ev.validation_notes}"

        # 3. Pre-Patch Inconclusive Check
        elif behavior_ev.pre_patch_state == "INCONCLUSIVE":
            terminal_state = "INCONCLUSIVE"
            reason = "Pre-patch verification was inconclusive; defensive guard or environment prevented reproducing red state."

        # 4. Pre-Patch Crash / Abort Check
        elif behavior_ev.pre_patch_state != "RED_STATE_REPRODUCED":
            terminal_state = "UNEXPECTED_FAILURE"
            reason = f"Pre-patch execution failed with unexpected state: {behavior_ev.pre_patch_state}"

        # 5. Patch Acceptance & Validation Check
        elif not patch_ev.success or patch_ev.validation_status in [
            "REJECTED_SYNTAX_ERROR",
            "REJECTED_EMPTY",
            "REJECTED_API_ERROR",
            "REJECTED",
            "REJECTED_DENYLIST_VIOLATION",
            "REJECTED_EXCEPTION",
        ]:
            terminal_state = "PATCH_REJECTED"
            reason = f"Remediation patch rejected ({patch_ev.validation_status}): {patch_ev.target_file}"

        # 6. Post-Patch Behavior Check: Persistence
        elif behavior_ev.post_patch_state == "RED_STATE_PERSISTS":
            terminal_state = "RED_STATE_PERSISTS"
            reason = "Post-patch re-test still reproduced vulnerable behavior; remediation was ineffective."

        # 7. Post-Patch Behavior Check: Security Block failure
        elif behavior_ev.post_patch_state != "GREEN_STATE_BLOCKED":
            terminal_state = "UNEXPECTED_FAILURE"
            reason = f"Post-patch execution failed with unexpected state: {behavior_ev.post_patch_state}"

        # 8. Regression Suite Failure Check
        elif regression_ev.executed and not regression_ev.passed:
            terminal_state = "REGRESSION_FAILURE"
            reason = f"Remediation introduced test regressions ({regression_ev.error or 'pytest failed'})."

        # 9. Complete Verified Green State
        elif (
            behavior_ev.pre_patch_state == "RED_STATE_REPRODUCED"
            and patch_ev.success
            and behavior_ev.post_patch_state == "GREEN_STATE_BLOCKED"
            and regression_ev.passed
            and behavior_ev.parent_validated
        ):
            terminal_state = "GREEN_STATE_VERIFIED"
            reason = "Reachable vulnerability reproduced in red state, remediated with valid diff, verified in green state, and passed regression test suite."

        else:
            terminal_state = "UNEXPECTED_FAILURE"
            reason = "Pipeline completed without meeting explicit evidence criteria for terminal state."

        evidence_summary = {
            "cve_id": cve_id,
            "repo": repo_path,
            "reachability_verdict": reach_ev.verdict,
            "pre_patch_exit_code": behavior_ev.pre_patch_exit_code,
            "pre_patch_state": behavior_ev.pre_patch_state,
            "post_patch_exit_code": behavior_ev.post_patch_exit_code,
            "post_patch_state": behavior_ev.post_patch_state,
            "parent_validated": behavior_ev.parent_validated,
            "remediation_engine": patch_ev.engine,
            "patch_validation_status": patch_ev.validation_status,
            "regression_passed": regression_ev.passed,
            "regression_test_count": regression_ev.test_count,
            "sandbox_engine": exec_ev.sandbox_engine,
            "isolation_tier": getattr(exec_ev, "isolation_tier", exec_ev.sandbox_engine),
            "cloud_status": exec_ev.cloud_status
        }

        # Derive Assurance Level and Policy Audit (P0.7)
        from vulntrace.core.policy import SecurityPolicyEngine
        from vulntrace.core.backend import BackendCapabilities

        capabilities = None
        if getattr(exec_ev, "capabilities", None):
            if isinstance(exec_ev.capabilities, dict):
                try:
                    capabilities = BackendCapabilities.model_validate(exec_ev.capabilities)
                except Exception:
                    pass
            elif isinstance(exec_ev.capabilities, BackendCapabilities):
                capabilities = exec_ev.capabilities

        if capabilities is None:
            tier_str = getattr(exec_ev, "isolation_tier", exec_ev.sandbox_engine) or "LOCAL_SUBPROCESS_FALLBACK"
            if "CONTAINER" in tier_str.upper() or "OCI" in tier_str.upper():
                from vulntrace.core.container_backend import ContainerExecutionBackend
                capabilities = ContainerExecutionBackend().capabilities
            else:
                from vulntrace.core.local_backend import LocalSubprocessBackend
                capabilities = LocalSubprocessBackend().capabilities

        policy_audit = SecurityPolicyEngine.audit_verdict_assurance(capabilities, terminal_state)
        assurance_level = policy_audit["assurance_level"]

        evidence_summary["assurance_level"] = assurance_level
        evidence_summary["is_hardened_container"] = policy_audit["is_hardened_container"]
        evidence_summary["policy_status"] = policy_audit["policy_status"]

        return FinalVerdictRecord(
            terminal_state=terminal_state,
            cve_id=cve_id,
            repo_path=repo_path,
            reason=reason,
            timestamp=time.time(),
            evidence_summary=evidence_summary,
            is_safe_claim=False,
            assurance_level=assurance_level,
            policy_audit=policy_audit
        )
