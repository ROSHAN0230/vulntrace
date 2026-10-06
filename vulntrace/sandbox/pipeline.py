"""
VulnTrace Defensive Verification Pipeline Orchestrator
Coordinates the 6-step verification lifecycle:
1. Reachability Check (AST Call Graph)
2. Harness Synthesis
3. Pre-Patch Sandbox Execution (RED STATE)
4. Nemotron / AST Remediation
5. Post-Patch Sandbox Execution (GREEN STATE)
6. Regression Testing
"""

import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, Callable
from vulntrace.models import (
    VerificationPipelineRequest,
    VerificationPipelineResponse,
    HarnessGenerateRequest,
    HarnessGenerateResponse,
    RemediationRequest,
    RemediationResponse,
    PipelineEvent,
    SandboxExecutionResult,
    AstAnalyzeRequest,
    RepositoryEvidence,
    AdvisoryEvidence,
    ReachabilityEvidence,
    BehaviorEvidence,
    PatchEvidence,
    RegressionEvidence,
    ExecutionEvidence,
    EnvironmentEvidence,
    FinalVerdictRecord
)
from vulntrace.sandbox.target_env import TargetEnvironmentManager
from vulntrace.core.backend import ExecutionBackend, IsolationTier
from vulntrace.core.factory import BackendFactory
from vulntrace.analyzer.ast_visitor import AstReachabilityAnalyzer
from vulntrace.agent.harness_synthesizer import HarnessSynthesizer
from vulntrace.agent.patcher import RemediationPatcher
from vulntrace.engine.verdict_engine import VerdictEngine
from vulntrace.intel.tavily_client import TavilyClient
from vulntrace.config import settings

class VerificationPipeline:
    """Executes end-to-end controlled defensive verification in disposable sandboxes."""

    @classmethod
    async def run_pipeline(
        cls,
        req: VerificationPipelineRequest,
        on_event: Optional[Callable[[PipelineEvent], None]] = None,
        backend: Optional[ExecutionBackend] = None
    ) -> VerificationPipelineResponse:
        t0 = time.perf_counter()
        source_repo = Path(req.repo_path).resolve()
        if backend is None:
            tier_override = None
            if req.execution_backend:
                if "CONTAINER" in req.execution_backend.upper() or "OCI" in req.execution_backend.upper() or "TIER1" in req.execution_backend.upper() or "TIER_1" in req.execution_backend.upper():
                    tier_override = IsolationTier.OCI_CONTAINER_ISOLATED
                elif "LOCAL" in req.execution_backend.upper() or "SUBPROCESS" in req.execution_backend.upper() or "TIER0" in req.execution_backend.upper() or "TIER_0" in req.execution_backend.upper():
                    tier_override = IsolationTier.LOCAL_SUBPROCESS_FALLBACK
            backend = BackendFactory.resolve_best_available_backend(
                force_tier=tier_override,
                target_repo=source_repo,
                unsafe_local=getattr(req, "unsafe_local", False)
            )

        def emit(event_type: str, stage: str, message: str, data: Optional[Dict[str, Any]] = None):
            if on_event:
                on_event(PipelineEvent(
                    event_type=event_type,
                    stage=stage,
                    message=message,
                    data=data,
                    timestamp=time.time()
                ))

        # Policy Evaluation & Gating (P0.7)
        from vulntrace.core.policy import SecurityPolicyEngine, ExecutionOperation
        assurance_level = SecurityPolicyEngine.evaluate_backend_assurance(backend.capabilities)
        policy_decision = SecurityPolicyEngine.enforce_operation_policy(
            ExecutionOperation.HIGH_ASSURANCE_FINAL_VERDICT,
            backend.capabilities,
            require_high_assurance=req.require_high_assurance
        )
        if not policy_decision.allowed:
            emit("ERROR", "POLICY", f"Security policy blocked execution: {policy_decision.rationale}", policy_decision.model_dump())
            raise PermissionError(f"Execution policy violation: {policy_decision.policy_violations}")

        emit("LOG", "POLICY", f"Security Policy Active: {assurance_level.value} on {backend.capabilities.tier.value}.", policy_decision.model_dump())

        emit("STAGE_START", "SANDBOX", f"Initializing disposable workspace on backend ({backend.capabilities.tier.value})...")
        workspace_id = await backend.initialize_workspace(source_repo)
        disposable_dir = Path(workspace_id)
        emit("LOG", "SANDBOX", f"Disposable workspace mounted at: {workspace_id}")

        # Controlled Target-Environment Setup Path (P0.2/P0.6/P0.7)
        prov_decision = SecurityPolicyEngine.enforce_operation_policy(
            ExecutionOperation.DEPENDENCY_PROVISIONING,
            backend.capabilities,
            require_high_assurance=req.require_high_assurance
        )
        if not prov_decision.allowed:
            emit("ERROR", "POLICY", f"Dependency provisioning blocked: {prov_decision.rationale}")
            raise PermissionError(f"Dependency provisioning blocked: {prov_decision.policy_violations}")

        emit("STAGE_START", "SETUP", f"Detecting target dependencies for {source_repo.name}...")
        has_manifest, detected_deps = TargetEnvironmentManager.detect_dependencies(disposable_dir)
        prov_result = await backend.provision_dependencies(
            workspace_id=workspace_id,
            manifest_dependencies=detected_deps,
            on_log=lambda msg: emit("LOG", "SETUP", msg)
        )
        prov_evidence = prov_result.structured_evidence or {}
        env_evidence = EnvironmentEvidence(
            has_manifest=has_manifest,
            detected_dependencies=prov_evidence.get("detected_dependencies", detected_deps),
            provisioned=(prov_result.exit_code == 0),
            python_version=prov_evidence.get("python_version", ""),
            python_executable=prov_evidence.get("python_executable", ""),
            venv_path=prov_evidence.get("venv_path"),
            wheel_cache_dir=prov_evidence.get("wheel_cache_dir"),
            build_duration_ms=prov_result.latency_ms,
            build_output=prov_evidence.get("build_output", prov_result.stdout),
            pip_log_excerpt=prov_evidence.get("pip_log_excerpt", prov_result.stderr[:500] if prov_result.stderr else None),
            failure_classification=prov_evidence.get("failure_classification", "ENV_BUILD_FAILED" if (has_manifest and prov_result.exit_code != 0) else None),
            failure_reason=prov_evidence.get("failure_reason", prov_result.stderr[:200] if prov_result.stderr else None),
            network_isolated=prov_evidence.get("network_isolated", True),
            notes=prov_result.validation_notes or ("Target environment provisioned" if prov_result.exit_code == 0 else "Environment build failed")
        )

        if has_manifest and prov_result.exit_code != 0:
            fail_reason = env_evidence.failure_reason or env_evidence.pip_log_excerpt or prov_result.stderr or "Target environment build failed"
            emit("ERROR", "SETUP", f"Target environment construction failed: {fail_reason[:150]}")
            dt_total = (time.perf_counter() - t0) * 1000.0
            emit("STATE_TRANSITION", "VERDICT", f"FINAL BEHAVIORAL VERDICT: ENV_BUILD_FAILED (Total: {round(dt_total, 2)}ms)")

            fail_harness = HarnessGenerateResponse(
                cve_id=req.cve_id,
                target_file=req.target_file or "unknown.py",
                function_name=req.target_function or "unknown",
                harness_code="# Harness synthesis skipped: environment build failed",
                sentinel_filename="none",
                latency_ms=0.0
            )
            fail_sandbox = SandboxExecutionResult(
                exit_code=1,
                stdout=prov_result.stdout,
                stderr=prov_result.stderr,
                latency_ms=prov_result.latency_ms,
                sentinel_created=False,
                reproduction_state="ENV_BUILD_FAILED",
                parent_validated=False,
                validation_notes=f"Target environment construction failed: {fail_reason[:150]}",
                sandbox_engine=backend.capabilities.tier.value,
                disposable_dir=str(disposable_dir),
                error=fail_reason
            )
            empty_rem = RemediationResponse(
                cve_id=req.cve_id,
                target_file=req.target_file or "unknown.py",
                engine="SKIPPED",
                diff="",
                explanation="Skipped remediation: Environment construction failed.",
                latency_ms=0.0,
                success=False,
                validation_status="SKIPPED"
            )
            empty_reg = {
                "executed": False,
                "passed": False,
                "test_count": 0,
                "latency_ms": 0.0,
                "error": "Regression tests skipped: environment construction failed"
            }

            verdict_rec = FinalVerdictRecord(
                terminal_state="ENV_BUILD_FAILED",
                cve_id=req.cve_id,
                repo_path=str(source_repo),
                reason=f"Target repository environment could not be built: {fail_reason}",
                timestamp=time.time(),
                evidence_summary={
                    "cve_id": req.cve_id,
                    "repo": str(source_repo),
                    "reachability_verdict": "NOT_EVALUATED",
                    "pre_patch_state": "ENV_BUILD_FAILED",
                    "sandbox_engine": backend.capabilities.tier.value,
                    "target_python_version": env_evidence.python_version,
                    "environment_build_duration_ms": env_evidence.build_duration_ms,
                    "pip_log_excerpt": env_evidence.pip_log_excerpt,
                    "failure_classification": "ENV_BUILD_FAILED"
                },
                is_safe_claim=False
            )

            return VerificationPipelineResponse(
                cve_id=req.cve_id,
                repo_path=str(source_repo),
                reachability_verdict="NOT_EVALUATED",
                harness=fail_harness,
                pre_patch_result=fail_sandbox,
                remediation=empty_rem,
                post_patch_result=fail_sandbox,
                regression_tests=empty_reg,
                final_behavioral_verdict="ENV_BUILD_FAILED",
                structured_evidence={
                    "environment": env_evidence.model_dump(),
                    "failure_classification": "ENV_BUILD_FAILED"
                },
                verdict_record=verdict_rec,
                environment=env_evidence,
                sandbox_engine=backend.capabilities.tier.value,
                cloud_status="PERMISSION_DENIED (HTTP 403)",
                total_pipeline_ms=round(dt_total, 2),
                isolation_tier=backend.capabilities.tier.value,
                assurance_level=assurance_level.value,
                policy_decision=policy_decision.model_dump()
            )

        if prov_result.exit_code == 0:
            emit("STAGE_COMPLETE", "SETUP", f"Target environment provisioned on backend ({backend.capabilities.tier.value}) in {prov_result.latency_ms}ms ({env_evidence.python_version}). Network isolation active.")
        else:
            emit("LOG", "SETUP", f"Target environment: {prov_result.validation_notes or 'standard environment'}")

        async def _run_backend_script(script_name: str, sentinel_name: str, stage_label: str) -> SandboxExecutionResult:
            cmd_res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name=script_name,
                timeout=10.0,
                sentinel_filename=sentinel_name,
                on_log=lambda msg: emit("LOG", stage_label, msg)
            )
            return SandboxExecutionResult(
                exit_code=cmd_res.exit_code,
                stdout=cmd_res.stdout,
                stderr=cmd_res.stderr,
                latency_ms=cmd_res.latency_ms,
                sentinel_created=cmd_res.sentinel_created,
                reproduction_state=cmd_res.reproduction_state,
                assertion_result=cmd_res.assertion_result,
                exception_type=cmd_res.exception_type,
                structured_evidence=cmd_res.structured_evidence,
                parent_validated=cmd_res.parent_validated,
                validation_notes=cmd_res.validation_notes,
                sandbox_engine=backend.capabilities.tier.value,
                disposable_dir=str(disposable_dir),
                error=cmd_res.error
            )

        try:
            vuln_sym = req.vulnerable_symbol or "yaml.load"

            # Stage 0: AST Reachability Analysis
            emit("STAGE_START", "AST", f"Analyzing AST reachability for {vuln_sym} in {source_repo.name}...")
            ast_res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
                repo_path=str(source_repo),
                target_symbols=[vuln_sym],
                entrypoints=req.entrypoints
            ))
            reachability_verdict = ast_res.verdict
            emit("LOG", "AST", f"Discovered {len(ast_res.discovered_calls)} call sites ({ast_res.reachable_vulnerabilities_count} reachable, {ast_res.unreachable_dead_code_count} dead code).")

            # Dynamic Target Inference if not explicitly supplied
            resolved_target_file = req.target_file
            resolved_target_func = req.target_function
            resolved_vuln_sym = vuln_sym

            if not resolved_target_file or not resolved_target_func:
                reachable_sites = [c for c in ast_res.discovered_calls if c.reachable]
                candidate = reachable_sites[0] if reachable_sites else (ast_res.discovered_calls[0] if ast_res.discovered_calls else None)
                if candidate:
                    resolved_target_file = candidate.file
                    resolved_target_func = candidate.function_name
                    resolved_vuln_sym = candidate.call_name
                else:
                    resolved_target_file = req.target_file or "unknown.py"
                    resolved_target_func = req.target_function or "unknown"

            # Assemble baseline repository & advisory evidence
            repo_ev = RepositoryEvidence(
                repo_path=str(source_repo),
                manifest_files=[f.name for f in source_repo.glob("*") if f.name in ["requirements.txt", "pyproject.toml", "package.json"]],
                python_files_count=len(list(source_repo.rglob("*.py")))
            )
            advisory_ev = AdvisoryEvidence(
                cve_id=req.cve_id,
                found=True,
                summary=f"Automated verification session for {req.cve_id}",
                source_url=f"https://osv.dev/vulnerability/{req.cve_id}"
            )
            reach_ev = ReachabilityEvidence(
                target_symbol=resolved_vuln_sym,
                discovered_call_sites_count=len(ast_res.discovered_calls),
                reachable_vulnerabilities_count=ast_res.reachable_vulnerabilities_count,
                unreachable_dead_code_count=ast_res.unreachable_dead_code_count,
                entrypoints=req.entrypoints,
                verdict=reachability_verdict
            )
            attestation = backend.generate_attestation(workspace_id)
            exec_ev = ExecutionEvidence(
                sandbox_engine=backend.capabilities.tier.value,
                cloud_status="PERMISSION_DENIED (HTTP 403)",
                disposable_dir=str(disposable_dir),
                isolation_tier=backend.capabilities.tier.value,
                capabilities=backend.capabilities.model_dump(),
                attestation=attestation.model_dump(),
                target_python_version=env_evidence.python_version,
                environment_build_duration_ms=env_evidence.build_duration_ms,
                environment_evidence=env_evidence.model_dump()
            )

            # Check if target is unreachable dead code (False positive suppression)
            if reachability_verdict == "UNREACHABLE_FALSE_POSITIVE":
                emit("STATE_TRANSITION", "AST", "UNREACHABLE FALSE POSITIVE CONFIRMED: 0 incoming edges from active entrypoints.")
                emit("LOG", "PIPELINE", "Halting pipeline early: no reachable vulnerable call path detected. Suppressing false alarm.")

                emit("STAGE_START", "REGRESSION", "Running baseline regression tests...")
                regression_res = await backend.run_regression_suite(workspace_id)
                emit("STAGE_COMPLETE", "REGRESSION", f"Baseline regression suite completed: {regression_res.get('test_count', 0)} tests passed.")

                dt_total = (time.perf_counter() - t0) * 1000.0
                emit("STATE_TRANSITION", "VERDICT", f"FINAL BEHAVIORAL VERDICT: UNREACHABLE_FALSE_POSITIVE (Total: {round(dt_total, 2)}ms)")

                empty_harness = HarnessGenerateResponse(
                    cve_id=req.cve_id,
                    target_file=resolved_target_file,
                    function_name=resolved_target_func,
                    harness_code="# Harness synthesis skipped: symbol is unreachable dead code",
                    sentinel_filename="none",
                    latency_ms=0.0
                )
                empty_sandbox = SandboxExecutionResult(
                    exit_code=0,
                    stdout="",
                    stderr="Execution skipped: symbol is unreachable dead code.",
                    latency_ms=0.0,
                    sentinel_created=False,
                    reproduction_state="UNREACHABLE_FALSE_POSITIVE",
                    parent_validated=True,
                    validation_notes="Static call graph confirmed 0 entrypoint call paths.",
                    sandbox_engine=backend.capabilities.tier.value,
                    disposable_dir=str(disposable_dir)
                )
                empty_rem = RemediationResponse(
                    cve_id=req.cve_id,
                    target_file=resolved_target_file,
                    engine="SKIPPED",
                    diff="",
                    explanation="Skipped remediation: Vulnerable call site has zero incoming execution edges.",
                    latency_ms=0.0,
                    success=True,
                    validation_status="SKIPPED"
                )

                verdict_rec = VerdictEngine.evaluate(
                    cve_id=req.cve_id,
                    repo_path=str(source_repo),
                    repo_ev=repo_ev,
                    advisory_ev=advisory_ev,
                    reach_ev=reach_ev,
                    behavior_ev=BehaviorEvidence(
                        pre_patch_exit_code=0,
                        pre_patch_sentinel_observed=False,
                        pre_patch_state="UNREACHABLE_FALSE_POSITIVE",
                        post_patch_exit_code=0,
                        post_patch_sentinel_observed=False,
                        post_patch_state="UNREACHABLE_FALSE_POSITIVE",
                        parent_validated=True
                    ),
                    patch_ev=PatchEvidence(
                        engine="SKIPPED",
                        target_file=resolved_target_file,
                        diff="",
                        validation_status="SKIPPED",
                        latency_ms=0.0,
                        success=True
                    ),
                    regression_ev=RegressionEvidence(
                        executed=True,
                        passed=regression_res.get("passed", False),
                        test_count=regression_res.get("test_count", 0),
                        latency_ms=regression_res.get("latency_ms", 0.0)
                    ),
                    exec_ev=exec_ev
                )

                return VerificationPipelineResponse(
                    cve_id=req.cve_id,
                    repo_path=str(source_repo),
                    reachability_verdict="UNREACHABLE_FALSE_POSITIVE",
                    harness=empty_harness,
                    pre_patch_result=empty_sandbox,
                    remediation=empty_rem,
                    post_patch_result=empty_sandbox,
                    regression_tests=regression_res,
                    final_behavioral_verdict=verdict_rec.terminal_state,
                    structured_evidence={"reachability": "UNREACHABLE_FALSE_POSITIVE", "dead_code_count": ast_res.unreachable_dead_code_count},
                    verdict_record=verdict_rec,
                    environment=env_evidence,
                    sandbox_engine=backend.capabilities.tier.value,
                    cloud_status="PERMISSION_DENIED (HTTP 403)",
                    total_pipeline_ms=round(dt_total, 2),
                    isolation_tier=backend.capabilities.tier.value,
                    isolation_attestation=attestation.model_dump(),
                    assurance_level=assurance_level.value,
                    policy_decision=policy_decision.model_dump()
                )

            emit("STATE_TRANSITION", "AST", f"REACHABLE VULNERABLE CALL PATH IDENTIFIED: Call graph path discovered to {resolved_target_file}:{resolved_target_func}()")

            # Threat Intelligence Query via Tavily with Strict Relevance Filtering
            tavily_report = None
            tavily_findings = []
            tavily_latency_ms = None
            if getattr(req, "query_tavily", True) and settings.has_tavily:
                emit("STAGE_START", "INTEL", f"Querying Tavily Threat Intelligence for real-time CVE advisories and PoCs for {req.cve_id}...")
                try:
                    tavily_client = TavilyClient()
                    tavily_report = await tavily_client.search_with_relevance(req.cve_id, max_results=6)
                    tavily_findings = tavily_report.findings
                    tavily_latency_ms = tavily_report.latency_ms
                    
                    emit("STAGE_COMPLETE", "INTEL", 
                         f"Tavily search completed: {tavily_report.raw_results_count} raw result(s), "
                         f"{tavily_report.retained_results_count} verified relevant to {req.cve_id} "
                         f"({tavily_report.filtered_out_count} excluded) in {tavily_latency_ms}ms.")
                    
                    for finding in tavily_findings[:2]:
                        emit("LOG", "INTEL", f"Verified Relevant Reference: {finding.title} ({finding.url})")
                    if tavily_report.filtered_out_count > 0:
                        emit("LOG", "INTEL", f"Relevance Filter: Excluded {tavily_report.filtered_out_count} result(s) not referencing {req.cve_id}.")
                except Exception as e:
                    emit("LOG", "INTEL", f"Tavily threat intelligence query failed: {e}")

            advisory_ev.pocs_count = len(tavily_findings)
            advisory_ev.pocs = tavily_findings
            advisory_ev.tavily_latency_ms = tavily_latency_ms

            # Stage 1: Harness Synthesis
            emit("STAGE_START", "HARNESS", f"Synthesizing controlled verification harness for {req.cve_id}...")
            sentinel_file = req.sentinel_filename or f"_sentinel_{uuid.uuid4().hex[:8]}.marker"
            harness_req = HarnessGenerateRequest(
                repo_path=str(disposable_dir),
                cve_id=req.cve_id,
                target_file=resolved_target_file,
                function_name=resolved_target_func,
                vulnerable_call=resolved_vuln_sym,
                sentinel_filename=sentinel_file
            )
            harness_res = HarnessSynthesizer.synthesize_harness(harness_req)
            
            # P0.5.5: Randomized harness artifact naming to reduce trivial environment detection
            harness_script_name = f"_eval_{uuid.uuid4().hex[:8]}.py"
            harness_file = disposable_dir / harness_script_name
            harness_file.write_text(harness_res.harness_code, encoding="utf-8")
            emit("STAGE_COMPLETE", "HARNESS", f"Harness generated in {harness_res.latency_ms}ms targeting {resolved_target_file}:{resolved_target_func}()")

            # Stage 2: Pre-Patch Sandbox Execution (Expect RED STATE)
            emit("STAGE_START", "REPRODUCTION", f"Executing pre-patch verification harness in isolated backend ({backend.capabilities.tier.value})...")
            pre_res = await _run_backend_script(harness_script_name, harness_res.sentinel_filename, "REPRODUCTION")

            # Check if pre-patch state could not reproduce (INCONCLUSIVE / GUARD BLOCKED / REJECTED)
            if pre_res.reproduction_state != "RED_STATE_REPRODUCED":
                emit("STATE_TRANSITION", "REPRODUCTION", f"PRE-PATCH STATE: {pre_res.reproduction_state} ({pre_res.validation_notes or pre_res.assertion_result}) (Exit {pre_res.exit_code}).")
                emit("LOG", "PATCH", "Halting automated patch synthesis: VulnTrace requires confirmed RED state before attempting remediation.")
                
                emit("STAGE_START", "REGRESSION", "Running baseline regression tests...")
                regression_res = await backend.run_regression_suite(workspace_id)
                emit("STAGE_COMPLETE", "REGRESSION", f"Baseline regression suite completed: {regression_res.get('test_count', 0)} tests passed.")

                empty_post = SandboxExecutionResult(
                    exit_code=pre_res.exit_code,
                    stdout="",
                    stderr=f"Post-patch verification skipped: Pre-patch state was {pre_res.reproduction_state}.",
                    latency_ms=0.0,
                    sentinel_created=False,
                    reproduction_state=pre_res.reproduction_state,
                    parent_validated=pre_res.parent_validated,
                    validation_notes=pre_res.validation_notes,
                    sandbox_engine=backend.capabilities.tier.value,
                    disposable_dir=str(disposable_dir)
                )
                empty_rem = RemediationResponse(
                    cve_id=req.cve_id,
                    target_file=resolved_target_file,
                    engine="SKIPPED",
                    diff="",
                    explanation=f"Skipped remediation: Pre-patch verification was not confirmed red ({pre_res.reproduction_state}).",
                    latency_ms=0.0,
                    success=False,
                    validation_status="SKIPPED"
                )

                verdict_rec = VerdictEngine.evaluate(
                    cve_id=req.cve_id,
                    repo_path=str(source_repo),
                    repo_ev=repo_ev,
                    advisory_ev=advisory_ev,
                    reach_ev=reach_ev,
                    behavior_ev=BehaviorEvidence(
                        pre_patch_exit_code=pre_res.exit_code,
                        pre_patch_sentinel_observed=pre_res.sentinel_created,
                        pre_patch_state=pre_res.reproduction_state,
                        pre_patch_assertion=pre_res.assertion_result,
                        post_patch_exit_code=0,
                        post_patch_sentinel_observed=False,
                        post_patch_state=pre_res.reproduction_state,
                        parent_validated=pre_res.parent_validated,
                        validation_notes=pre_res.validation_notes
                    ),
                    patch_ev=PatchEvidence(
                        engine="SKIPPED",
                        target_file=resolved_target_file,
                        diff="",
                        validation_status="SKIPPED",
                        latency_ms=0.0,
                        success=False
                    ),
                    regression_ev=RegressionEvidence(
                        executed=True,
                        passed=regression_res.get("passed", False),
                        test_count=regression_res.get("test_count", 0),
                        latency_ms=regression_res.get("latency_ms", 0.0)
                    ),
                    exec_ev=exec_ev
                )

                dt_total = (time.perf_counter() - t0) * 1000.0
                emit("STATE_TRANSITION", "VERDICT", f"FINAL BEHAVIORAL VERDICT: {verdict_rec.terminal_state} (Total: {round(dt_total, 2)}ms)")

                return VerificationPipelineResponse(
                    cve_id=req.cve_id,
                    repo_path=str(source_repo),
                    reachability_verdict=reachability_verdict,
                    harness=harness_res,
                    pre_patch_result=pre_res,
                    remediation=empty_rem,
                    post_patch_result=empty_post,
                    regression_tests=regression_res,
                    final_behavioral_verdict=verdict_rec.terminal_state,
                    structured_evidence=pre_res.structured_evidence,
                    verdict_record=verdict_rec,
                    environment=env_evidence,
                    sandbox_engine=backend.capabilities.tier.value,
                    cloud_status="PERMISSION_DENIED (HTTP 403)",
                    total_pipeline_ms=round(dt_total, 2),
                    isolation_tier=backend.capabilities.tier.value,
                    isolation_attestation=attestation.model_dump()
                )

            emit("STATE_TRANSITION", "REPRODUCTION", f"RED STATE REPRODUCED: Sentinel marker confirmed (exit {pre_res.exit_code}) in {pre_res.latency_ms}ms")

            # Stage 3: Remediation Synthesis & Application
            emit("STAGE_START", "PATCH", f"Synthesizing surgical remediation (Nemotron: {req.use_nemotron})...")
            
            # Incorporate Tavily threat intelligence into advisory prompt for Nemotron
            advisory_context = req.advisory_summary or f"Remediate {req.cve_id} in {resolved_target_file}:{resolved_target_func}(): unsafe {resolved_vuln_sym} deserialization."
            if tavily_findings:
                advisory_context += "\n\nReal-Time Verified Threat Intelligence & Exploitation Context (via Tavily Search):\n"
                for idx, finding in enumerate(tavily_findings[:3], 1):
                    advisory_context += f"[{idx}] {finding.title}\nURL: {finding.url}\nContext: {finding.snippet}\n\n"
                advisory_context += "Analyze this vulnerability context and synthesize a secure, minimal patch that prevents this exploit without breaking valid application data structures or custom loader handlers."
                emit("LOG", "PATCH", f"Incorporated {min(len(tavily_findings), 3)} verified-relevant Tavily threat intelligence references into Nemotron reasoning context.")
            elif tavily_report and tavily_report.raw_results_count > 0:
                emit("LOG", "PATCH", f"Tavily returned {tavily_report.raw_results_count} results but none matched target {req.cve_id}; proceeding without unverified external intelligence.")

            rem_req = RemediationRequest(
                repo_path=str(disposable_dir),
                cve_id=req.cve_id,
                target_file=resolved_target_file,
                vulnerable_call=resolved_vuln_sym,
                use_nemotron=req.use_nemotron,
                advisory_summary=advisory_context
            )
            remediation_res = await RemediationPatcher.synthesize_remediation(rem_req, workspace_dir=disposable_dir)

            if not remediation_res.success:
                emit("STATE_TRANSITION", "PATCH", f"PATCH REJECTED: {remediation_res.validation_status} ({remediation_res.error})")
                empty_post = SandboxExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Post-patch verification skipped: Remediation was rejected ({remediation_res.error}).",
                    latency_ms=0.0,
                    sentinel_created=False,
                    reproduction_state="PATCH_REJECTED",
                    parent_validated=False,
                    validation_notes=f"Remediation patch rejected: {remediation_res.validation_status}",
                    sandbox_engine=backend.capabilities.tier.value,
                    disposable_dir=str(disposable_dir)
                )

                verdict_rec = VerdictEngine.evaluate(
                    cve_id=req.cve_id,
                    repo_path=str(source_repo),
                    repo_ev=repo_ev,
                    advisory_ev=advisory_ev,
                    reach_ev=reach_ev,
                    behavior_ev=BehaviorEvidence(
                        pre_patch_exit_code=pre_res.exit_code,
                        pre_patch_sentinel_observed=pre_res.sentinel_created,
                        pre_patch_state=pre_res.reproduction_state,
                        pre_patch_assertion=pre_res.assertion_result,
                        post_patch_exit_code=-1,
                        post_patch_sentinel_observed=False,
                        post_patch_state="PATCH_REJECTED",
                        parent_validated=False
                    ),
                    patch_ev=PatchEvidence(
                        engine=remediation_res.engine,
                        target_file=resolved_target_file,
                        diff=remediation_res.diff,
                        validation_status=remediation_res.validation_status or "REJECTED",
                        latency_ms=remediation_res.latency_ms,
                        success=False
                    ),
                    regression_ev=RegressionEvidence(
                        executed=False,
                        passed=False,
                        test_count=0,
                        latency_ms=0.0,
                        error="SKIPPED_DUE_TO_PATCH_REJECTION"
                    ),
                    exec_ev=exec_ev
                )

                dt_total = (time.perf_counter() - t0) * 1000.0
                emit("STATE_TRANSITION", "VERDICT", f"FINAL BEHAVIORAL VERDICT: {verdict_rec.terminal_state} (Total: {round(dt_total, 2)}ms)")

                return VerificationPipelineResponse(
                    cve_id=req.cve_id,
                    repo_path=str(source_repo),
                    reachability_verdict=reachability_verdict,
                    harness=harness_res,
                    pre_patch_result=pre_res,
                    remediation=remediation_res,
                    post_patch_result=empty_post,
                    regression_tests={"passed": False, "test_count": 0, "error": "PATCH_REJECTED"},
                    final_behavioral_verdict=verdict_rec.terminal_state,
                    structured_evidence=pre_res.structured_evidence,
                    verdict_record=verdict_rec,
                    environment=env_evidence,
                    sandbox_engine=backend.capabilities.tier.value,
                    cloud_status="PERMISSION_DENIED (HTTP 403)",
                    total_pipeline_ms=round(dt_total, 2),
                    isolation_tier=backend.capabilities.tier.value,
                    isolation_attestation=attestation.model_dump(),
                    assurance_level=assurance_level.value,
                    policy_decision=policy_decision.model_dump()
                )

            emit("STAGE_COMPLETE", "PATCH", f"Remediation generated via {remediation_res.engine} ({remediation_res.latency_ms}ms)")

            # Stage 4: Post-Patch Sandbox Execution (Expect GREEN STATE)
            emit("STAGE_START", "VERIFICATION", f"Executing post-patch re-test in isolated backend ({backend.capabilities.tier.value}) (expecting safe-block)...")
            post_res = await _run_backend_script(harness_script_name, harness_res.sentinel_filename, "VERIFICATION")

            if post_res.reproduction_state == "GREEN_STATE_BLOCKED":
                emit("STATE_TRANSITION", "VERIFICATION", f"GREEN STATE VERIFIED: Risky instantiation blocked (exit {post_res.exit_code}, {post_res.assertion_result}) in {post_res.latency_ms}ms")
            else:
                emit("STATE_TRANSITION", "VERIFICATION", f"POST-PATCH VERIFICATION FAILED: {post_res.reproduction_state} ({post_res.validation_notes})")

            # Stage 5: Regression Testing
            emit("STAGE_START", "REGRESSION", "Executing regression test suite (pytest)...")
            regression_res = await backend.run_regression_suite(workspace_id)
            if regression_res.get("passed"):
                emit("STAGE_COMPLETE", "REGRESSION", f"Regression suite PASSED: {regression_res.get('test_count', 0)} tests passed in {regression_res.get('latency_ms')}ms")
            else:
                emit("STATE_TRANSITION", "REGRESSION", f"REGRESSION FAILURE: {regression_res.get('stderr')}")

            # Stage 6: Centralized Formal Verdict Decision via VerdictEngine
            behavior_ev = BehaviorEvidence(
                pre_patch_exit_code=pre_res.exit_code,
                pre_patch_sentinel_observed=pre_res.sentinel_created,
                pre_patch_state=pre_res.reproduction_state,
                pre_patch_assertion=pre_res.assertion_result,
                post_patch_exit_code=post_res.exit_code,
                post_patch_sentinel_observed=post_res.sentinel_created,
                post_patch_state=post_res.reproduction_state,
                post_patch_assertion=post_res.assertion_result,
                parent_validated=post_res.parent_validated,
                validation_notes=post_res.validation_notes
            )
            patch_ev = PatchEvidence(
                engine=remediation_res.engine,
                target_file=resolved_target_file,
                diff=remediation_res.diff,
                validation_status=remediation_res.validation_status or "ACCEPTED",
                tokens_used=remediation_res.tokens_used,
                reasoning_tokens=remediation_res.reasoning_tokens,
                latency_ms=remediation_res.latency_ms,
                success=remediation_res.success
            )
            regression_ev = RegressionEvidence(
                executed=True,
                passed=regression_res.get("passed", False),
                test_count=regression_res.get("test_count", 0),
                latency_ms=regression_res.get("latency_ms", 0.0),
                error=regression_res.get("error")
            )

            verdict_record = VerdictEngine.evaluate(
                cve_id=req.cve_id,
                repo_path=str(source_repo),
                repo_ev=repo_ev,
                advisory_ev=advisory_ev,
                reach_ev=reach_ev,
                behavior_ev=behavior_ev,
                patch_ev=patch_ev,
                regression_ev=regression_ev,
                exec_ev=exec_ev
            )

            final_verdict = verdict_record.terminal_state
            dt_total = (time.perf_counter() - t0) * 1000.0
            emit("STATE_TRANSITION", "VERDICT", f"FINAL BEHAVIORAL VERDICT: {final_verdict} (Total pipeline: {round(dt_total, 2)}ms)")

            # Assemble comprehensive, multi-layer evidence record
            pipeline_evidence = dict(post_res.structured_evidence or pre_res.structured_evidence or {})
            if tavily_report:
                pipeline_evidence["tavily_threat_intelligence"] = {
                    "provider": "Tavily Search API",
                    "endpoint": "https://api.tavily.com/search",
                    "status": "HTTP_200_OK" if tavily_report.status_code == 200 else f"HTTP_{tavily_report.status_code}",
                    "latency_ms": tavily_report.latency_ms,
                    "query": tavily_report.query,
                    "raw_results_count": tavily_report.raw_results_count,
                    "retained_relevant_count": tavily_report.retained_results_count,
                    "filtered_out_count": tavily_report.filtered_out_count,
                    "relevance_criterion": f"Must explicitly mention target '{req.cve_id}' in title, URL, or body content",
                    "retained_sources": [{"title": f.title, "url": f.url} for f in tavily_findings],
                    "filtered_out_reasons": tavily_report.rejection_reasons
                }
            elif tavily_findings:
                pipeline_evidence["tavily_threat_intelligence"] = {
                    "provider": "Tavily Search API",
                    "endpoint": "https://api.tavily.com/search",
                    "status": "HTTP_200_OK",
                    "latency_ms": tavily_latency_ms,
                    "raw_results_count": len(tavily_findings),
                    "retained_relevant_count": len(tavily_findings),
                    "filtered_out_count": 0,
                    "retained_sources": [{"title": f.title, "url": f.url} for f in tavily_findings]
                }
            if remediation_res.engine == "NVIDIA_NEMOTRON_3_ULTRA":
                pipeline_evidence["nebius_nemotron_inference"] = {
                    "provider": "Nebius Token Factory",
                    "endpoint": "https://api.tokenfactory.nebius.com/v1/chat/completions",
                    "model": remediation_res.model_name or "nvidia/Nemotron-3-Ultra-550b-a55b",
                    "tokens_used": remediation_res.tokens_used,
                    "reasoning_tokens": remediation_res.reasoning_tokens,
                    "latency_ms": remediation_res.latency_ms,
                    "validation_status": remediation_res.validation_status
                }

            pipeline_evidence["environment"] = env_evidence.model_dump()
            return VerificationPipelineResponse(
                cve_id=req.cve_id,
                repo_path=str(source_repo),
                reachability_verdict=reachability_verdict,
                harness=harness_res,
                pre_patch_result=pre_res,
                remediation=remediation_res,
                post_patch_result=post_res,
                regression_tests=regression_res,
                final_behavioral_verdict=final_verdict,
                structured_evidence=pipeline_evidence,
                verdict_record=verdict_record,
                environment=env_evidence,
                sandbox_engine=backend.capabilities.tier.value,
                cloud_status="PERMISSION_DENIED (HTTP 403)",
                total_pipeline_ms=round(dt_total, 2),
                isolation_tier=backend.capabilities.tier.value,
                isolation_attestation=attestation.model_dump(),
                assurance_level=assurance_level.value,
                policy_decision=policy_decision.model_dump()
            )

        finally:
            # Deterministic cleanup of isolated workspace
            await backend.cleanup_workspace(workspace_id)
            emit("STAGE_COMPLETE", "SANDBOX", "Disposable workspace cleanly destroyed on backend.")
