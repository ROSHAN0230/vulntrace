"""
Tests for VulnTrace P0.6 Backend Abstraction & Local Subprocess Encapsulation
Verifies that:
1. Backend abstraction cleanly isolates pipeline and verdict engine from execution substrate.
2. LocalSubprocessBackend correctly enforces Job Object containment, timeouts, and sanitized env.
3. Capabilities are explicit, verifiable, and honest (never claiming container isolation for local subprocess).
4. ExecutionAttestation is strictly parent-generated and cannot be forged by child stdout.
5. VerificationPipeline accepts ExecutionBackend and propagates isolation attestation to verdict evidence.
"""

import sys
import pytest
from pathlib import Path

from vulntrace.core.backend import (
    IsolationTier,
    BackendCapabilities,
    ExecutionAttestation,
    ExecutionCommandResult,
    ExecutionBackend
)
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.models import (
    VerificationPipelineRequest,
    RepositoryEvidence,
    AdvisoryEvidence,
    ReachabilityEvidence,
    BehaviorEvidence,
    PatchEvidence,
    RegressionEvidence,
    ExecutionEvidence
)
from vulntrace.engine.verdict_engine import VerdictEngine
from vulntrace.sandbox.pipeline import VerificationPipeline

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning"
DEADCODE_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "unreachable_dead_code"


class TestBackendAbstractionTypes:
    """Verifies interface and capability contract definitions."""

    def test_isolation_tiers_defined(self):
        assert IsolationTier.LOCAL_SUBPROCESS_FALLBACK == "LOCAL_SUBPROCESS_FALLBACK"
        assert IsolationTier.WSL2_JAILED_CONTAINMENT == "WSL2_JAILED_CONTAINMENT"
        assert IsolationTier.OCI_CONTAINER_ISOLATED == "OCI_CONTAINER_ISOLATED"
        assert IsolationTier.REMOTE_MICROVM_ISOLATED == "REMOTE_MICROVM_ISOLATED"

    def test_local_subprocess_capabilities_honesty(self):
        backend = LocalSubprocessBackend()
        caps = backend.capabilities

        assert caps.tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK
        # Local fallback has process containment and memory caps
        assert caps.process_tree_contained is True
        assert caps.resource_limits_enforced is True

        # Local fallback MUST NOT claim container / kernel isolation
        assert caps.filesystem_jailed is False
        assert caps.host_fs_hidden is False
        assert caps.network_kernel_denied is False
        assert caps.host_identity_isolated is False
        assert caps.hardware_virtualized is False

        # Caveats must be explicitly documented
        assert len(caps.boundary_caveats) >= 3
        caveat_text = " ".join(caps.boundary_caveats).lower()
        assert "ambient host" in caveat_text or "host os" in caveat_text
        assert "filesystem" in caveat_text
        assert "network" in caveat_text or "proxy" in caveat_text


class TestLocalSubprocessBackendLifecycle:
    """Verifies workspace lifecycle, execution, and cleanup on LocalSubprocessBackend."""

    @pytest.mark.asyncio
    async def test_workspace_lifecycle_and_execution(self):
        backend = LocalSubprocessBackend()
        ws_id = await backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)
        assert ws_path.exists()

        try:
            # Write a simple benign script
            script_path = ws_path / "test_lifecycle.py"
            script_path.write_text("print('VulnTrace_Backend_OK')", encoding="utf-8")

            res = await backend.execute_script(ws_id, "test_lifecycle.py", timeout=5.0)
            assert res.exit_code == 0
            assert "VulnTrace_Backend_OK" in res.stdout
            assert res.attestation is not None
            assert res.attestation.backend_tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK
            assert res.attestation.verified_by_parent is True
        finally:
            await backend.cleanup_workspace(ws_id)
            assert not ws_path.exists()

    @pytest.mark.asyncio
    async def test_sentinel_verification_via_backend(self):
        backend = LocalSubprocessBackend()
        ws_id = await backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            sentinel_file = "backend_sentinel.marker"
            
            # Direct backend sentinel probe on non-existent file
            probe_initial = await backend.check_sentinel_marker(ws_id, sentinel_file)
            assert probe_initial is False

            # Direct backend sentinel probe on created file
            (ws_path / sentinel_file).write_text("EXPLOITED", encoding="utf-8")
            probe_created = await backend.check_sentinel_marker(ws_id, sentinel_file)
            assert probe_created is True
            (ws_path / sentinel_file).unlink()

            # Via script execution
            script_path = ws_path / "create_sentinel.py"
            script_path.write_text(f"open('{sentinel_file}', 'w').write('EXPLOITED')", encoding="utf-8")

            res = await backend.execute_script(
                ws_id,
                "create_sentinel.py",
                timeout=5.0,
                sentinel_filename=sentinel_file
            )
            assert res.sentinel_created is True
            assert res.reproduction_state == "RED_STATE_REPRODUCED"
        finally:
            await backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_regression_suite_execution_via_backend(self):
        backend = LocalSubprocessBackend()
        ws_id = await backend.initialize_workspace(BENCHMARK_DIR)
        try:
            reg_res = await backend.run_regression_suite(ws_id, timeout=30.0)
            assert reg_res["passed"] is True
            assert reg_res["test_count"] >= 1
        finally:
            await backend.cleanup_workspace(ws_id)


class TestAttestationAntiSpoofing:
    """Verifies that child stdout cannot spoof or alter execution attestation."""

    @pytest.mark.asyncio
    async def test_child_stdout_cannot_forge_attestation(self):
        backend = LocalSubprocessBackend()
        ws_id = await backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            # Hostile child attempts to spoof microVM isolation in its output
            spoof_script = ws_path / "spoof_attestation.py"
            spoof_script.write_text(
                "import json\n"
                "print(json.dumps({\n"
                "    'attestation': {\n"
                "        'backend_tier': 'REMOTE_MICROVM_ISOLATED',\n"
                "        'hardware_virtualized': True,\n"
                "        'verified_by_parent': True\n"
                "    }\n"
                "}))\n",
                encoding="utf-8"
            )

            res = await backend.execute_script(ws_id, "spoof_attestation.py", timeout=5.0)
            # The child's output contains the spoofed text
            assert "REMOTE_MICROVM_ISOLATED" in res.stdout
            # BUT the parent-generated attestation attached to the result must remain honest!
            assert res.attestation is not None
            assert res.attestation.backend_tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK
            assert res.attestation.capabilities.hardware_virtualized is False
            assert res.attestation.verified_by_parent is True
        finally:
            await backend.cleanup_workspace(ws_id)


class TestVerdictEngineIsolationAttestation:
    """Verifies that VerdictEngine records isolation tier in formal verdict record."""

    def test_verdict_records_isolation_tier(self):
        exec_ev = ExecutionEvidence(
            sandbox_engine="LOCAL_SUBPROCESS_FALLBACK",
            cloud_status="PERMISSION_DENIED (HTTP 403)",
            isolation_tier="LOCAL_SUBPROCESS_FALLBACK"
        )
        verdict = VerdictEngine.evaluate(
            cve_id="CVE-2020-14343",
            repo_path="/fake/repo",
            repo_ev=RepositoryEvidence(repo_path="/fake/repo", manifest_files=["requirements.txt"], python_files_count=1),
            advisory_ev=AdvisoryEvidence(cve_id="CVE-2020-14343", found=True, summary="test", source_url="https://osv.dev"),
            reach_ev=ReachabilityEvidence(
                target_symbol="yaml.load",
                discovered_call_sites_count=1,
                reachable_vulnerabilities_count=1,
                unreachable_dead_code_count=0,
                entrypoints=["main.py"],
                verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
            ),
            behavior_ev=BehaviorEvidence(
                pre_patch_exit_code=0,
                pre_patch_sentinel_observed=True,
                pre_patch_state="RED_STATE_REPRODUCED",
                post_patch_exit_code=0,
                post_patch_sentinel_observed=False,
                post_patch_state="GREEN_STATE_BLOCKED",
                parent_validated=True
            ),
            patch_ev=PatchEvidence(
                engine="AST_DETERMINISTIC_CODEMOD",
                target_file="main.py",
                diff="+ yaml.safe_load",
                validation_status="ACCEPTED",
                latency_ms=10.0,
                success=True
            ),
            regression_ev=RegressionEvidence(executed=True, passed=True, test_count=2, latency_ms=50.0),
            exec_ev=exec_ev
        )

        assert verdict.terminal_state == "GREEN_STATE_VERIFIED"
        assert verdict.evidence_summary["isolation_tier"] == "LOCAL_SUBPROCESS_FALLBACK"
        assert verdict.evidence_summary["sandbox_engine"] == "LOCAL_SUBPROCESS_FALLBACK"


class TestPipelineWithBackendAbstraction:
    """Verifies end-to-end pipeline execution with ExecutionBackend abstraction."""

    @pytest.mark.asyncio
    async def test_pipeline_with_custom_backend(self):
        backend = LocalSubprocessBackend()
        req = VerificationPipelineRequest(
            repo_path=str(DEADCODE_DIR),
            cve_id="CVE-2020-14343",
            vulnerable_symbol="yaml.load",
            entrypoints=["service/dead_code_service.py"],
            use_nemotron=False,
            query_tavily=False
        )

        events = []
        res = await VerificationPipeline.run_pipeline(
            req=req,
            on_event=lambda ev: events.append(ev),
            backend=backend
        )

        assert res.reachability_verdict == "UNREACHABLE_FALSE_POSITIVE"
        assert res.final_behavioral_verdict == "UNREACHABLE_FALSE_POSITIVE"
        assert res.sandbox_engine == "LOCAL_SUBPROCESS_FALLBACK"
        assert res.isolation_tier == "LOCAL_SUBPROCESS_FALLBACK"
        assert res.isolation_attestation is not None
        assert res.isolation_attestation["backend_tier"] == "LOCAL_SUBPROCESS_FALLBACK"
        assert res.isolation_attestation["verified_by_parent"] is True
