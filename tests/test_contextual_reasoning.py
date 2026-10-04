"""
VulnTrace Contextual Reasoning Benchmark Test
Verifies Section 6: Proving Nemotron's real contextual reasoning over blind deterministic codemods.
A naive AST replacement (yaml.safe_load) strips custom application tag handlers (!env_var) and fails regressions.
NVIDIA Nemotron 3 Ultra understands surrounding module context, binds AppSafeLoader, and passes both security and regression suites.
"""

import pytest
from pathlib import Path
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest
from vulntrace.config import settings

@pytest.mark.asyncio
async def test_contextual_reasoning_nemotron_vs_blind_ast():
    if not settings.has_nebius:
        pytest.skip("NEBIUS_API_KEY not configured in environment or .env; skipping live Nemotron test.")

    repo_path = (Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning").resolve()
    assert repo_path.exists()

    req = VerificationPipelineRequest(
        repo_path=str(repo_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=True
    )

    res = await VerificationPipeline.run_pipeline(req)

    # Reachability path identified
    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"

    # Pre-patch red state reproduced
    assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"

    # Remediation synthesized by Nemotron 3 Ultra
    assert res.remediation.engine == "NVIDIA_NEMOTRON_3_ULTRA"
    assert res.remediation.success is True

    # Post-patch security block verified (exit 42)
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.post_patch_result.exit_code == 42

    # Regression tests: all 3 passed (including custom tag !env_var)
    assert res.regression_tests.get("passed") is True
    assert res.regression_tests.get("test_count") == 3

    # Final verdict
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"
