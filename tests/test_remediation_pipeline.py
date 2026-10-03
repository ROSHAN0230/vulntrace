import pytest
from pathlib import Path
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest

@pytest.mark.asyncio
async def test_end_to_end_verification_pipeline():
    sample_repo = (Path(__file__).resolve().parent.parent / "sample_repo").resolve()
    assert sample_repo.exists()

    events = []
    req = VerificationPipelineRequest(
        repo_path=str(sample_repo),
        cve_id="CVE-2020-14343",
        target_file="service.py",
        target_function="load_user_config",
        use_nemotron=False  # test with deterministic codemod for fast, reliable CI pass
    )
    res = await VerificationPipeline.run_pipeline(req, on_event=lambda e: events.append(e))

    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"
    assert res.pre_patch_result.exit_code == 0
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.post_patch_result.exit_code == 42
    assert res.regression_tests.get("passed") is True
    assert res.regression_tests.get("test_count") == 2
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"
    assert res.sandbox_engine in ["LOCAL_SUBPROCESS_FALLBACK", "OCI_CONTAINER_ISOLATED"]
    assert res.isolation_tier in ["LOCAL_SUBPROCESS_FALLBACK", "OCI_CONTAINER_ISOLATED"]
    assert res.isolation_attestation is not None
    assert len(events) >= 5
