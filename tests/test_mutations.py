"""
VulnTrace Mutation / Perturbation Test Suite
Empirically attacks the VulnTrace engine by systematically altering repository geometry,
file paths, function names, call depths, and sentinel marker names to prove that
reachability analysis and verification harnesses are dynamically synthesized from code topology
rather than static assumptions or hardcoded strings.
"""

import pytest
import shutil
import tempfile
from pathlib import Path
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest

@pytest.fixture
def temp_mutated_repo():
    """Creates a temporary mutated codebase with randomized topology."""
    temp_dir = Path(tempfile.mkdtemp(prefix="vulntrace_mutation_"))
    try:
        # Create deep 4-tier directory hierarchy with non-standard names
        src_dir = temp_dir / "infra" / "adapters" / "input_pipelines"
        src_dir.mkdir(parents=True, exist_ok=True)
        tests_dir = temp_dir / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)

        # Tier 4: The leaf vulnerable sink with completely arbitrary names
        leaf_file = src_dir / "untrusted_blob_deserializer.py"
        leaf_file.write_text(
            '''"""Arbitrary untrusted blob deserializer."""
import yaml
import os

def unpack_tenant_manifest(blob_data: str) -> dict:
    """Deserializes raw tenant manifest."""
    # Intentional vulnerable call
    result = yaml.load(blob_data, Loader=yaml.Loader)
    if isinstance(result, dict):
        return result
    return {"manifest": result}
''',
            encoding="utf-8"
        )

        # Tier 3: Internal router
        router_file = temp_dir / "infra" / "router.py"
        router_file.write_text(
            '''from infra.adapters.input_pipelines.untrusted_blob_deserializer import unpack_tenant_manifest

def route_tenant_payload(raw_payload: str) -> dict:
    return unpack_tenant_manifest(raw_payload)
''',
            encoding="utf-8"
        )

        # Tier 2: Controller dispatcher
        controller_file = temp_dir / "controllers" / "tenant_controller.py"
        controller_file.parent.mkdir(parents=True, exist_ok=True)
        controller_file.write_text(
            '''from infra.router import route_tenant_payload

def dispatch_incoming_schema(schema_text: str) -> dict:
    return route_tenant_payload(schema_text)
''',
            encoding="utf-8"
        )

        # Tier 1: Gateway Entrypoint
        gateway_file = temp_dir / "api" / "gateway.py"
        gateway_file.parent.mkdir(parents=True, exist_ok=True)
        gateway_file.write_text(
            '''from controllers.tenant_controller import dispatch_incoming_schema

def api_handle_manifest_upload(raw_manifest: str) -> dict:
    """Public API endpoint handler."""
    return dispatch_incoming_schema(raw_manifest)
''',
            encoding="utf-8"
        )

        # Pytest regression suite
        test_file = tests_dir / "test_tenant_pipeline.py"
        test_file.write_text(
            '''from api.gateway import api_handle_manifest_upload

def test_valid_manifest():
    res = api_handle_manifest_upload("service_name: core_auth\\nport: 8080")
    assert res.get("service_name") == "core_auth"
    assert res.get("port") == 8080

def test_list_manifest():
    res = api_handle_manifest_upload("items:\\n  - alpha\\n  - beta")
    assert "items" in res
    assert len(res["items"]) == 2
''',
            encoding="utf-8"
        )

        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_mutation_deep_renamed_callchain(temp_mutated_repo):
    """
    Test 1: Completely renamed directory structure, filenames, and function names.
    Proves zero reliance on 'service.py', 'load_user_config', or 'services/yaml_parser.py'.
    Uses a custom sentinel marker 'mutation_proof_8829.marker'.
    """
    req = VerificationPipelineRequest(
        repo_path=str(temp_mutated_repo),
        cve_id="CVE-2020-14343",
        target_file="infra/adapters/input_pipelines/untrusted_blob_deserializer.py",
        target_function="unpack_tenant_manifest",
        vulnerable_symbol="yaml.load",
        sentinel_filename="mutation_proof_8829.marker",
        use_nemotron=False  # Deterministic AST codemod for fast, reliable CI verification
    )

    res = await VerificationPipeline.run_pipeline(req)

    # 1. Reachability correctly identified across 4 tiers
    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"

    # 2. Harness generated targeting the custom function and custom sentinel
    assert res.harness.target_file == "infra/adapters/input_pipelines/untrusted_blob_deserializer.py"
    assert res.harness.function_name == "unpack_tenant_manifest"
    assert res.harness.sentinel_filename == "mutation_proof_8829.marker"

    # 3. Pre-patch state reproduced (RED)
    assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"
    assert res.pre_patch_result.exit_code == 0

    # 4. Remediation applied cleanly to the renamed file
    assert res.remediation.success is True
    assert "infra/adapters/input_pipelines/untrusted_blob_deserializer.py" in res.remediation.diff
    assert "safe_load" in res.remediation.diff

    # 5. Post-patch state blocked (GREEN) with exit code 42
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.post_patch_result.exit_code == 42
    assert res.post_patch_result.assertion_result == "GREEN_SECURITY_BLOCK_VERIFIED"

    # 6. Regression tests pass
    assert res.regression_tests.get("passed") is True
    assert res.regression_tests.get("test_count") == 2

    # 7. Final verdict
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"


@pytest.mark.asyncio
async def test_mutation_dynamic_symbol_and_target_inference(temp_mutated_repo):
    """
    Test 2: Target file and target function are NOT provided in the request (None).
    Proves that the engine dynamically infers the target file and function from AST call graph.
    """
    req = VerificationPipelineRequest(
        repo_path=str(temp_mutated_repo),
        cve_id="CVE-2020-14343",
        target_file=None,        # Dynamic inference
        target_function=None,    # Dynamic inference
        vulnerable_symbol="yaml.load",
        sentinel_filename="dynamic_infer_sentinel.marker",
        use_nemotron=False
    )

    res = await VerificationPipeline.run_pipeline(req)

    # Inferred correct file and function
    assert "untrusted_blob_deserializer.py" in res.harness.target_file
    assert res.harness.function_name == "unpack_tenant_manifest"
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
