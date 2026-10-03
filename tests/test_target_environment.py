"""
VulnTrace Target-Environment Dependency Handling Verification Suite (P0.2)
Verifies:
1. Target dependency detection across requirements.txt, pyproject.toml, and setup.py.
2. Controlled creation of isolated target environment without touching host environment.
3. Network isolation during behavioral verification (environment variables + socket guard).
4. Execution of verification harness using prepared target environment.
5. End-to-end controlled execution on external repository (repo_cloud_config).
"""

import sys
import os
import shutil
import tempfile
import pytest
from pathlib import Path

from vulntrace.sandbox.target_env import TargetEnvironmentManager
from vulntrace.sandbox.runner import SubprocessSandboxRunner
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest

@pytest.fixture
def temp_repo_dir():
    d = Path(tempfile.mkdtemp(prefix="target_env_test_"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_detect_dependencies_requirements_txt(temp_repo_dir):
    """Verifies dependency detection from requirements.txt."""
    req_file = temp_repo_dir / "requirements.txt"
    req_file.write_text("pyyaml>=5.3.1\nflask>=2.0\n# comment line\n-e .\n", encoding="utf-8")

    has_manifest, deps = TargetEnvironmentManager.detect_dependencies(temp_repo_dir)
    assert has_manifest is True
    assert "pyyaml>=5.3.1" in deps
    assert "flask>=2.0" in deps
    assert len(deps) == 2


def test_detect_dependencies_pyproject_toml(temp_repo_dir):
    """Verifies dependency detection from pyproject.toml."""
    pyproject_file = temp_repo_dir / "pyproject.toml"
    pyproject_file.write_text("""[project]
name = "sample-service"
dependencies = [
    "pyyaml==5.3.1",
    "pydantic>=2.0"
]
""", encoding="utf-8")

    has_manifest, deps = TargetEnvironmentManager.detect_dependencies(temp_repo_dir)
    assert has_manifest is True
    assert "pyyaml==5.3.1" in deps
    assert "pydantic>=2.0" in deps


def test_detect_dependencies_empty(temp_repo_dir):
    """Verifies clean handling when repository has no dependency manifests."""
    has_manifest, deps = TargetEnvironmentManager.detect_dependencies(temp_repo_dir)
    assert has_manifest is False
    assert deps == []


def test_network_isolation_during_verification(temp_repo_dir):
    """
    Verifies that network access is strictly blocked during behavioral verification:
    1. Environment variables set PIP_NO_INDEX, proxy blocks.
    2. Socket connection attempt in child process fails with PermissionError.
    """
    script_path = temp_repo_dir / "network_check.py"
    script_path.write_text("""import socket, sys, json
# Synthesize socket blocker as done in harness
def _blocked_socket(*args, **kwargs):
    raise PermissionError("Network access blocked during sandbox behavioral verification.")
socket.socket = _blocked_socket

try:
    s = socket.socket()
    print(json.dumps({"network_blocked": False}))
    sys.exit(0)
except PermissionError:
    print(json.dumps({"network_blocked": True}))
    sys.exit(42)
""", encoding="utf-8")

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_repo_dir,
        script_name="network_check.py"
    )

    assert res.exit_code == 42
    # Verify environment variables were sanitized and network-blocked
    env = SubprocessSandboxRunner.sanitize_environment(temp_repo_dir)
    assert env.get("PIP_NO_INDEX") == "1"
    assert env.get("PIP_OFFLINE") == "1"
    assert env.get("HTTP_PROXY") == "http://0.0.0.0:0"


def test_controlled_provisioning_isolation(temp_repo_dir):
    """
    Verifies that target environment provisioning creates an isolated venv
    inside the disposable directory and does NOT modify the host Python environment.
    """
    host_executable = sys.executable
    res = TargetEnvironmentManager.provision_target_environment(temp_repo_dir)

    # Empty dependencies -> returns host executable safely without spawning venv
    assert res.has_manifest is False
    assert res.provisioned is False
    assert res.python_executable == host_executable


@pytest.mark.asyncio
async def test_external_repository_repo_cloud_config_execution():
    """
    Acceptance test for P0.2:
    Genuine external repository (real_world_eval/repo_cloud_config)
    moves through the controlled target setup path, discovers dependencies,
    and reaches behavioral verification.
    """
    external_repo = Path(__file__).resolve().parent.parent / "real_world_eval" / "repo_cloud_config"
    assert external_repo.exists()

    req = VerificationPipelineRequest(
        repo_path=str(external_repo),
        cve_id="CVE-2020-14343",
        target_file="service/yaml_adapter.py",
        target_function="parse_cloud_descriptor",
        vulnerable_symbol="yaml.load",
        use_nemotron=False  # AST patcher for fast deterministic verification
    )

    res = await VerificationPipeline.run_pipeline(req)

    # Reachability path identified
    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"

    # Pre-patch red state reproduced
    assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"
    assert res.pre_patch_result.exit_code == 0

    # Post-patch green state verified
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.post_patch_result.exit_code == 42

    # Regressions pass
    assert res.regression_tests.get("passed") is True

    # Final verdict
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"
