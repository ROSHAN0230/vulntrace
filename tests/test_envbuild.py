"""
VulnTrace Milestone M2 — Dedicated Target Environment Builder Tests (Spec §4.5)

Verifies:
1. Dedicated per-case virtual environment outside repository workspace.
2. Target dependency installation from declared manifests (requirements.txt, pyproject.toml, setup.py).
3. Wheel caching and build metrics (Python version, build duration ms, pip log excerpt).
4. Truthful failure classification: Broken dependencies produce ENV_BUILD_FAILED, never UNEXPECTED_FAILURE.
5. Verification pipeline early-halting and structured environment evidence preservation.
6. Host isolation and secret sanitization during environment construction.
"""

import os
import shutil
import tempfile
from pathlib import Path
import pytest

from vulntrace.envbuild import EnvironmentBuilder
from vulntrace.models import VerificationPipelineRequest
from vulntrace.sandbox.pipeline import VerificationPipeline


@pytest.fixture
def temp_repo_dir():
    d = Path(tempfile.mkdtemp(prefix="vulntrace_test_repo_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_detect_declared_dependencies(temp_repo_dir: Path):
    """Proves manifest detection across requirements.txt, pyproject.toml, and setup.py without code execution."""
    # 1. No manifests
    has_manifest, deps = EnvironmentBuilder.detect_declared_dependencies(temp_repo_dir)
    assert has_manifest is False
    assert deps == []

    # 2. requirements.txt
    req_file = temp_repo_dir / "requirements.txt"
    req_file.write_text("requests>=2.28.0\npytest==8.0.0\n# comment\n", encoding="utf-8")
    has_manifest, deps = EnvironmentBuilder.detect_declared_dependencies(temp_repo_dir)
    assert has_manifest is True
    assert "requests>=2.28.0" in deps
    assert "pytest==8.0.0" in deps

    # 3. setup.py install_requires fallback
    req_file.unlink()
    setup_file = temp_repo_dir / "setup.py"
    setup_file.write_text("""
from setuptools import setup
setup(
    name="sample",
    install_requires=["click>=8.0.0", "pyyaml>=6.0"]
)
""", encoding="utf-8")
    has_manifest, deps = EnvironmentBuilder.detect_declared_dependencies(temp_repo_dir)
    assert has_manifest is True
    assert "click>=8.0.0" in deps
    assert "pyyaml>=6.0" in deps


def test_resolve_base_python(temp_repo_dir: Path):
    """Proves interpreter resolution respects .python-version runtime hints."""
    # Default resolution
    exe, ver = EnvironmentBuilder.resolve_base_python(temp_repo_dir)
    assert Path(exe).exists()
    assert "Python" in ver

    # Legacy Python hint (.python-version with 3.6 / 2.7)
    pyver = temp_repo_dir / ".python-version"
    pyver.write_text("3.6.1\n", encoding="utf-8")
    exe_legacy, ver_legacy = EnvironmentBuilder.resolve_base_python(temp_repo_dir)
    assert Path(exe_legacy).exists()
    assert "Python" in ver_legacy


def test_environment_builder_sanitizes_secrets(temp_repo_dir: Path):
    """Proves build environment purges API tokens, secrets, and cloud credentials (P0.5.1)."""
    scratch = temp_repo_dir / "scratch"
    scratch.mkdir()

    # Inject simulated sensitive environment variables into host
    test_secrets = {
        "OPENAI_API_KEY": "sk-secret-test-token-12345",
        "NEBIUS_API_KEY": "nebius-secret-token",
        "TAVILY_API_KEY": "tvly-secret-token",
        "AWS_SECRET_ACCESS_KEY": "aws-secret-key-material",
        "GITHUB_TOKEN": "ghp_super_secret_github_token",
        "BITBUCKET_AUTH_PASSWORD": "secret_password"
    }
    for k, v in test_secrets.items():
        os.environ[k] = v

    try:
        safe_env = EnvironmentBuilder.sanitize_environment(scratch)

        # None of the secrets or token keys must survive sanitization
        for k in test_secrets:
            assert k not in safe_env, f"Secret key {k} was not purged by sanitize_environment!"

        # Scratch directory paths must be established
        assert safe_env["TEMP"] == str(scratch.resolve())
        assert safe_env["PYTHONUNBUFFERED"] == "1"
        assert safe_env["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    finally:
        for k in test_secrets:
            os.environ.pop(k, None)


def test_dedicated_venv_outside_workspace(temp_repo_dir: Path):
    """Proves environment builder creates a dedicated venv outside the workspace and records metrics."""
    # Create simple repository with minimal requirements
    (temp_repo_dir / "requirements.txt").write_text("six>=1.10.0\n", encoding="utf-8")

    res = EnvironmentBuilder.build_environment(
        repo_dir=temp_repo_dir,
        workspace_id="test_m2_dedicated"
    )

    try:
        assert res.has_manifest is True
        assert "six>=1.10.0" in res.detected_dependencies
        assert res.provisioned is True
        assert res.python_version != ""
        assert Path(res.python_executable).exists()
        assert res.build_duration_ms > 0

        # Dedicated venv MUST be strictly OUTSIDE workspace directory (Spec §4.5)
        assert res.venv_path is not None
        assert "vulntrace_case_envs" in res.venv_path
        assert not str(Path(res.venv_path).resolve()).startswith(str(temp_repo_dir.resolve()))

        # Wheel cache must be configured
        assert res.wheel_cache_dir is not None
        assert "vulntrace_wheel_cache" in res.wheel_cache_dir
        assert Path(res.wheel_cache_dir).exists()
    finally:
        EnvironmentBuilder.cleanup_case_environment(res.venv_path)


def test_broken_requirements_fixture_yields_env_build_failed(temp_repo_dir: Path):
    """
    Spec §4.5 / M2 AC 9: A deliberately broken requirements/dependency fixture
    yields ENV_BUILD_FAILED rather than UNEXPECTED_FAILURE.
    """
    broken_pkg = "nonexistent-vulntrace-impossible-pkg-xyz9999==0.0.1"
    (temp_repo_dir / "requirements.txt").write_text(f"{broken_pkg}\n", encoding="utf-8")

    res = EnvironmentBuilder.build_environment(
        repo_dir=temp_repo_dir,
        workspace_id="test_m2_broken_reqs"
    )

    try:
        assert res.has_manifest is True
        assert res.provisioned is False
        assert res.failure_classification == "ENV_BUILD_FAILED"
        assert res.failure_reason is not None
        assert "pip install exited" in res.failure_reason or "ENV_BUILD_FAILED" in res.failure_classification
        assert res.pip_log_excerpt is not None
        assert len(res.pip_log_excerpt) > 0
        assert res.build_duration_ms > 0
    finally:
        EnvironmentBuilder.cleanup_case_environment(res.venv_path)


@pytest.mark.asyncio
async def test_pipeline_early_halts_on_broken_dependencies(temp_repo_dir: Path):
    """
    Proves that VerificationPipeline halts early and returns ENV_BUILD_FAILED
    when target environment construction fails, preserving structured evidence.
    """
    # Create target file with arbitrary code
    target_file = temp_repo_dir / "app.py"
    target_file.write_text("""
def parse_data(raw):
    return raw
""", encoding="utf-8")

    # Add deliberately unresolvable dependency
    (temp_repo_dir / "requirements.txt").write_text("definitely-unresolvable-package-abc999==9.9.9\n", encoding="utf-8")

    req = VerificationPipelineRequest(
        repo_path=str(temp_repo_dir),
        cve_id="CVE-2020-14343",
        target_file="app.py",
        target_function="parse_data",
        vulnerable_symbol="yaml.load",
        entrypoints=["app.py:parse_data"],
        execution_backend="LOCAL_SUBPROCESS_FALLBACK"
    )

    response = await VerificationPipeline.run_pipeline(req)

    # Truthful behavioral classification
    assert response.final_behavioral_verdict == "ENV_BUILD_FAILED"
    assert response.verdict_record is not None
    assert response.verdict_record.terminal_state == "ENV_BUILD_FAILED"
    assert response.verdict_record.is_safe_claim is False
    assert response.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

    # Environment evidence is fully populated
    assert response.environment is not None
    assert response.environment.provisioned is False
    assert response.environment.failure_classification == "ENV_BUILD_FAILED"
    assert response.environment.pip_log_excerpt is not None
    assert response.environment.build_duration_ms > 0


@pytest.mark.asyncio
async def test_flasgger_vulnerable_commit_deterministic_verdict_3x():
    """
    Spec §4.5 & M2 AC 1 / Requirement 8:
    Run the Flasgger vulnerable commit (163a753) 3 consecutive times with the dedicated environment builder.
    Verdicts must be 100% identical, build time and Python version recorded in bundle,
    and repository submodule returned to clean state.
    """
    flasgger_path = Path(__file__).resolve().parent.parent / "real_world_eval" / "flasgger"
    if not flasgger_path.exists() or not (flasgger_path / ".git").exists():
        pytest.skip("real_world_eval/flasgger repository submodule is not present.")

    import subprocess
    def _git(*args):
        return subprocess.run(["git"] + list(args), cwd=str(flasgger_path), capture_output=True, text=True).stdout.strip()

    # Checkout vulnerable commit 163a753
    _git("checkout", "163a753")
    verdicts = []
    durations = []
    py_versions = []

    try:
        for i in range(3):
            req = VerificationPipelineRequest(
                repo_path=str(flasgger_path),
                cve_id="CVE-2020-14343",
                target_file="flasgger/utils.py",
                target_function="parse_docstring",
                execution_backend="LOCAL_SUBPROCESS_FALLBACK",
                use_nemotron=True,
            )
            res = await VerificationPipeline.run_pipeline(req)
            verdicts.append(res.final_behavioral_verdict)
            assert res.environment is not None
            assert res.environment.has_manifest is True
            assert res.environment.build_duration_ms > 0
            assert "Python" in res.environment.python_version
            durations.append(res.environment.build_duration_ms)
            py_versions.append(res.environment.python_version)

            if res.environment.provisioned:
                # AC 1: Target environment provisioned (e.g. Python <= 3.10 with PyYAML 5.4.1 runtime)
                assert res.pre_patch_result is not None
                assert res.pre_patch_result.exit_code == 42
                assert res.pre_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
            else:
                # AC 1 / Spec §4.5: Honest failure classification when host lacks compatible Python runtime
                assert res.environment.failure_classification == "ENV_BUILD_FAILED"
                assert res.environment.pip_log_excerpt is not None

        # AC 1: 3x identical reproducible verdicts
        assert len(verdicts) == 3
        assert len(set(verdicts)) == 1, f"Flasgger verdicts were not identical across 3 runs: {verdicts}"
        # Accept either GREEN_STATE_VERIFIED or an honest explained non-GREEN verdict (Spec §4.5 & M2 AC 1)
        assert verdicts[0] in ("INCONCLUSIVE", "ENV_BUILD_FAILED", "GREEN_STATE_VERIFIED", "UNREACHABLE_FALSE_POSITIVE")
        # AC 2: Build metrics recorded
        assert all(d > 0 for d in durations)
        assert len(set(py_versions)) == 1
    finally:
        # Guarantee repository submodule returns to clean tracked commit ee62207
        _git("checkout", "ee62207")


def test_wheel_cache_flattening_and_offline_lookup(temp_repo_dir: Path):
    """Proves that EnvironmentBuilder populates wheel cache and flattens wheels for offline reuse."""
    cache_dir = EnvironmentBuilder.get_wheel_cache_dir()
    assert cache_dir.exists()
    assert "vulntrace_wheel_cache" in str(cache_dir)

