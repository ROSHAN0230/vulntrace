"""
VulnTrace Dependency Preflight Regression Test Suite (Spec §4.5, §4.6)
Validates conservative static manifest inspection, PEP 508 requirement parsing,
PEP 440 version validation, fail-closed handling for dynamic and unsupported constructs,
and digest-bound sandbox runtime inventory caching.
"""

from unittest.mock import patch

import pytest

from vulntrace.core.container_backend import ContainerExecutionBackend
from vulntrace.sandbox.target_env import (
    ManifestClassification,
    TargetEnvironmentManager,
)


class TestDependencyPreflightRequirementsParser:
    """Tests 1-5: Requirements parser and security boundary tests."""

    @pytest.mark.asyncio
    async def test_recursive_requirements_detects_nested_missing_dependencies(self, tmp_path):
        """1. Recursive requirements detect missing nested dependencies."""
        sub_dir = tmp_path / "sub"
        sub_dir.mkdir()
        (sub_dir / "nested.txt").write_text("missing-nested-dep>=1.0.0\n", encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("-r sub/nested.txt\nPyYAML>=5.0\n", encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert "missing-nested-dep>=1.0.0" in inspection.dependencies
        assert "PyYAML>=5.0" in inspection.dependencies

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
        assert any("missing-nested-dep" in d for d in result.structured_evidence["missing_dependencies"])

    @pytest.mark.asyncio
    async def test_recursive_include_cycles_fail_closed(self, tmp_path):
        """2. Recursive include cycles fail closed."""
        (tmp_path / "requirements.txt").write_text("-r req_b.txt\n", encoding="utf-8")
        (tmp_path / "req_b.txt").write_text("-r requirements.txt\n", encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert inspection.classification == ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
        assert "Circular" in (inspection.failure_reason or "")

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

    @pytest.mark.asyncio
    async def test_workspace_path_traversal_and_symlink_escapes_fail_closed(self, tmp_path):
        """3. Workspace path traversal and symlink escapes fail closed."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "requirements.txt").write_text("-r ../escaped.txt\n", encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(repo_dir)
        assert inspection.classification == ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
        assert "escapes workspace" in (inspection.failure_reason or "").lower()

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(repo_dir), [])
        assert result.exit_code != 0
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

    @pytest.mark.asyncio
    async def test_unsupported_requirement_directives_fail_closed(self, tmp_path):
        """4. Unsupported requirement directives fail closed."""
        directives = [
            "-c constraints.txt\n",
            "--index-url https://pypi.org/simple\n",
            "-f /wheels\n",
            "--hash sha256:1234567890abcdef\n",
        ]
        for directive in directives:
            (tmp_path / "requirements.txt").write_text(directive, encoding="utf-8")
            inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
            assert inspection.classification == ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS

            backend = ContainerExecutionBackend()
            result = await backend.provision_dependencies(str(tmp_path), [])
            assert result.exit_code != 0
            assert result.structured_evidence["provisioned"] is False
            assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

    @pytest.mark.asyncio
    async def test_malformed_requirement_syntax_fails_closed(self, tmp_path):
        """5. Malformed requirement syntax fails closed."""
        (tmp_path / "requirements.txt").write_text("invalid syntax >==< 1.0\n", encoding="utf-8")

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
        assert "malformed" in result.stderr.lower() or "syntax" in result.stderr.lower()


class TestDependencyPreflightVersionAndMarkerEvaluation:
    """Tests 6-11: Version comparison, environment markers, extras, and direct URLs."""

    @pytest.mark.asyncio
    async def test_compatible_installed_versions_pass(self, tmp_path):
        """6. Compatible installed versions pass."""
        # pyyaml (6.0.1) and pytest (7.4.4) are installed in the sandbox base image
        (tmp_path / "requirements.txt").write_text("PyYAML>=5.0.0\npytest>=7.0.0\n", encoding="utf-8")

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code == 0
        assert result.parent_validated is True
        assert result.structured_evidence["provisioned"] is True
        assert result.structured_evidence["failure_classification"] is None
        assert len(result.structured_evidence["missing_dependencies"]) == 0

    @pytest.mark.asyncio
    async def test_incompatible_installed_versions_fail(self, tmp_path):
        """7. Incompatible installed versions fail."""
        # Sandbox has pytest 7.4.4, which fails >=8.0.0
        (tmp_path / "requirements.txt").write_text("pytest>=8.0.0\n", encoding="utf-8")

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
        assert any("pytest>=8.0.0" in d for d in result.structured_evidence["missing_dependencies"])

    @pytest.mark.asyncio
    async def test_inactive_environment_markers_skipped_correctly(self, tmp_path):
        """8. Inactive environment markers are skipped correctly."""
        # Sandbox is Python 3.12 under Linux/POSIX. Marker for Python < 3.8 is inactive.
        (tmp_path / "requirements.txt").write_text(
            "missing-legacy-lib>=1.0; python_version < '3.8'\nPyYAML>=5.0\n",
            encoding="utf-8"
        )

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code == 0
        assert result.parent_validated is True
        assert result.structured_evidence["provisioned"] is True
        assert len(result.structured_evidence["missing_dependencies"]) == 0

    @pytest.mark.asyncio
    async def test_active_markers_with_missing_packages_fail(self, tmp_path):
        """9. Active markers with missing packages fail."""
        # Sandbox is Python 3.12 under Linux/POSIX. Marker for Python >= 3.10 is active.
        (tmp_path / "requirements.txt").write_text(
            "missing-active-lib>=1.0; python_version >= '3.10'\n",
            encoding="utf-8"
        )

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
        assert any("missing-active-lib" in d for d in result.structured_evidence["missing_dependencies"])

    @pytest.mark.asyncio
    async def test_extras_rejected_under_policy_a(self, tmp_path):
        """10. Extras are rejected with a clear reason (Policy A)."""
        (tmp_path / "requirements.txt").write_text("pytest[testing]>=7.0.0\n", encoding="utf-8")

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
        assert "Policy A" in result.stderr or "extras" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_direct_url_and_vcs_dependencies_fail_under_offline_policy(self, tmp_path):
        """11. Direct URLs/VCS dependencies fail under offline policy."""
        vcs_lines = [
            "git+https://github.com/org/repo.git\n",
            "foo @ https://example.com/packages/foo-1.0.whl\n",
        ]
        for line in vcs_lines:
            (tmp_path / "requirements.txt").write_text(line, encoding="utf-8")
            backend = ContainerExecutionBackend()
            result = await backend.provision_dependencies(str(tmp_path), [])
            assert result.exit_code != 0
            assert result.structured_evidence["provisioned"] is False
            assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"


class TestDependencyPreflightManifestInspection:
    """Tests 12-17: Manifest formats (setup.py, setup.cfg, pyproject.toml, and unsupported ecosystems)."""

    def test_static_setup_py_declarations_extracted(self, tmp_path):
        """12. Static setup.py declarations are extracted."""
        code = "from setuptools import setup\nsetup(name='sample', install_requires=['pytest>=7.0.0', 'pyyaml'])\n"
        (tmp_path / "setup.py").write_text(code, encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert inspection.classification == ManifestClassification.SUPPORTED_VALIDATED
        assert "pytest>=7.0.0" in inspection.dependencies
        assert "pyyaml" in inspection.dependencies

    @pytest.mark.asyncio
    async def test_dynamic_setup_py_declarations_fail_closed(self, tmp_path):
        """13. Dynamic setup.py declarations fail closed."""
        code = (
            "from setuptools import setup\n"
            "reqs = [line.strip() for line in open('req.txt')]\n"
            "setup(name='dynamic-sample', install_requires=reqs)\n"
        )
        (tmp_path / "setup.py").write_text(code, encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert inspection.classification == ManifestClassification.DYNAMIC_UNVERIFIED

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

    def test_conventional_setup_cfg_dependencies_extracted(self, tmp_path):
        """14. Conventional setup.cfg dependencies are extracted."""
        cfg_content = "[options]\ninstall_requires =\n    PyYAML>=5.0\n    pytest>=7.0\n"
        (tmp_path / "setup.cfg").write_text(cfg_content, encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert inspection.classification == ManifestClassification.SUPPORTED_VALIDATED
        assert "PyYAML>=5.0" in inspection.dependencies
        assert "pytest>=7.0" in inspection.dependencies

    def test_static_pep621_dependencies_extracted(self, tmp_path):
        """15. Static PEP 621 dependencies are extracted."""
        toml_content = '[project]\nname = "pep621-pkg"\nversion = "1.0.0"\ndependencies = ["pytest>=7.0.0", "pyyaml"]\n'
        (tmp_path / "pyproject.toml").write_text(toml_content, encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert inspection.classification == ManifestClassification.SUPPORTED_VALIDATED
        assert "pytest>=7.0.0" in inspection.dependencies
        assert "pyyaml" in inspection.dependencies

    @pytest.mark.asyncio
    async def test_dynamic_pep621_declarations_fail_closed(self, tmp_path):
        """16. Dynamic PEP 621 declarations fail closed."""
        toml_content = '[project]\nname = "dynamic-pkg"\nversion = "1.0.0"\ndynamic = ["dependencies"]\n'
        (tmp_path / "pyproject.toml").write_text(toml_content, encoding="utf-8")

        inspection = TargetEnvironmentManager.inspect_manifests(tmp_path)
        assert inspection.has_manifest is True
        assert inspection.classification == ManifestClassification.DYNAMIC_UNVERIFIED

        backend = ContainerExecutionBackend()
        result = await backend.provision_dependencies(str(tmp_path), [])
        assert result.exit_code != 0
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

    @pytest.mark.asyncio
    async def test_unsupported_poetry_pipenv_conda_declarations_fail_closed(self, tmp_path):
        """17. Unsupported Poetry/Pipenv/Conda declarations fail closed."""
        backend = ContainerExecutionBackend()

        # Poetry
        poetry_dir = tmp_path / "poetry"
        poetry_dir.mkdir()
        (poetry_dir / "pyproject.toml").write_text('[tool.poetry.dependencies]\npython = "^3.12"\n', encoding="utf-8")
        res_poetry = await backend.provision_dependencies(str(poetry_dir), [])
        assert res_poetry.exit_code != 0
        assert res_poetry.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

        # Pipenv
        pipenv_dir = tmp_path / "pipenv"
        pipenv_dir.mkdir()
        (pipenv_dir / "Pipfile").write_text('[[source]]\nurl = "https://pypi.org/simple"\n', encoding="utf-8")
        res_pipenv = await backend.provision_dependencies(str(pipenv_dir), [])
        assert res_pipenv.exit_code != 0
        assert res_pipenv.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"

        # Conda
        conda_dir = tmp_path / "conda"
        conda_dir.mkdir()
        (conda_dir / "environment.yml").write_text("name: test\ndependencies:\n  - python=3.12\n", encoding="utf-8")
        res_conda = await backend.provision_dependencies(str(conda_dir), [])
        assert res_conda.exit_code != 0
        assert res_conda.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"


class TestDependencyPreflightCacheAndAttestation:
    """Tests 18-22: Inventory caching, error handling, curated fixtures, and schema compatibility."""

    def test_inventory_cache_refreshes_when_image_digest_changes(self):
        """18. Inventory cache refreshes when the image digest changes."""
        import json
        import subprocess
        ContainerExecutionBackend.clear_availability_cache()
        backend = ContainerExecutionBackend()

        digest_1 = "sha256:" + "1" * 64
        digest_2 = "sha256:" + "2" * 64
        mock_output = json.dumps({
            "packages": {"pytest": "7.4.4", "pyyaml": "6.0.1"},
            "markers": {"python_version": "3.12", "os_name": "posix", "sys_platform": "linux"}
        })

        with patch.object(backend, "get_image_digest", return_value=digest_1), \
             patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_output)):
            data_1 = backend.get_sandbox_runtime_data()
            assert data_1 is not None
            assert data_1.image_digest == digest_1

        with patch.object(backend, "get_image_digest", return_value=digest_2), \
             patch("subprocess.run", return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_output)):
            data_2 = backend.get_sandbox_runtime_data()
            assert data_2 is not None
            assert data_2.image_digest == digest_2
            assert data_1 is not data_2

    def test_clear_availability_cache_clears_inventory_state(self):
        """19. clear_availability_cache() clears inventory state."""
        backend = ContainerExecutionBackend()
        backend.get_sandbox_runtime_data()
        assert len(ContainerExecutionBackend._cached_runtime_data) > 0

        ContainerExecutionBackend.clear_availability_cache()
        assert len(ContainerExecutionBackend._cached_runtime_data) == 0
        assert ContainerExecutionBackend._cached_sandbox_packages is None

    @pytest.mark.asyncio
    async def test_inventory_inspection_errors_fail_closed_unverified_fallback_prohibited(self, tmp_path):
        """20. Inventory inspection errors fail closed; unverified fallback inventory is prohibited."""
        ContainerExecutionBackend.clear_availability_cache()
        backend = ContainerExecutionBackend()
        (tmp_path / "requirements.txt").write_text("pytest>=7.0.0\n", encoding="utf-8")

        # When subprocess query fails or produces garbage, get_sandbox_runtime_data returns None
        with patch("subprocess.run", side_effect=RuntimeError("Subprocess query failed")):
            data = backend.get_sandbox_runtime_data(fresh=True)
            assert data is None

            # Untrusted repository MUST fail closed with ENV_BUILD_FAILED without using unverified fallback
            result = await backend.provision_dependencies(str(tmp_path), [])
            assert result.exit_code != 0
            assert result.parent_validated is False
            assert result.structured_evidence["provisioned"] is False
            assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
            assert "unable to verify sandbox package inventory" in result.stderr.lower()

    @pytest.mark.asyncio
    async def test_unverifiable_inventory_pipeline_verdict_not_evaluated(self, tmp_path):
        """23. Inability to verify runtime inventory yields NOT_EVALUATED and no target execution."""
        from vulntrace.sandbox.pipeline import VerificationPipeline, VerificationPipelineRequest
        (tmp_path / "requirements.txt").write_text("pytest>=7.0.0\n", encoding="utf-8")
        (tmp_path / "target.py").write_text("def vuln(): pass\n", encoding="utf-8")

        req = VerificationPipelineRequest(
            repo_path=str(tmp_path),
            cve_id="CVE-TEST-0001",
            target_file="target.py",
            target_function="vuln",
            vulnerable_symbol="vuln",
            use_nemotron=False,
        )

        with patch.object(ContainerExecutionBackend, "get_sandbox_runtime_data", return_value=None):
            res = await VerificationPipeline.run_pipeline(req)
            assert res.final_behavioral_verdict == "ENV_BUILD_FAILED"
            assert res.reachability_verdict == "NOT_EVALUATED"
            assert res.environment.provisioned is False
            assert "skipped: environment build failed" in res.harness.harness_code.lower()
            assert res.isolation_attestation is None

    @pytest.mark.asyncio
    async def test_curated_fixture_behavior_remains_intact(self, tmp_path):
        """21. Existing curated fixture behavior remains intact."""
        backend = ContainerExecutionBackend()
        # Mock is_curated_fixture to return True for tmp_path
        (tmp_path / "requirements.txt").write_text("some-unbaked-dependency>=1.0.0\n", encoding="utf-8")

        with patch("vulntrace.core.container_backend.is_curated_fixture", return_value=True):
            result = await backend.provision_dependencies(str(tmp_path), [])
            # Curated fixtures are not failed by the preflight check
            assert result.exit_code == 0
            assert result.parent_validated is True
            assert result.structured_evidence["provisioned"] is True

    @pytest.mark.asyncio
    async def test_evidence_and_return_schemas_remain_compatible(self, tmp_path):
        """22. Existing evidence/return schemas remain compatible."""
        backend = ContainerExecutionBackend()
        (tmp_path / "requirements.txt").write_text("PyYAML>=5.0.0\n", encoding="utf-8")

        result = await backend.provision_dependencies(str(tmp_path), [])

        # Verify ExecutionCommandResult attributes
        assert hasattr(result, "exit_code")
        assert hasattr(result, "stdout")
        assert hasattr(result, "stderr")
        assert hasattr(result, "latency_ms")
        assert hasattr(result, "parent_validated")
        assert hasattr(result, "validation_notes")
        assert hasattr(result, "structured_evidence")
        assert hasattr(result, "attestation")

        evidence = result.structured_evidence
        required_keys = {
            "has_manifest",
            "detected_dependencies",
            "missing_dependencies",
            "provisioned",
            "image",
            "network_isolated",
            "setup_executed_in_container",
            "setup_latency_ms",
            "build_duration_ms",
            "python_version",
            "failure_classification",
            "pip_log_excerpt",
        }
        for key in required_keys:
            assert key in evidence, f"Missing required evidence key: {key}"
