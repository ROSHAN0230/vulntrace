"""
Tests for VulnTrace Phase 3: Adversarial Trusted Fixture Classification Hardening.
Verifies that:
1. Arbitrary repositories containing .vulntrace_curated_fixture are refused by Tier 0.
2. Untrusted repositories beneath misleading directory names (test_*, sample_repo,
   benchmarks, pytest-*, vulntrace_*) are refused.
3. External repositories cannot gain trusted status using symlinks or NTFS junctions
   pointing to or from approved paths.
4. Unknown, ambiguous, empty, non-existent, and out-of-registry paths fail closed.
5. All legitimate registered canonical fixtures remain usable under Tier 0.
6. unsafe_local=True, --unsafe-local, and VULNTRACE_UNSAFE_LOCAL=1 cannot bypass the policy.
7. When Tier 1 is unavailable, non-curated repositories are refused unconditionally.
8. TrustedFixtureRegistry dynamic registration lifecycle functions securely.
"""

import sys
import subprocess
from pathlib import Path
from unittest.mock import patch
import tempfile
import pytest

from vulntrace.core.backend import (
    IsolationTier,
    is_curated_fixture,
    TrustedFixtureRegistry
)
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.factory import BackendFactory
from vulntrace.core.container_backend import ContainerExecutionBackend
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = PROJECT_ROOT / "benchmarks" / "contextual_reasoning"
FIXTURE_SAMPLE_REPO = PROJECT_ROOT / "tests" / "fixtures" / "sample_repo"
FLASGGER_DIR = PROJECT_ROOT / "real_world_eval" / "flasgger"
REPO_CLOUD_CONFIG = PROJECT_ROOT / "real_world_eval" / "repo_cloud_config"
COOKIECUTTER_DIR = PROJECT_ROOT / "real_world_eval" / "cookiecutter"


def create_directory_link(link_path: Path, target_path: Path) -> None:
    """Creates a directory symlink or NTFS junction cross-platform without admin rights."""
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link_path), str(target_path)],
            check=True,
            capture_output=True
        )
    else:
        link_path.symlink_to(target_path, target_is_directory=True)


class TestCuratedMarkerFileRejection:
    """Proves that containing .vulntrace_curated_fixture never grants trusted status."""

    def test_arbitrary_repo_with_curated_marker_refused_by_classifier(self, tmp_path):
        untrusted_repo = tmp_path / "arbitrary_attacker_repo"
        untrusted_repo.mkdir()
        (untrusted_repo / ".vulntrace_curated_fixture").write_text("trusted=true\n", encoding="utf-8")
        (untrusted_repo / "main.py").write_text("print('malicious')\n", encoding="utf-8")

        assert is_curated_fixture(untrusted_repo) is False

    @pytest.mark.asyncio
    async def test_arbitrary_repo_with_curated_marker_refused_by_local_subprocess(self, tmp_path):
        untrusted_repo = tmp_path / "arbitrary_attacker_repo"
        untrusted_repo.mkdir()
        (untrusted_repo / ".vulntrace_curated_fixture").write_text("curated\n", encoding="utf-8")

        backend = LocalSubprocessBackend(unsafe_local=False)
        with pytest.raises(PermissionError) as exc_info:
            await backend.initialize_workspace(untrusted_repo)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)
        assert "strictly restricted to curated developer fixtures" in str(exc_info.value)

    def test_arbitrary_repo_with_curated_marker_refused_by_backend_factory(self, tmp_path):
        untrusted_repo = tmp_path / "arbitrary_attacker_repo"
        untrusted_repo.mkdir()
        (untrusted_repo / ".vulntrace_curated_fixture").write_text("curated\n", encoding="utf-8")

        with pytest.raises(PermissionError) as exc_info:
            BackendFactory.resolve_best_available_backend(
                target_repo=untrusted_repo,
                prefer_container=False,
                unsafe_local=False
            )
        assert "is a real/non-curated codebase requiring Isolation Tier 1" in str(exc_info.value)


class TestMisleadingDirectoryNamesRejection:
    """Proves that parent names or substrings like benchmarks, test_, sample_repo do not grant trust."""

    @pytest.mark.parametrize("deceptive_name", [
        "test_malicious_suite",
        "sample_repo",
        "benchmarks",
        "pytest-run-adversarial",
        "vulntrace_exploit_fixture",
        "synthetic_benchmark",
        "dead_code_service",
        "tmp_path_deceptive",
    ])
    def test_untrusted_repo_with_deceptive_directory_name_refused(self, tmp_path, deceptive_name):
        deceptive_dir = tmp_path / deceptive_name
        deceptive_dir.mkdir(parents=True, exist_ok=True)
        (deceptive_dir / "app.py").write_text("print('untrusted')\n", encoding="utf-8")

        assert is_curated_fixture(deceptive_dir) is False

    @pytest.mark.parametrize("deceptive_name", [
        "test_suite_exploit",
        "benchmarks",
        "sample_repo",
        "pytest-12345",
    ])
    @pytest.mark.asyncio
    async def test_deceptive_named_repo_refused_by_local_subprocess(self, tmp_path, deceptive_name):
        deceptive_dir = tmp_path / deceptive_name
        deceptive_dir.mkdir(parents=True, exist_ok=True)

        backend = LocalSubprocessBackend(unsafe_local=False)
        with pytest.raises(PermissionError) as exc_info:
            await backend.initialize_workspace(deceptive_dir)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)

    def test_external_directory_mimicking_benchmark_subpath_refused(self, tmp_path):
        """External temp dir creating benchmarks/contextual_reasoning path hierarchy is refused."""
        fake_bench = tmp_path / "benchmarks" / "contextual_reasoning"
        fake_bench.mkdir(parents=True)
        (fake_bench / "service.py").write_text("print('fake')\n", encoding="utf-8")

        assert is_curated_fixture(fake_bench) is False


class TestSymlinkAndJunctionAliasResistance:
    """Proves that external repositories cannot alias into approved fixtures via junctions or symlinks."""

    def test_external_repo_junction_pointing_to_approved_fixture_refused(self, tmp_path):
        """An external link pointing to a canonical benchmark is refused because input path is external."""
        external_dir = tmp_path / "external_workspace"
        external_dir.mkdir()
        link_to_curated = external_dir / "aliased_curated"

        try:
            create_directory_link(link_to_curated, BENCHMARK_DIR)
        except Exception as e:
            pytest.skip(f"Junction/symlink creation unavailable in environment: {e}")

        # The input path originates outside approved fixture roots
        assert is_curated_fixture(link_to_curated) is False
        assert is_curated_fixture(external_dir) is False

    @pytest.mark.asyncio
    async def test_external_junction_refused_by_local_subprocess(self, tmp_path):
        external_dir = tmp_path / "external_workspace"
        external_dir.mkdir()
        link_to_curated = external_dir / "aliased_curated"

        try:
            create_directory_link(link_to_curated, BENCHMARK_DIR)
        except Exception as e:
            pytest.skip(f"Junction/symlink creation unavailable: {e}")

        backend = LocalSubprocessBackend(unsafe_local=False)
        with pytest.raises(PermissionError) as exc_info:
            await backend.initialize_workspace(link_to_curated)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)

    def test_external_junction_refused_by_backend_factory(self, tmp_path):
        external_dir = tmp_path / "external_workspace"
        external_dir.mkdir()
        link_to_curated = external_dir / "aliased_curated"

        try:
            create_directory_link(link_to_curated, BENCHMARK_DIR)
        except Exception as e:
            pytest.skip(f"Junction/symlink creation unavailable: {e}")

        with pytest.raises(PermissionError) as exc_info:
            BackendFactory.resolve_best_available_backend(
                target_repo=link_to_curated,
                prefer_container=False,
                unsafe_local=False
            )
        assert "is a real/non-curated codebase requiring Isolation Tier 1" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_external_junction_refused_by_verification_pipeline(self, tmp_path):
        """Pipeline entry point must refuse external symlinks or junctions to approved fixtures under Tier 0."""
        external_dir = tmp_path / "external_workspace"
        external_dir.mkdir()
        link_to_curated = external_dir / "aliased_curated"

        try:
            create_directory_link(link_to_curated, BENCHMARK_DIR)
        except Exception as e:
            pytest.skip(f"Junction/symlink creation unavailable: {e}")

        req = VerificationPipelineRequest(
            repo_path=str(link_to_curated),
            cve_id="CVE-2020-14343",
            target_file="service/custom_loader.py",
            target_function="load_config",
            vulnerable_symbol="yaml.load",
            execution_backend="LOCAL_SUBPROCESS_FALLBACK"
        )
        with pytest.raises(PermissionError) as exc_info:
            await VerificationPipeline.run_pipeline(req)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)

    def test_symlink_with_approved_name_pointing_to_untrusted_repo_refused(self, tmp_path):
        """A link with an approved-looking name pointing to untrusted code is refused."""
        untrusted_code = tmp_path / "untrusted_payload"
        untrusted_code.mkdir()
        (untrusted_code / "exploit.py").write_text("# payload\n", encoding="utf-8")

        fake_benchmark = tmp_path / "benchmarks_contextual_reasoning"
        try:
            create_directory_link(fake_benchmark, untrusted_code)
        except Exception as e:
            pytest.skip(f"Junction/symlink creation unavailable: {e}")

        assert is_curated_fixture(fake_benchmark) is False


class TestUnknownAndAmbiguousPathsFailClosed:
    """Proves that non-existent, ambiguous, None, empty, or real-world paths fail closed."""

    def test_none_path_refused(self):
        assert is_curated_fixture(None) is False

    def test_empty_and_whitespace_paths_refused(self):
        assert is_curated_fixture("") is False
        assert is_curated_fixture("   ") is False

    def test_nonexistent_paths_refused(self):
        assert is_curated_fixture(Path("/nonexistent/bogus/path/xyz987")) is False
        assert is_curated_fixture(PROJECT_ROOT / "benchmarks" / "nonexistent_scenario") is False

    def test_invalid_types_refused(self):
        assert is_curated_fixture(12345) is False
        assert is_curated_fixture(True) is False
        assert is_curated_fixture([]) is False
        assert is_curated_fixture(object()) is False

    def test_real_world_eval_submodules_strictly_refused(self):
        """Real-world repositories must unconditionally fail closed under Tier 0."""
        assert is_curated_fixture(FLASGGER_DIR) is False
        assert is_curated_fixture(REPO_CLOUD_CONFIG) is False
        assert is_curated_fixture(COOKIECUTTER_DIR) is False

    def test_regular_files_inside_fixture_refused(self):
        """Files rather than directories must never be classified as repository fixtures."""
        file_path = BENCHMARK_DIR / "service" / "custom_loader.py"
        assert file_path.exists() and file_path.is_file()
        assert is_curated_fixture(file_path) is False

    def test_parent_fixtures_dir_itself_refused(self):
        """Parent directories containing fixtures must never independently qualify for Tier 0."""
        assert is_curated_fixture(PROJECT_ROOT / "tests" / "fixtures") is False
        assert is_curated_fixture(PROJECT_ROOT / "benchmarks") is False
        assert is_curated_fixture(PROJECT_ROOT) is False

    def test_backend_factory_refuses_forced_tier0_on_none_when_unspecified(self):
        """BackendFactory allows unspecified repo under force_tier but locks backend."""
        backend = BackendFactory.resolve_best_available_backend(
            force_tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            target_repo=None
        )
        assert getattr(backend, "unsafe_local", False) is False

    def test_backend_factory_refuses_forced_tier0_on_untrusted_repo(self, tmp_path):
        untrusted = tmp_path / "untrusted"
        untrusted.mkdir()
        with pytest.raises(PermissionError) as exc_info:
            BackendFactory.resolve_best_available_backend(
                force_tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
                target_repo=untrusted
            )
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)


class TestLegitimateRegisteredFixturesRemainUsable:
    """Proves all canonical registered fixtures qualify for Tier 0 and execute cleanly."""

    CANONICAL_FIXTURES = [
        PROJECT_ROOT / "benchmarks" / "contextual_reasoning",
        PROJECT_ROOT / "benchmarks" / "deep_callchain",
        PROJECT_ROOT / "benchmarks" / "unreachable_dead_code",
        PROJECT_ROOT / "benchmarks" / "regression_sensitive",
        PROJECT_ROOT / "benchmarks" / "inconclusive_guard",
        PROJECT_ROOT / "tests" / "fixtures" / "sample_repo",
        PROJECT_ROOT / "tests" / "fixtures" / "deserialization" / "pickle_fixed",
        PROJECT_ROOT / "tests" / "fixtures" / "deserialization" / "pickle_vulnerable",
        PROJECT_ROOT / "tests" / "fixtures" / "deserialization" / "yaml_fixed",
        PROJECT_ROOT / "tests" / "fixtures" / "deserialization" / "yaml_vulnerable",
    ]

    @pytest.mark.parametrize("fixture_path", CANONICAL_FIXTURES)
    def test_canonical_fixture_classified_as_curated(self, fixture_path):
        assert fixture_path.exists(), f"Canonical fixture missing: {fixture_path}"
        assert is_curated_fixture(fixture_path) is True

    @pytest.mark.parametrize("fixture_path", CANONICAL_FIXTURES)
    def test_backend_factory_permits_canonical_fixture(self, fixture_path):
        backend = BackendFactory.resolve_best_available_backend(
            target_repo=fixture_path,
            prefer_container=False,
            unsafe_local=False
        )
        assert backend.capabilities.tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK

    @pytest.mark.asyncio
    async def test_local_subprocess_initializes_canonical_fixture(self):
        backend = LocalSubprocessBackend(unsafe_local=False)
        ws_id = await backend.initialize_workspace(FIXTURE_SAMPLE_REPO)
        try:
            assert Path(ws_id).exists()
            assert (Path(ws_id) / "service.py").exists()
        finally:
            await backend.cleanup_workspace(ws_id)


class TestUnsafeLocalOverridesCannotBypassPolicy:
    """Proves that unsafe_local=True, --unsafe-local, and env var overrides cannot bypass trust."""

    @pytest.mark.asyncio
    async def test_direct_backend_refuses_even_with_unsafe_local_true(self, tmp_path):
        untrusted = tmp_path / "untrusted_repo"
        untrusted.mkdir()

        backend = LocalSubprocessBackend(unsafe_local=True)
        with pytest.raises(PermissionError) as exc_info:
            await backend.initialize_workspace(untrusted)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)
        assert "Unsafe-local overrides are prohibited" in str(exc_info.value)

    def test_backend_factory_refuses_even_with_unsafe_local_true(self, tmp_path):
        untrusted = tmp_path / "untrusted_repo"
        untrusted.mkdir()

        with pytest.raises(PermissionError) as exc_info:
            BackendFactory.resolve_best_available_backend(
                target_repo=untrusted,
                prefer_container=False,
                unsafe_local=True
            )
        assert "is a real/non-curated codebase requiring Isolation Tier 1" in str(exc_info.value)
        assert "unsafe_local overrides are prohibited" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_env_override_prohibited_in_direct_backend(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VULNTRACE_UNSAFE_LOCAL", "1")
        untrusted = tmp_path / "untrusted_repo"
        untrusted.mkdir()

        backend = LocalSubprocessBackend(unsafe_local=False)
        with pytest.raises(PermissionError) as exc_info:
            await backend.initialize_workspace(untrusted)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)

    def test_env_override_prohibited_in_factory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VULNTRACE_UNSAFE_LOCAL", "1")
        untrusted = tmp_path / "untrusted_repo"
        untrusted.mkdir()

        with pytest.raises(PermissionError) as exc_info:
            BackendFactory.resolve_best_available_backend(
                target_repo=untrusted,
                prefer_container=False,
                unsafe_local=False
            )
        assert "is a real/non-curated codebase requiring Isolation Tier 1" in str(exc_info.value)


class TestContainerUnavailableFailsClosed:
    """Proves that when Tier 1 is unavailable, non-curated repositories are refused unconditionally."""

    def test_factory_fails_closed_when_container_unavailable(self, tmp_path):
        untrusted = tmp_path / "untrusted_repo"
        untrusted.mkdir()

        with patch.object(ContainerExecutionBackend, "is_available", return_value=False):
            with pytest.raises(PermissionError) as exc_info:
                BackendFactory.resolve_best_available_backend(
                    target_repo=untrusted,
                    prefer_container=True,
                    unsafe_local=False
                )
            assert "is a real/non-curated codebase requiring Isolation Tier 1" in str(exc_info.value)
            assert "Refusing uncontained execution on host." in str(exc_info.value)

    def test_factory_fails_closed_when_container_unavailable_even_with_unsafe_local(self, tmp_path):
        untrusted = tmp_path / "untrusted_repo"
        untrusted.mkdir()

        with patch.object(ContainerExecutionBackend, "is_available", return_value=False):
            with pytest.raises(PermissionError) as exc_info:
                BackendFactory.resolve_best_available_backend(
                    target_repo=untrusted,
                    prefer_container=True,
                    unsafe_local=True
                )
            assert "is a real/non-curated codebase requiring Isolation Tier 1" in str(exc_info.value)
            assert "unsafe_local overrides are prohibited" in str(exc_info.value)


class TestTrustedFixtureRegistryLifecycle:
    """Verifies that TrustedFixtureRegistry dynamic registration and lifecycle operate securely."""

    def test_dynamic_registration_and_unregistration(self, tmp_path):
        custom_fixture = tmp_path / "my_custom_fixture"
        custom_fixture.mkdir()

        assert is_curated_fixture(custom_fixture) is False

        TrustedFixtureRegistry.register_trusted_fixture(custom_fixture)
        try:
            assert is_curated_fixture(custom_fixture) is True
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(custom_fixture)

        assert is_curated_fixture(custom_fixture) is False

    def test_temporary_trusted_fixture_context_manager(self, tmp_path):
        custom_fixture = tmp_path / "ctx_fixture"
        custom_fixture.mkdir()

        assert is_curated_fixture(custom_fixture) is False

        with TrustedFixtureRegistry.temporary_trusted_fixture(custom_fixture):
            assert is_curated_fixture(custom_fixture) is True

        assert is_curated_fixture(custom_fixture) is False

    def test_forbidden_roots_cannot_be_trusted_even_if_registered(self):
        """Even if someone attempts to register FLASGGER_DIR, is_curated_fixture refuses it."""
        TrustedFixtureRegistry.register_trusted_fixture(FLASGGER_DIR)
        try:
            assert is_curated_fixture(FLASGGER_DIR) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(FLASGGER_DIR)

    def test_registering_filesystem_root_refused(self, tmp_path):
        """Registering filesystem root (C:/ or /) must be refused and not grant trust to external repos."""
        anchor = Path(PROJECT_ROOT.anchor)
        TrustedFixtureRegistry.register_trusted_fixture(anchor)
        try:
            assert is_curated_fixture(anchor) is False
            assert is_curated_fixture(tmp_path) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(anchor)

    def test_registering_system_tempdir_refused(self, tmp_path):
        """Registering system temp directory must be refused and not grant trust to arbitrary temp repos."""
        temp_dir = Path(tempfile.gettempdir())
        TrustedFixtureRegistry.register_trusted_fixture(temp_dir)
        try:
            assert is_curated_fixture(temp_dir) is False
            assert is_curated_fixture(tmp_path) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(temp_dir)

    def test_registering_project_root_refused(self):
        """Registering project root must be refused and not grant trust to the entire repository."""
        TrustedFixtureRegistry.register_trusted_fixture(PROJECT_ROOT)
        try:
            assert is_curated_fixture(PROJECT_ROOT) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(PROJECT_ROOT)
