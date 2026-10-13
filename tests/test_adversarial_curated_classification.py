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

import os
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

        create_directory_link(link_to_curated, BENCHMARK_DIR)

        # The input path originates outside approved fixture roots
        assert is_curated_fixture(link_to_curated) is False
        assert is_curated_fixture(external_dir) is False

    @pytest.mark.asyncio
    async def test_external_junction_refused_by_local_subprocess(self, tmp_path):
        external_dir = tmp_path / "external_workspace"
        external_dir.mkdir()
        link_to_curated = external_dir / "aliased_curated"

        create_directory_link(link_to_curated, BENCHMARK_DIR)

        backend = LocalSubprocessBackend(unsafe_local=False)
        with pytest.raises(PermissionError) as exc_info:
            await backend.initialize_workspace(link_to_curated)
        assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)

    def test_external_junction_refused_by_backend_factory(self, tmp_path):
        external_dir = tmp_path / "external_workspace"
        external_dir.mkdir()
        link_to_curated = external_dir / "aliased_curated"

        create_directory_link(link_to_curated, BENCHMARK_DIR)

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

        create_directory_link(link_to_curated, BENCHMARK_DIR)

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
        create_directory_link(fake_benchmark, untrusted_code)

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


class TestDynamicRegistryAuthorityAmendments:
    """
    Verifies Amendments A and B for dynamic registry authority hardening.
    Amendment A:
    - Dedicated dynamic-registration validation path rejects any candidate path if either
      its original absolute path or its resolved destination lies within PROJECT_ROOT.
    - Broad in-project directories (benchmarks, tests, tests/fixtures, etc.) cannot be dynamically registered.
    - get_all_approved_roots() independently re-validates dynamic roots on every call.
    - External temporary test fixtures outside PROJECT_ROOT can register and unregister securely.

    Amendment B:
    - Canonical allowlist verification verifies that every canonical path originates from
      CANONICAL_FIXTURE_RELPATHS, exists, is a directory, cannot be redirected through symlinks
      or NTFS junctions, and resolves to its intended location inside PROJECT_ROOT.
    - Canonical fixtures are preserved and remain curated under Tier 0.
    """

    def test_dynamic_registration_rejects_broad_in_project_directories(self):
        """Dynamic registration must refuse all broad in-project directories."""
        for broad in TrustedFixtureRegistry.FORBIDDEN_BROAD_IN_PROJECT_RELPATHS:
            broad_path = PROJECT_ROOT / broad
            if broad_path.exists():
                TrustedFixtureRegistry.register_trusted_fixture(broad_path)
                try:
                    assert broad_path.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
                    assert is_curated_fixture(broad_path) is False
                finally:
                    TrustedFixtureRegistry.unregister_trusted_fixture(broad_path)

    def test_dynamic_registration_rejects_arbitrary_in_project_paths(self):
        """Dynamic registration must refuse any path within PROJECT_ROOT."""
        in_project_candidates = [
            PROJECT_ROOT / "vulntrace",
            PROJECT_ROOT / "docs",
            PROJECT_ROOT / "ui",
            PROJECT_ROOT / "real_world_eval",
            PROJECT_ROOT / "real_world_eval" / "flasgger",
            PROJECT_ROOT / "tests" / "fixtures",
        ]
        for candidate in in_project_candidates:
            if candidate.exists():
                TrustedFixtureRegistry.register_trusted_fixture(candidate)
                try:
                    assert candidate.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
                    assert is_curated_fixture(candidate) is False
                finally:
                    TrustedFixtureRegistry.unregister_trusted_fixture(candidate)

    def test_dynamic_registration_rejects_external_link_targeting_in_project_path(self, tmp_path):
        """
        External directory link (symlink/junction) pointing into PROJECT_ROOT must be rejected
        because its resolved destination lies within PROJECT_ROOT (Amendment A).
        """
        external_link = tmp_path / "link_to_benchmarks"
        create_directory_link(external_link, PROJECT_ROOT / "benchmarks")

        TrustedFixtureRegistry.register_trusted_fixture(external_link)
        try:
            assert external_link.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
            assert is_curated_fixture(external_link) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(external_link)

    def test_dynamic_revalidation_drops_deleted_dynamic_roots(self, tmp_path):
        """get_all_approved_roots() independently re-validates dynamic roots and drops deleted ones."""
        ephemeral = tmp_path / "ephemeral_fixture"
        ephemeral.mkdir()

        TrustedFixtureRegistry.register_trusted_fixture(ephemeral)
        try:
            assert ephemeral.resolve() in TrustedFixtureRegistry.get_all_approved_roots()
            assert is_curated_fixture(ephemeral) is True

            # Delete the directory from disk
            ephemeral.rmdir()

            # Dynamic revalidation should detect it is gone
            assert ephemeral.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
            assert is_curated_fixture(ephemeral) is False
        finally:
            TrustedFixtureRegistry.unregister_trusted_fixture(ephemeral)

    def test_temporary_trusted_fixture_rejects_in_project_path(self):
        """temporary_trusted_fixture must not register in-project directories."""
        broad_dir = PROJECT_ROOT / "benchmarks"
        with TrustedFixtureRegistry.temporary_trusted_fixture(broad_dir):
            assert broad_dir.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
            assert is_curated_fixture(broad_dir) is False

    def test_canonical_fixtures_intact_and_exact_count(self):
        """get_canonical_fixtures() returns exactly the 10 authorized canonical fixtures."""
        canonical = TrustedFixtureRegistry.get_canonical_fixtures()
        assert len(canonical) == 10
        for p in canonical:
            assert p.exists()
            assert p.is_dir()
            assert is_curated_fixture(p) is True
            # Existing subdirectories inside canonical fixtures inherit curated status
            for sub in p.iterdir():
                if sub.is_dir():
                    assert is_curated_fixture(sub) is True
                    break

    def test_canonical_fixtures_reject_symlink_redirection(self):
        """If a canonical fixture is intercepted/redirected via symlink or junction, it is rejected (Amendment B)."""
        with patch("vulntrace.core.backend._is_symlink_or_junction", return_value=True):
            canonical = TrustedFixtureRegistry.get_canonical_fixtures()
            assert len(canonical) == 0

    def test_canonical_fixtures_reject_path_traversal_or_absolute_paths(self):
        """Malicious relpaths with .. or absolute paths in allowlist are rejected."""
        with patch.object(
            TrustedFixtureRegistry,
            "CANONICAL_FIXTURE_RELPATHS",
            ("../outside_repo", "/etc/passwd", "benchmarks/../../outside")
        ):
            canonical = TrustedFixtureRegistry.get_canonical_fixtures()
            assert len(canonical) == 0

    def test_external_dynamic_fixture_lifecycle(self, tmp_path):
        """Legitimate external test fixtures outside PROJECT_ROOT function normally."""
        ext_repo = tmp_path / "valid_external_test_fixture"
        ext_repo.mkdir()
        subpkg = ext_repo / "subpkg"
        subpkg.mkdir()

        assert is_curated_fixture(ext_repo) is False
        assert is_curated_fixture(subpkg) is False

        with TrustedFixtureRegistry.temporary_trusted_fixture(ext_repo):
            assert ext_repo.resolve() in TrustedFixtureRegistry.get_all_approved_roots()
            assert is_curated_fixture(ext_repo) is True
            assert is_curated_fixture(subpkg) is True

        assert ext_repo.resolve() not in TrustedFixtureRegistry.get_all_approved_roots()
        assert is_curated_fixture(ext_repo) is False
        assert is_curated_fixture(subpkg) is False


class TestAncestorLinkRedirectionResistance:
    """
    Verifies that canonical fixture discovery and Tier 0 classification reject
    fixtures whose parent or intermediate ancestor directories are redirected
    via real NTFS junctions or symlinks.
    Tests run in controlled temporary project trees using scoped monkeypatching
    of PROJECT_ROOT, leaving actual repository fixtures completely untouched.
    """

    def test_real_ancestor_ntfs_junction_rejection(self, tmp_path):
        """
        Tests that an NTFS junction at the top-level fixture directory (e.g., benchmarks)
        redirected to an unapproved directory within the project tree is rejected.
        On Windows, unexpected junction creation failure fails the test.
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: NTFS junction requires Windows platform")

        proj = tmp_path / "proj"
        proj.mkdir()
        attacker_dir = proj / "attacker_dir"
        attacker_dir.mkdir()
        (attacker_dir / "contextual_reasoning").mkdir(parents=True)

        benchmarks_junction = proj / "benchmarks"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(benchmarks_junction), str(attacker_dir)],
            check=True,
            capture_output=True,
        )

        with patch("vulntrace.core.backend.PROJECT_ROOT", proj):
            canonical = TrustedFixtureRegistry.get_canonical_fixtures()
            # Redirected fixture must NOT be in canonical fixtures
            assert (attacker_dir / "contextual_reasoning").resolve() not in canonical
            assert (benchmarks_junction / "contextual_reasoning").resolve() not in canonical

            # Tier 0 classification must refuse the redirected fixture via junction path
            assert is_curated_fixture(benchmarks_junction / "contextual_reasoning") is False
            # Tier 0 classification must also refuse the target directory directly
            assert is_curated_fixture(attacker_dir / "contextual_reasoning") is False

            # Production entry point: BackendFactory refuses Tier 0
            with pytest.raises(PermissionError) as exc_info:
                BackendFactory.resolve_best_available_backend(
                    target_repo=benchmarks_junction / "contextual_reasoning",
                    prefer_container=False,
                    unsafe_local=False,
                )
            assert "requires Isolation Tier 1" in str(exc_info.value) or "requiring Isolation Tier 1" in str(exc_info.value)

            # Production entry point: LocalSubprocessBackend refuses initialization
            backend = LocalSubprocessBackend(unsafe_local=False)
            import asyncio
            with pytest.raises(PermissionError) as exc_info2:
                asyncio.run(backend.initialize_workspace(benchmarks_junction / "contextual_reasoning"))
            assert "refused non-curated repository" in str(exc_info2.value)

    def test_real_intermediate_ancestor_ntfs_junction_rejection(self, tmp_path):
        """
        Tests that an NTFS junction at an intermediate ancestor directory (e.g., tests/fixtures)
        redirected to an unapproved directory is rejected.
        On Windows, unexpected junction creation failure fails the test.
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: NTFS junction requires Windows platform")

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "tests").mkdir()
        attacker_dir = proj / "attacker_dir"
        attacker_dir.mkdir()
        (attacker_dir / "sample_repo").mkdir(parents=True)

        fixtures_junction = proj / "tests" / "fixtures"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(fixtures_junction), str(attacker_dir)],
            check=True,
            capture_output=True,
        )

        with patch("vulntrace.core.backend.PROJECT_ROOT", proj):
            canonical = TrustedFixtureRegistry.get_canonical_fixtures()
            assert (attacker_dir / "sample_repo").resolve() not in canonical
            assert is_curated_fixture(fixtures_junction / "sample_repo") is False
            assert is_curated_fixture(attacker_dir / "sample_repo") is False

    def test_real_ancestor_symlink_rejection(self, tmp_path):
        """
        Tests that an ancestor directory symlink redirected to an unapproved directory
        is rejected. On Windows, skips ONLY when explicitly denied by OS permission (WinError 1314).
        """
        proj = tmp_path / "proj"
        proj.mkdir()
        attacker_dir = proj / "attacker_dir"
        attacker_dir.mkdir()
        (attacker_dir / "contextual_reasoning").mkdir(parents=True)

        benchmarks_link = proj / "benchmarks"
        try:
            benchmarks_link.symlink_to(attacker_dir, target_is_directory=True)
        except OSError as e:
            if getattr(e, "winerror", None) == 1314:
                pytest.skip("Platform-blocked: directory symlink creation requires elevated privileges (WinError 1314)")
            raise

        with patch("vulntrace.core.backend.PROJECT_ROOT", proj):
            canonical = TrustedFixtureRegistry.get_canonical_fixtures()
            assert (attacker_dir / "contextual_reasoning").resolve() not in canonical
            assert is_curated_fixture(benchmarks_link / "contextual_reasoning") is False
            assert is_curated_fixture(attacker_dir / "contextual_reasoning") is False

    def test_real_non_redirected_control_fixture_accepted_in_temp_tree(self, tmp_path):
        """
        Verifies positive control: an authentic non-redirected canonical fixture inside
        a temporary project tree is accepted by get_canonical_fixtures and classified as curated.
        """
        proj = tmp_path / "proj"
        proj.mkdir()
        legit_dir = proj / "benchmarks" / "contextual_reasoning"
        legit_dir.mkdir(parents=True)

        with patch("vulntrace.core.backend.PROJECT_ROOT", proj):
            canonical = TrustedFixtureRegistry.get_canonical_fixtures()
            assert legit_dir.resolve() in canonical
            assert is_curated_fixture(legit_dir) is True

    def test_preresolved_redirected_path_rejected_by_backend_and_factory(self, tmp_path):
        """
        Verifies that even if a caller passes the pre-resolved target path (bypassing
        the junction in the argument string), the unapproved target is rejected.
        On Windows, unexpected junction creation failure fails the test.
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: NTFS junction requires Windows platform")

        proj = tmp_path / "proj"
        proj.mkdir()
        attacker_dir = proj / "attacker_dir"
        attacker_dir.mkdir()
        target_fixture = attacker_dir / "contextual_reasoning"
        target_fixture.mkdir(parents=True)

        benchmarks_junction = proj / "benchmarks"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(benchmarks_junction), str(attacker_dir)],
            check=True,
            capture_output=True,
        )

        with patch("vulntrace.core.backend.PROJECT_ROOT", proj):
            # Target path directly passed
            assert is_curated_fixture(target_fixture) is False

            with pytest.raises(PermissionError):
                BackendFactory.resolve_best_available_backend(
                    target_repo=target_fixture,
                    prefer_container=False,
                    unsafe_local=False,
                )

            import asyncio
            backend = LocalSubprocessBackend(unsafe_local=False)
            with pytest.raises(PermissionError):
                asyncio.run(backend.initialize_workspace(target_fixture))

    def test_simulated_python311_fallback_junction_detection(self, tmp_path):
        """
        Simulates a Python 3.11 runtime lacking Path.is_junction and os.path.isjunction APIs,
        proving that the Windows os.lstat fallback detects real NTFS junctions, accepts normal
        directories, and fails closed on metadata errors.
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: NTFS junction requires Windows platform")

        proj = tmp_path / "proj"
        proj.mkdir()
        attacker_dir = proj / "attacker_dir"
        attacker_dir.mkdir()
        (attacker_dir / "contextual_reasoning").mkdir(parents=True)

        normal_dir = proj / "normal_dir"
        normal_dir.mkdir()

        benchmarks_junction = proj / "benchmarks"
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(benchmarks_junction), str(attacker_dir)],
            check=True,
            capture_output=True,
        )

        import vulntrace.core.backend as backend_module

        # Temporarily simulate absence of Python 3.12+ is_junction APIs
        orig_path_junction = getattr(Path, "is_junction", None)
        orig_os_junction = getattr(os.path, "isjunction", None)

        try:
            if hasattr(Path, "is_junction"):
                delattr(Path, "is_junction")
            if hasattr(os.path, "isjunction"):
                delattr(os.path, "isjunction")

            # Verify that hasattr is now False in this scope
            assert not hasattr(benchmarks_junction, "is_junction")
            assert not hasattr(os.path, "isjunction")

            # 1. Fallback correctly detects the real junction via os.lstat
            assert backend_module._is_symlink_or_junction(benchmarks_junction) is True

            # 2. Normal non-reparse directory is accepted
            assert backend_module._is_symlink_or_junction(normal_dir) is False

            # 3. Non-existent / error-raising path fails closed
            assert backend_module._is_symlink_or_junction(tmp_path / "nonexistent_err") is True

            # 4. Canonical fixtures reject the ancestor junction under simulated 3.11
            with patch("vulntrace.core.backend.PROJECT_ROOT", proj):
                canonical = TrustedFixtureRegistry.get_canonical_fixtures()
                assert len(canonical) == 0
                assert is_curated_fixture(benchmarks_junction / "contextual_reasoning") is False
                assert is_curated_fixture(attacker_dir / "contextual_reasoning") is False
        finally:
            if orig_path_junction is not None:
                setattr(Path, "is_junction", orig_path_junction)
            if orig_os_junction is not None:
                setattr(os.path, "isjunction", orig_os_junction)

    def test_real_windows_python311_subprocess_verification(self, tmp_path):
        """
        Executes out-of-process verification using real Python 3.11 (py -3.11) on Windows
        against an actual NTFS junction, proving detection, canonical rejection, normal
        directory acceptance, and fail-closed behavior on metadata errors.
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: requires Windows platform")

        # Verify py -3.11 is installed and available
        try:
            subprocess.run(
                ["py", "-3.11", "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            pytest.skip(f"Platform-blocked: py -3.11 interpreter unavailable: {e}")

        # Construct verification script for out-of-process execution
        test_script = f"""
import sys
import types
import os
import pathlib
import subprocess

# Stub pydantic if missing in bare Python 3.11 interpreter
if "pydantic" not in sys.modules:
    pyd = types.ModuleType("pydantic")
    pyd.BaseModel = type("BaseModel", (), {{}})
    pyd.Field = lambda default_factory=None, **kwargs: (default_factory() if default_factory else kwargs.get("default", None))
    sys.modules["pydantic"] = pyd

sys.path.insert(0, r"{PROJECT_ROOT}")
import vulntrace.core.backend as backend

tmp_base = pathlib.Path(r"{tmp_path}")
proj = tmp_base / "proj_py311"
proj.mkdir()
attacker_dir = proj / "attacker_dir"
attacker_dir.mkdir()
(attacker_dir / "contextual_reasoning").mkdir(parents=True)

normal_dir = proj / "normal_dir"
normal_dir.mkdir()

benchmarks_junction = proj / "benchmarks"
subprocess.run(
    ["cmd", "/c", "mklink", "/J", str(benchmarks_junction), str(attacker_dir)],
    check=True,
    capture_output=True,
)

# 1. Real NTFS junction must be detected under Python 3.11
assert backend._is_symlink_or_junction(benchmarks_junction) is True, "Junction was not detected under Python 3.11!"

# 2. Normal directory must NOT be detected as symlink or junction
assert backend._is_symlink_or_junction(normal_dir) is False, "Normal directory falsely flagged under Python 3.11!"

# 3. Path metadata error / non-existent path must fail closed
assert backend._is_symlink_or_junction(tmp_base / "nonexistent_err_path") is True, "Metadata error did not fail closed!"

# 4. Canonical fixtures must reject ancestor junction
backend.PROJECT_ROOT = proj
canonical = backend.TrustedFixtureRegistry.get_canonical_fixtures()
assert len(canonical) == 0, f"Expected 0 canonical fixtures with junction ancestor, got {{len(canonical)}}"
assert backend.is_curated_fixture(benchmarks_junction / "contextual_reasoning") is False
assert backend.is_curated_fixture(attacker_dir / "contextual_reasoning") is False

# 5. Positive control: legitimate non-redirected fixture accepted
proj_ok = tmp_base / "proj_ok_py311"
proj_ok.mkdir()
legit_fixture = proj_ok / "benchmarks" / "contextual_reasoning"
legit_fixture.mkdir(parents=True)
backend.PROJECT_ROOT = proj_ok
canonical_ok = backend.TrustedFixtureRegistry.get_canonical_fixtures()
assert legit_fixture.resolve() in canonical_ok
assert backend.is_curated_fixture(legit_fixture) is True

# 6. Missing metadata fields fail closed under Python 3.11
import unittest.mock
class MockStatNoTag:
    st_mode = 0o040777
    st_file_attributes = 0x10

with unittest.mock.patch("vulntrace.core.backend.os.lstat", return_value=MockStatNoTag()):
    assert backend._is_symlink_or_junction(normal_dir) is True, "Missing st_reparse_tag did not fail closed under Python 3.11!"

class MockStatNoAttrs:
    st_mode = 0o040777
    st_reparse_tag = 0

with unittest.mock.patch("vulntrace.core.backend.os.lstat", return_value=MockStatNoAttrs()):
    assert backend._is_symlink_or_junction(normal_dir) is True, "Missing st_file_attributes did not fail closed under Python 3.11!"

print("PYTHON_311_VERIFICATION_SUCCESS")
"""

        proc = subprocess.run(
            ["py", "-3.11", "-c", test_script],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "PYTHON_311_VERIFICATION_SUCCESS" in proc.stdout

    def test_windows_reparse_missing_constant_fails_closed(self, tmp_path):
        """
        Tests that if stat.FILE_ATTRIBUTE_REPARSE_POINT is unavailable on Windows,
        _is_symlink_or_junction() fails closed by returning True (unsafe).
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: requires Windows platform")

        normal_dir = tmp_path / "normal_dir"
        normal_dir.mkdir()

        import stat
        import vulntrace.core.backend as backend_module

        orig_const = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", None)
        try:
            if hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT"):
                delattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT")
            assert not hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT")

            # Must fail closed (return True) even on an authentic normal directory
            assert backend_module._is_symlink_or_junction(normal_dir) is True
        finally:
            if orig_const is not None:
                setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", orig_const)

    def test_windows_reparse_missing_st_file_attributes_fails_closed(self, tmp_path):
        """
        Tests that if the stat struct is missing st_file_attributes on Windows,
        _is_symlink_or_junction() fails closed by returning True (unsafe).
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: requires Windows platform")

        normal_dir = tmp_path / "normal_dir"
        normal_dir.mkdir()

        import vulntrace.core.backend as backend_module

        # Mock os.lstat to return a struct lacking st_file_attributes
        class MockStatWithoutFileAttributes:
            st_mode = 0o040777
            st_reparse_tag = 0

        with patch("vulntrace.core.backend.os.lstat", return_value=MockStatWithoutFileAttributes()):
            # Must fail closed (return True)
            assert backend_module._is_symlink_or_junction(normal_dir) is True

    def test_windows_reparse_missing_st_reparse_tag_fails_closed(self, tmp_path):
        """
        Tests that if the stat struct is missing st_reparse_tag on Windows,
        _is_symlink_or_junction() fails closed by returning True (unsafe).
        """
        if sys.platform != "win32":
            pytest.skip("Platform-blocked: requires Windows platform")

        normal_dir = tmp_path / "normal_dir"
        normal_dir.mkdir()

        import vulntrace.core.backend as backend_module

        # Mock os.lstat to return a struct lacking st_reparse_tag
        class MockStatWithoutReparseTag:
            st_mode = 0o040777
            st_file_attributes = 0x10  # FILE_ATTRIBUTE_DIRECTORY

        with patch("vulntrace.core.backend.os.lstat", return_value=MockStatWithoutReparseTag()):
            # Must fail closed (return True)
            assert backend_module._is_symlink_or_junction(normal_dir) is True


class TestDependencyIntegrityEnforcement:
    """Proves that missing required project dependencies (e.g. Pydantic) fail explicitly."""

    def test_backend_import_strictly_fails_without_pydantic_in_fresh_subprocess(self):
        """
        Tests missing-Pydantic behavior in a fresh Python subprocess without relying on
        cached module state or importlib.reload. Confirms that importing vulntrace.core.backend
        fails explicitly with an ImportError/ModuleNotFoundError rather than silently using
        fallback classes.
        """
        script = f"""
import sys
# Block pydantic from importing by setting it to None in sys.modules
sys.modules['pydantic'] = None
sys.path.insert(0, r'{PROJECT_ROOT}')

try:
    import vulntrace.core.backend
    print('UNEXPECTED_IMPORT_SUCCESS')
except (ImportError, ModuleNotFoundError) as e:
    print(f'EXPECTED_IMPORT_FAILURE: {{e}}')
"""
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "EXPECTED_IMPORT_FAILURE" in proc.stdout
        assert "UNEXPECTED_IMPORT_SUCCESS" not in proc.stdout


