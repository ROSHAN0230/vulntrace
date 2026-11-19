"""
Tests for VulnTrace P0.6 Container Execution Backend & Host Isolation Sentinels
Verifies:
1. OCI Container substrate capabilities and honest security contract.
2. Host Isolation Sentinels: Host files outside the mounted workspace are completely inaccessible.
3. Native Network Denial: Raw socket connections are denied at the kernel level (Errno 101 Network unreachable).
4. Process and Resource Limits: Cgroup pids-limit prevents runaway fork-bombing.
5. Execution Attestation: Parent-generated cryptographic attestation record.
6. BackendFactory: Automatic resolution and tier override.
7. Full Verification Pipeline: End-to-end execution under OCI_CONTAINER_ISOLATED tier.
"""

import json
import tempfile
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch

from vulntrace.core.backend import IsolationTier
from vulntrace.core.container_backend import ContainerExecutionBackend
from vulntrace.core.factory import BackendFactory
from vulntrace.models import VerificationPipelineRequest
from vulntrace.sandbox.pipeline import VerificationPipeline

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning"
DEADCODE_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "unreachable_dead_code"

pytestmark = pytest.mark.container


@pytest.fixture(scope="module")
def container_backend():
    """Provides a container execution backend if Podman is available; skips otherwise."""
    backend = ContainerExecutionBackend()
    if not backend.is_available():
        pytest.skip("OCI Container execution backend (Podman/crun) is not available on this host.")
    return backend


class TestContainerBackendCapabilities:
    """Verifies OCI container capabilities contract."""

    def test_container_capabilities_contract(self, container_backend):
        caps = container_backend.capabilities
        assert caps.tier == IsolationTier.OCI_CONTAINER_ISOLATED
        assert caps.filesystem_jailed is True
        assert caps.host_fs_hidden is True
        assert caps.network_kernel_denied is True
        assert caps.process_tree_contained is True
        assert caps.resource_limits_enforced is True
        assert caps.host_identity_isolated is True
        assert caps.hardware_virtualized is False
        assert len(caps.boundary_caveats) >= 1


class TestHostIsolationSentinels:
    """
    Host Isolation Sentinels (P0.6 Phase E)
    Proves that the container backend CANNOT read host secrets or modify host integrity files,
    while documenting the baseline ambient access of local subprocess fallback.
    """

    @pytest.mark.asyncio
    async def test_container_cannot_read_host_secret_sentinel(self, container_backend):
        # 1. Create a host secret sentinel file completely outside the workspace
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            f.write("SUPER_SECRET_HOST_CREDENTIAL_9999")
            host_secret_path = Path(f.name).resolve()

        ws_id = await container_backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            # Construct WSL path to the external secret
            wsl_secret_path = ContainerExecutionBackend.to_wsl_path(host_secret_path)

            # Adversarial script attempts to read the host secret
            script_path = ws_path / "steal_host_secret.py"
            script_path.write_text(
                f"import os\n"
                f"target = '{wsl_secret_path}'\n"
                f"if os.path.exists(target):\n"
                f"    print('LEAKED:' + open(target).read())\n"
                f"else:\n"
                f"    print('SECRET_NOT_FOUND_ISOLATED')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "steal_host_secret.py", timeout=5.0)
            assert res.exit_code == 0
            # Under container isolation, the external host path is NOT mounted inside the container!
            assert "LEAKED:SUPER_SECRET_HOST_CREDENTIAL" not in res.stdout
            assert "SECRET_NOT_FOUND_ISOLATED" in res.stdout

        finally:
            await container_backend.cleanup_workspace(ws_id)
            if host_secret_path.exists():
                host_secret_path.unlink()

    @pytest.mark.asyncio
    async def test_container_cannot_modify_host_integrity_sentinel(self, container_backend):
        # 1. Create a host integrity sentinel file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".canary", delete=False) as f:
            f.write("ORIGINAL_HOST_INTEGRITY_CONTENT")
            host_canary_path = Path(f.name).resolve()

        ws_id = await container_backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            wsl_canary_path = ContainerExecutionBackend.to_wsl_path(host_canary_path)

            # Adversarial script attempts to overwrite the host file
            script_path = ws_path / "tamper_host.py"
            script_path.write_text(
                f"try:\n"
                f"    with open('{wsl_canary_path}', 'w') as f:\n"
                f"        f.write('TAMPERED_BY_CONTAINER')\n"
                f"    print('TAMPER_SUCCEEDED')\n"
                f"except Exception as e:\n"
                f"    print(f'TAMPER_BLOCKED: {{type(e).__name__}}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "tamper_host.py", timeout=5.0)

            # Account for isolated tmpfs shadow path:
            # Under Linux/WSL2, tempfile creates host sentinels under /tmp, which is shadowed
            # inside the container by --tmpfs /tmp:rw,nosuid,nodev,size=64m. Writing to /tmp
            # succeeds only within the container's isolated in-memory tmpfs scratchpad.
            # Outside /tmp (e.g. Windows /mnt/c or non-tmp paths), --read-only rootfs blocks the write outright.
            is_tmpfs_shadowed = wsl_canary_path.startswith("/tmp/") or wsl_canary_path == "/tmp"
            if not is_tmpfs_shadowed:
                assert "TAMPER_SUCCEEDED" not in res.stdout

            # Ground truth: Host sentinel file MUST remain byte-for-byte unmodified
            assert host_canary_path.exists(), "Host sentinel file disappeared"
            assert host_canary_path.read_text(encoding="utf-8") == "ORIGINAL_HOST_INTEGRITY_CONTENT", (
                f"Host sentinel file was modified! Expected 'ORIGINAL_HOST_INTEGRITY_CONTENT', got {host_canary_path.read_text()!r}"
            )

        finally:
            await container_backend.cleanup_workspace(ws_id)
            if host_canary_path.exists():
                host_canary_path.unlink()


class TestNativeNetworkDenial:
    """
    Native Network Denial (P0.6 Phase F)
    Verifies that raw native network connections fail at the kernel level
    (Errno 101 Network unreachable) under container backend --network none.
    """

    @pytest.mark.asyncio
    async def test_kernel_level_network_denial(self, container_backend):
        ws_id = await container_backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "network_attempt.py"
            script_path.write_text(
                "import socket\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.settimeout(2.0)\n"
                "try:\n"
                "    s.connect(('1.1.1.1', 80))\n"
                "    print('NETWORK_CONNECTED_UNEXPECTED')\n"
                "except OSError as e:\n"
                "    print(f'KERNEL_NETWORK_DENIED: Errno={e.errno}, Message={e}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "network_attempt.py", timeout=5.0)
            assert res.exit_code == 0
            assert "NETWORK_CONNECTED_UNEXPECTED" not in res.stdout
            assert "KERNEL_NETWORK_DENIED" in res.stdout
            # Errno 101: Network unreachable
            assert "101" in res.stdout or "Network unreachable" in res.stdout
        finally:
            await container_backend.cleanup_workspace(ws_id)


class TestResourceAndPidContainment:
    """
    Resource & PID Containment (P0.6 Phase G)
    Verifies that cgroup limits prevent process exhaustion inside the container.
    """

    @pytest.mark.asyncio
    async def test_pids_limit_prevents_uncontrolled_forking(self, container_backend):
        ws_id = await container_backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "fork_limit.py"
            script_path.write_text(
                "import os\n"
                "spawned = 0\n"
                "try:\n"
                "    for _ in range(200):\n"
                "        pid = os.fork()\n"
                "        if pid == 0:\n"
                "            os._exit(0)\n"
                "        spawned += 1\n"
                "    print('FORK_ALL_SUCCEEDED')\n"
                "except BlockingIOError as e:\n"
                "    print(f'PID_LIMIT_ENFORCED: {e}')\n"
                "except OSError as e:\n"
                "    print(f'PID_LIMIT_ENFORCED: {e}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "fork_limit.py", timeout=10.0)
            # The fork storm hits cgroup pids.max
            assert "FORK_ALL_SUCCEEDED" not in res.stdout
            assert "PID_LIMIT_ENFORCED" in res.stdout or res.exit_code != 0
        finally:
            await container_backend.cleanup_workspace(ws_id)


class TestContainerExecutionAttestation:
    """
    Execution Attestation (P0.6 Phase H)
    Verifies cryptographic/parent-validated attestation records for OCI container backend.
    """

    @pytest.mark.asyncio
    async def test_attestation_fields_and_integrity(self, container_backend):
        ws_id = await container_backend.initialize_workspace(BENCHMARK_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "hello.py"
            script_path.write_text("print('HELLO_CONTAINER')", encoding="utf-8")

            res = await container_backend.execute_script(ws_id, "hello.py", timeout=5.0)
            assert res.exit_code == 0
            assert res.attestation is not None
            att = res.attestation

            assert att.backend_tier == IsolationTier.OCI_CONTAINER_ISOLATED
            assert "podman" in att.runtime_engine.lower()
            assert "none" in att.network_mode.lower()
            assert att.image_digest is not None
            assert att.verified_by_parent is True
            assert att.capabilities.network_kernel_denied is True
            assert att.capabilities.filesystem_jailed is True
            assert att.capabilities.host_fs_hidden is True
        finally:
            await container_backend.cleanup_workspace(ws_id)


class TestBackendFactoryResolution:
    """
    Backend Factory (P0.6 Phase I)
    Verifies automatic discovery and forced selection logic.
    """

    def test_factory_resolves_container_when_available(self, container_backend):
        backend = BackendFactory.resolve_best_available_backend(prefer_container=True)
        assert backend.capabilities.tier == IsolationTier.OCI_CONTAINER_ISOLATED

    def test_factory_honors_local_override(self):
        backend = BackendFactory.resolve_best_available_backend(
            force_tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK
        )
        assert backend.capabilities.tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK


class TestFullPipelineWithContainerBackend:
    """
    Full Verification Pipeline with Container Backend (P0.6 Phase J)
    Runs end-to-end verification under OCI_CONTAINER_ISOLATED tier.
    """

    @pytest.mark.asyncio
    async def test_pipeline_dead_code_under_container(self, container_backend):
        req = VerificationPipelineRequest(
            repo_path=str(DEADCODE_DIR),
            cve_id="CVE-2020-14343",
            vulnerable_symbol="yaml.load",
            entrypoints=["service/dead_code_service.py"],
            use_nemotron=False,
            query_tavily=False,
            execution_backend="OCI_CONTAINER_ISOLATED"
        )

        events = []
        res = await VerificationPipeline.run_pipeline(
            req=req,
            on_event=lambda ev: events.append(ev),
            backend=container_backend
        )

        assert res.reachability_verdict == "UNREACHABLE_FALSE_POSITIVE"
        assert res.final_behavioral_verdict == "UNREACHABLE_FALSE_POSITIVE"
        assert res.sandbox_engine == "OCI_CONTAINER_ISOLATED"
        assert res.isolation_tier == "OCI_CONTAINER_ISOLATED"
        assert res.isolation_attestation is not None
        assert res.isolation_attestation["backend_tier"] == "OCI_CONTAINER_ISOLATED"
        assert res.isolation_attestation["capabilities"]["network_kernel_denied"] is True
        assert res.isolation_attestation["capabilities"]["host_fs_hidden"] is True
        assert res.isolation_attestation["capabilities"]["filesystem_jailed"] is True

    @pytest.mark.asyncio
    async def test_pipeline_e2e_remediation_under_container(self, container_backend):
        sample_repo = (Path(__file__).resolve().parent / "fixtures" / "sample_repo").resolve()
        req = VerificationPipelineRequest(
            repo_path=str(sample_repo),
            cve_id="CVE-2020-14343",
            target_file="service.py",
            target_function="load_user_config",
            vulnerable_symbol="yaml.load",
            use_nemotron=False,
            query_tavily=False,
            execution_backend="OCI_CONTAINER_ISOLATED"
        )

        events = []
        res = await VerificationPipeline.run_pipeline(
            req=req,
            on_event=lambda ev: events.append(ev),
            backend=container_backend
        )

        assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
        assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"
        assert res.pre_patch_result.exit_code == 0
        assert res.remediation.success is True
        assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
        assert res.post_patch_result.exit_code == 42
        assert res.regression_tests.get("passed") is True
        assert res.regression_tests.get("test_count") == 2
        assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"
        assert res.sandbox_engine == "OCI_CONTAINER_ISOLATED"
        assert res.isolation_tier == "OCI_CONTAINER_ISOLATED"
        assert res.isolation_attestation is not None
        assert res.isolation_attestation["backend_tier"] == "OCI_CONTAINER_ISOLATED"
        assert res.isolation_attestation["capabilities"]["network_kernel_denied"] is True
        assert res.isolation_attestation["capabilities"]["process_tree_contained"] is True


VALID_PODMAN_INFO = {
    "host": {
        "security": {"rootless": True},
        "ociRuntime": {"name": "crun"},
        "cgroupVersion": "v2",
        "cgroupControllers": ["cpu", "memory", "pids"],
        "serviceIsRemote": False,
        "remoteSocket": {"exists": False}
    }
}

VALID_HEX_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def make_mock_subprocess(
    version_stdout="podman version 4.9.3\n",
    version_code=0,
    info_dict=None,
    info_code=0,
    info_raw_stdout=None,
    image_exists_code=0,
    inspect_stdout=None,
    inspect_code=0,
    raise_on_version=None
):
    """Constructs a deterministic mock for subprocess.run simulating Podman CLI."""
    if info_dict is None:
        info_dict = VALID_PODMAN_INFO

    def mock_run(cmd, *args, **kwargs):
        cmd_strs = [str(c) for c in cmd]
        # podman --version
        if "--version" in cmd_strs:
            if raise_on_version:
                raise raise_on_version
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=version_code,
                stdout=version_stdout,
                stderr=""
            )
        # podman info --format json
        if "info" in cmd_strs:
            stdout_str = info_raw_stdout if info_raw_stdout is not None else json.dumps(info_dict)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=info_code,
                stdout=stdout_str,
                stderr=""
            )
        # podman image exists
        if "image" in cmd_strs and "exists" in cmd_strs:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=image_exists_code,
                stdout="",
                stderr=""
            )
        # podman image inspect --format {{.Digest}}
        if "inspect" in cmd_strs:
            if inspect_stdout is not None:
                stdout_val = inspect_stdout
                retcode = inspect_code
            elif image_exists_code == 0:
                stdout_val = f"sha256:{VALID_HEX_DIGEST}\n"
                retcode = 0
            else:
                stdout_val = ""
                retcode = 1
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=retcode,
                stdout=stdout_val,
                stderr=""
            )
        # fallback for execution commands
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="MOCK_EXEC_OUTPUT\n",
            stderr=""
        )

    return mock_run


class TestContainerPreflightAndSecurityAlignment:
    """
    Tier 1 Backend Security Alignment & Fail-Closed Preflight Tests.
    Verifies:
    1. Strict version parsing (SemVer, suffixes, warning rejection, malformed rejection).
    2. Strict local-runtime verification (serviceIsRemote, CONTAINER_HOST/CONNECTION).
    3. Cache correctness and negative cache invalidation.
    4. Image digest cryptographic verification (genuine SHA-256 vs unavailable None).
    5. Injection of --userns keep-id across all three execution command paths.
    """

    def setup_method(self):
        ContainerExecutionBackend.clear_availability_cache()

    def teardown_method(self):
        ContainerExecutionBackend.clear_availability_cache()

    # --- Phase B: Version Parser Tests ---

    def test_version_output_captured_correctly(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(version_stdout="podman version 4.9.3\n")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True
            assert backend._runtime_version == "podman 4.9.3"

    def test_version_with_legitimate_suffix_accepted(self):
        suffixes = [
            ("podman version 4.9.3-ubuntu1\n", "podman 4.9.3-ubuntu1"),
            ("podman version 4.9.3+ds1-1build2\n", "podman 4.9.3+ds1-1build2"),
            ("podman 5.0.0-rc2\n", "podman 5.0.0-rc2"),
        ]
        for stdout_str, expected in suffixes:
            ContainerExecutionBackend.clear_availability_cache()
            backend = ContainerExecutionBackend()
            mock_fn = make_mock_subprocess(version_stdout=stdout_str)
            with patch("subprocess.run", side_effect=mock_fn):
                assert backend.is_available() is True
                assert backend._runtime_version == expected

    def test_version_empty_output_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(version_stdout="")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            assert backend._verified_runtime is False

    def test_version_arbitrary_text_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(version_stdout="some arbitrary non-version output\n")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            assert backend._verified_runtime is False

    def test_version_unexpected_leading_warnings_fails_closed(self):
        backend = ContainerExecutionBackend()
        warning_output = (
            'time="2026-11-15T06:49:34Z" level=warning msg="rootfs mount warning"\n'
            'podman version 4.9.3\n'
        )
        mock_fn = make_mock_subprocess(version_stdout=warning_output)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            assert backend._verified_runtime is False

    def test_version_malformed_digits_fails_closed(self):
        for bad_ver in ["podman version x.y.z\n", "podman version\n", "podman\n"]:
            ContainerExecutionBackend.clear_availability_cache()
            backend = ContainerExecutionBackend()
            mock_fn = make_mock_subprocess(version_stdout=bad_ver)
            with patch("subprocess.run", side_effect=mock_fn):
                assert backend.is_available() is False
                assert backend._verified_runtime is False

    def test_version_nonzero_exit_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(version_code=127)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            assert backend._verified_runtime is False

    def test_version_timeout_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(raise_on_version=subprocess.TimeoutExpired(cmd="podman", timeout=15))
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            assert backend._verified_runtime is False

    def test_version_failure_prevents_verified_attestation(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(version_stdout="malformed text\n")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            att = backend.generate_attestation(workspace_id="/fake/ws")
            assert att.runtime_engine == "podman_unverified"
            assert att.runtime_version == "podman (unverified)"
            assert att.verified_by_parent is True

    # --- Phase C: Strict Local-Runtime Verification Tests ---

    def test_remote_service_is_remote_true_fails_closed(self):
        backend = ContainerExecutionBackend()
        info_dict = dict(VALID_PODMAN_INFO)
        info_dict["host"] = dict(VALID_PODMAN_INFO["host"])
        info_dict["host"]["serviceIsRemote"] = True
        mock_fn = make_mock_subprocess(info_dict=info_dict)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_remote_service_is_remote_missing_fails_closed(self):
        backend = ContainerExecutionBackend()
        info_dict = dict(VALID_PODMAN_INFO)
        info_dict["host"] = dict(VALID_PODMAN_INFO["host"])
        del info_dict["host"]["serviceIsRemote"]
        mock_fn = make_mock_subprocess(info_dict=info_dict)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_remote_service_is_remote_none_fails_closed(self):
        backend = ContainerExecutionBackend()
        info_dict = dict(VALID_PODMAN_INFO)
        info_dict["host"] = dict(VALID_PODMAN_INFO["host"])
        info_dict["host"]["serviceIsRemote"] = None
        mock_fn = make_mock_subprocess(info_dict=info_dict)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_remote_container_host_env_fails_closed(self, monkeypatch):
        backend = ContainerExecutionBackend()
        monkeypatch.setenv("CONTAINER_HOST", "tcp://remote-box:2375")
        mock_fn = make_mock_subprocess()
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_remote_container_connection_env_fails_closed(self, monkeypatch):
        backend = ContainerExecutionBackend()
        monkeypatch.setenv("CONTAINER_CONNECTION", "remote-production-server")
        mock_fn = make_mock_subprocess()
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_local_remote_socket_exists_true_is_not_rejected(self):
        backend = ContainerExecutionBackend()
        info_dict = dict(VALID_PODMAN_INFO)
        info_dict["host"] = dict(VALID_PODMAN_INFO["host"])
        info_dict["host"]["remoteSocket"] = {"path": "/run/user/1000/podman/podman.sock", "exists": True}
        info_dict["host"]["serviceIsRemote"] = False
        mock_fn = make_mock_subprocess(info_dict=info_dict)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True
            assert backend._verified_runtime is True

    # --- Phase D: Cache Correctness Tests ---

    def test_changed_remote_env_cannot_bypass_cached_positive_result(self, monkeypatch):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess()
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True

        # Now set CONTAINER_HOST without clearing cache
        monkeypatch.setenv("CONTAINER_HOST", "ssh://user@remote-box/run/podman.sock")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_changed_connection_env_cannot_bypass_cached_positive_result(self, monkeypatch):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess()
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True

        # Now set CONTAINER_CONNECTION without clearing cache
        monkeypatch.setenv("CONTAINER_CONNECTION", "remote-profile")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_missing_image_negative_cache_does_not_block_newly_provisioned_image(self):
        backend = ContainerExecutionBackend()
        mock_fn_no_img = make_mock_subprocess(image_exists_code=1)
        with patch("subprocess.run", side_effect=mock_fn_no_img):
            assert backend.is_available() is False

        # Image is now built without restarting process
        mock_fn_with_img = make_mock_subprocess(image_exists_code=0)
        with patch("subprocess.run", side_effect=mock_fn_with_img):
            # Fresh preflight detects newly built image
            assert backend.is_available(fresh=True) is True
            # New instance also detects it
            new_backend = ContainerExecutionBackend()
            assert new_backend.is_available() is True

    def test_generate_attestation_never_presents_stale_verified_if_env_switched_to_remote(self, monkeypatch):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess()
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True
            att_clean = backend.generate_attestation("/clean/ws")
            assert "podman_crun_rootless" in att_clean.runtime_engine

        # Switched to remote environment
        monkeypatch.setenv("CONTAINER_HOST", "tcp://remote-box:2375")
        att_stale = backend.generate_attestation("/remote/ws")
        assert att_stale.runtime_engine == "podman_unverified"
        assert att_stale.runtime_version == "podman (unverified)"

    # --- Phase E: Image Digest Tests ---

    def test_image_digest_valid_sha256_inspect_output(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(image_exists_code=0)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True
            digest = backend.get_image_digest()
            assert digest == f"sha256:{VALID_HEX_DIGEST}"
            att = backend.generate_attestation("/fake/ws")
            assert att.image_digest == f"sha256:{VALID_HEX_DIGEST}"

    def test_image_digest_missing_returns_none(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(inspect_stdout="\n", inspect_code=0)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.get_image_digest() is None

    def test_image_digest_unavailable_returns_none_never_fake_placeholder(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(image_exists_code=1, inspect_code=1)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False
            digest = backend.get_image_digest()
            assert digest is None
            att = backend.generate_attestation("/fake/ws")
            assert att.image_digest is None
            assert "vulntrace-sandbox-base-local" not in str(att)

    def test_image_digest_malformed_inspect_output_returns_none(self):
        backend = ContainerExecutionBackend()
        for bad_digest in ["sha256:short\n", "sha256:not-valid-hex-characters-here!\n", "md5:12345\n"]:
            mock_fn = make_mock_subprocess(inspect_stdout=bad_digest, inspect_code=0)
            with patch("subprocess.run", side_effect=mock_fn):
                assert backend.get_image_digest() is None

    def test_image_digest_id_mistakenly_returned_instead_of_digest_returns_none(self):
        backend = ContainerExecutionBackend()
        # Bare 64-character hex image ID without sha256: prefix must NOT be manufactured into a digest
        mock_fn = make_mock_subprocess(inspect_stdout=f"{VALID_HEX_DIGEST}\n", inspect_code=0)
        with patch("subprocess.run", side_effect=mock_fn):
            digest = backend.get_image_digest()
            assert digest is None

    def test_changed_digest_after_rebuilding_same_image_tag(self):
        backend = ContainerExecutionBackend()
        digest_1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        digest_2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

        # Build 1
        mock_fn_1 = make_mock_subprocess(inspect_stdout=f"{digest_1}\n")
        with patch("subprocess.run", side_effect=mock_fn_1):
            assert backend.get_image_digest() == digest_1

        # Build 2 replaces the tag
        mock_fn_2 = make_mock_subprocess(inspect_stdout=f"{digest_2}\n")
        with patch("subprocess.run", side_effect=mock_fn_2):
            # Cached query returns old digest if not fresh
            assert backend.get_image_digest(fresh=False) == digest_1
            # Fresh query must return new digest
            assert backend.get_image_digest(fresh=True) == digest_2

    # --- Structural Preflight & Enforcement Tests ---

    def test_missing_podman_info_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(info_code=1)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_json_parsing_valid(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(info_raw_stdout=json.dumps(VALID_PODMAN_INFO))
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True

    def test_json_parsing_leading_garbage_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_stdout = "WARNING: /etc/subuid mapping notice\n" + json.dumps(VALID_PODMAN_INFO)
        mock_fn = make_mock_subprocess(info_raw_stdout=bad_stdout)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_json_parsing_trailing_garbage_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_stdout = json.dumps(VALID_PODMAN_INFO) + "\nWARNING: extra trailing garbage on stdout"
        mock_fn = make_mock_subprocess(info_raw_stdout=bad_stdout)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_malformed_json_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(info_raw_stdout="INVALID_JSON_CORRUPTED_OUTPUT")
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_rootless_false_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_info = {
            "host": {
                "security": {"rootless": False},
                "ociRuntime": {"name": "crun"},
                "cgroupVersion": "v2",
                "cgroupControllers": ["cpu", "memory", "pids"],
                "serviceIsRemote": False,
                "remoteSocket": {"exists": False}
            }
        }
        mock_fn = make_mock_subprocess(info_dict=bad_info)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_missing_rootless_property_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_info = {
            "host": {
                "security": {},
                "ociRuntime": {"name": "crun"},
                "cgroupVersion": "v2",
                "cgroupControllers": ["cpu", "memory", "pids"]
            }
        }
        mock_fn = make_mock_subprocess(info_dict=bad_info)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_non_crun_runtime_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_info = {
            "host": {
                "security": {"rootless": True},
                "ociRuntime": {"name": "runc"},
                "cgroupVersion": "v2",
                "cgroupControllers": ["cpu", "memory", "pids"],
                "serviceIsRemote": False,
                "remoteSocket": {"exists": False}
            }
        }
        mock_fn = make_mock_subprocess(info_dict=bad_info)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_non_v2_cgroup_version_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_info = {
            "host": {
                "security": {"rootless": True},
                "ociRuntime": {"name": "crun"},
                "cgroupVersion": "v1",
                "cgroupControllers": ["cpu", "memory", "pids"],
                "serviceIsRemote": False,
                "remoteSocket": {"exists": False}
            }
        }
        mock_fn = make_mock_subprocess(info_dict=bad_info)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_missing_cgroup_controllers_fails_closed(self):
        backend = ContainerExecutionBackend()
        bad_info = {
            "host": {
                "security": {"rootless": True},
                "ociRuntime": {"name": "crun"},
                "cgroupVersion": "v2",
                "cgroupControllers": ["cpu", "memory"],
                "serviceIsRemote": False,
                "remoteSocket": {"exists": False}
            }
        }
        mock_fn = make_mock_subprocess(info_dict=bad_info)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_missing_sandbox_image_fails_closed(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess(image_exists_code=1)
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

    def test_fully_valid_local_rootless_crun_passes_preflight(self):
        backend = ContainerExecutionBackend()
        mock_fn = make_mock_subprocess()
        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is True
            assert backend._runtime_version == "podman 4.9.3"
            att = backend.generate_attestation(workspace_id="/valid/ws")
            assert "podman_crun_rootless" in att.runtime_engine
            assert att.runtime_version == "podman 4.9.3"
            assert att.verified_by_parent is True

    @pytest.mark.asyncio
    async def test_all_three_execution_paths_include_userns_keep_id(self, tmp_path):
        backend = ContainerExecutionBackend()
        captured_commands = []

        mock_fn = make_mock_subprocess()

        def recording_run(cmd, *args, **kwargs):
            cmd_strs = [str(c) for c in cmd]
            if "run" in cmd_strs:
                captured_commands.append(list(cmd))
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="OK\n", stderr="")
            return mock_fn(cmd, *args, **kwargs)

        with patch("subprocess.run", side_effect=recording_run):
            # Preflight must pass
            assert backend.is_available() is True

            # 1. provision_dependencies() with setup.py present
            setup_file = tmp_path / "setup.py"
            setup_file.write_text("from setuptools import setup; setup()", encoding="utf-8")
            await backend.provision_dependencies(str(tmp_path), manifest_dependencies=[])

            # 2. execute_script()
            script_file = tmp_path / "run.py"
            script_file.write_text("print('test')", encoding="utf-8")
            await backend.execute_script(str(tmp_path), "run.py")

            # 3. run_regression_suite()
            await backend.run_regression_suite(str(tmp_path))

        run_commands = [c for c in captured_commands if "run" in c and "inspect" not in c]
        assert len(run_commands) == 3, f"Expected exactly 3 'podman run' executions, got {len(run_commands)}"

        for i, cmd in enumerate(run_commands):
            assert "--userns" in cmd, f"Path {i} missing '--userns': {cmd}"
            userns_idx = cmd.index("--userns")
            assert userns_idx + 1 < len(cmd), f"Path {i} malformed '--userns' without argument"
            assert cmd[userns_idx + 1] == "keep-id", f"Path {i} '--userns' argument is '{cmd[userns_idx + 1]}', expected 'keep-id'"

            assert "--user" in cmd, f"Path {i} missing '--user': {cmd}"
            user_idx = cmd.index("--user")
            assert cmd[user_idx + 1] == "1000:1000", f"Path {i} '--user' value is '{cmd[user_idx + 1]}', expected '1000:1000'"

    @pytest.mark.asyncio
    async def test_preflight_failure_blocks_execution_script_and_pytest(self, tmp_path):
        backend = ContainerExecutionBackend()
        # Mock preflight failure (e.g. rootless: false)
        bad_info = {"host": {"security": {"rootless": False}}}
        mock_fn = make_mock_subprocess(info_dict=bad_info)

        with patch("subprocess.run", side_effect=mock_fn):
            assert backend.is_available() is False

            # execute_script must raise RuntimeError
            with pytest.raises(RuntimeError, match="preflight check failed"):
                await backend.execute_script(str(tmp_path), "run.py")

            # run_regression_suite must fail without executing container
            res = await backend.run_regression_suite(str(tmp_path))
            assert res["passed"] is False
            assert "preflight check failed" in res["error"]

    @pytest.mark.asyncio
    async def test_fresh_preflight_blocks_execution_when_runtime_changes_to_rootful_or_runc(self, tmp_path):
        backend = ContainerExecutionBackend()
        captured_commands = []

        # State 1: Valid rootless crun runtime
        current_info = dict(VALID_PODMAN_INFO)

        def dynamic_mock_run(cmd, *args, **kwargs):
            cmd_strs = [str(c) for c in cmd]
            if "run" in cmd_strs:
                captured_commands.append(list(cmd))
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="OK\n", stderr="")
            if "--version" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="podman version 4.9.3\n", stderr="")
            if "info" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=json.dumps(current_info), stderr="")
            if "image" in cmd_strs and "exists" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            if "inspect" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=f"sha256:{VALID_HEX_DIGEST}\n", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="MOCK\n", stderr="")

        with patch("subprocess.run", side_effect=dynamic_mock_run):
            # Step 1: Initial preflight succeeds and is cached as available
            assert backend.is_available() is True
            assert backend._is_available is True

            # Step 2: Underneath the cached backend, runtime configuration changes to rootful
            current_info["host"] = dict(VALID_PODMAN_INFO["host"])
            current_info["host"]["security"] = {"rootless": False}

            # Step 3: Attempt all three execution paths
            # Path 1: execute_script
            script_file = tmp_path / "run.py"
            script_file.write_text("print('test')", encoding="utf-8")
            with pytest.raises(RuntimeError, match="preflight check failed"):
                await backend.execute_script(str(tmp_path), "run.py")

            # Path 2: provision_dependencies with setup.py
            setup_file = tmp_path / "setup.py"
            setup_file.write_text("from setuptools import setup; setup()", encoding="utf-8")
            with pytest.raises(RuntimeError, match="preflight check failed"):
                await backend.provision_dependencies(str(tmp_path), manifest_dependencies=[])

            # Path 3: run_regression_suite
            res = await backend.run_regression_suite(str(tmp_path))
            assert res["passed"] is False
            assert "preflight check failed" in res["error"]

            # Step 4: Confirm fresh preflight rejected execution before any 'podman run' was launched
            run_commands = [c for c in captured_commands if "run" in c and "inspect" not in c]
            assert len(run_commands) == 0, f"Expected 0 'podman run' calls after runtime became rootful, got {len(run_commands)}"

    @pytest.mark.asyncio
    async def test_fresh_preflight_blocks_execution_when_runtime_changes_to_runc(self, tmp_path):
        backend = ContainerExecutionBackend()
        captured_commands = []

        current_info = dict(VALID_PODMAN_INFO)

        def dynamic_mock_run(cmd, *args, **kwargs):
            cmd_strs = [str(c) for c in cmd]
            if "run" in cmd_strs:
                captured_commands.append(list(cmd))
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="OK\n", stderr="")
            if "--version" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="podman version 4.9.3\n", stderr="")
            if "info" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=json.dumps(current_info), stderr="")
            if "image" in cmd_strs and "exists" in cmd_strs:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="MOCK\n", stderr="")

        with patch("subprocess.run", side_effect=dynamic_mock_run):
            assert backend.is_available() is True

            # Runtime changed to runc
            current_info["host"] = dict(VALID_PODMAN_INFO["host"])
            current_info["host"]["ociRuntime"] = {"name": "runc"}

            script_file = tmp_path / "run.py"
            script_file.write_text("print('test')", encoding="utf-8")
            with pytest.raises(RuntimeError, match="preflight check failed"):
                await backend.execute_script(str(tmp_path), "run.py")

            run_commands = [c for c in captured_commands if "run" in c and "inspect" not in c]
            assert len(run_commands) == 0


class TestContainerProvisioningDependencyCorrectness:
    """
    Dependency Provisioning Correctness (Spec §4.5 & §4.6)
    Verifies that:
    1. A successful packaging/build command alone does not prove runtime dependencies were provisioned.
    2. A missing declared runtime dependency produces provisioned=False.
    3. The correct failure classification is ENV_BUILD_FAILED.
    4. Dependencies already installed in the image are recognised appropriately.
    5. Existing valid provisioning behavior is preserved.
    6. Existing response and evidence schemas remain unchanged.
    """

    @pytest.mark.asyncio
    async def test_packaging_build_alone_does_not_claim_provisioned_when_dependencies_missing(self, tmp_path):
        backend = ContainerExecutionBackend()
        # Setup.py builds successfully, but workspace declares missing runtime dependency 'jsonschema'
        setup_script = "from setuptools import setup\nsetup(name='dummy-pkg', version='0.1.0')\n"
        (tmp_path / "setup.py").write_text(setup_script, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("jsonschema>=2.5.1\n", encoding="utf-8")

        result = await backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=["jsonschema>=2.5.1"]
        )

        # Build command exited, but required runtime dependencies are missing!
        assert result.exit_code != 0
        assert result.parent_validated is False
        assert result.structured_evidence["provisioned"] is False
        assert result.structured_evidence["failure_classification"] == "ENV_BUILD_FAILED"
        assert "jsonschema" in result.structured_evidence["pip_log_excerpt"]
        assert any("jsonschema" in d for d in result.structured_evidence["missing_dependencies"])

    @pytest.mark.asyncio
    async def test_declared_dependencies_satisfied_claims_provisioned_true(self, tmp_path):
        backend = ContainerExecutionBackend()
        # Declare dependency that is pre-baked in sandbox image (PyYAML)
        setup_script = "from setuptools import setup\nsetup(name='dummy-pkg', version='0.1.0')\n"
        (tmp_path / "setup.py").write_text(setup_script, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("PyYAML>=5.3.1\n", encoding="utf-8")

        result = await backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=["PyYAML>=5.3.1"]
        )

        assert result.exit_code == 0
        assert result.parent_validated is True
        assert result.structured_evidence["provisioned"] is True
        assert result.structured_evidence["failure_classification"] is None
        assert len(result.structured_evidence["missing_dependencies"]) == 0

    @pytest.mark.asyncio
    async def test_response_and_evidence_schema_preserved(self, tmp_path):
        backend = ContainerExecutionBackend()
        (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(name='dummy', version='1.0')\n", encoding="utf-8")

        result = await backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=[]
        )

        # Verify ExecutionCommandResult contract
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
            "has_manifest", "detected_dependencies", "missing_dependencies",
            "provisioned", "image", "network_isolated", "setup_executed_in_container",
            "setup_latency_ms", "build_duration_ms", "python_version",
            "failure_classification", "pip_log_excerpt"
        }
        for k in required_keys:
            assert k in evidence, f"Missing required evidence key: {k}"
