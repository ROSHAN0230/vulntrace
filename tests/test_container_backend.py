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

import tempfile
import pytest
from pathlib import Path

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
            assert "TAMPER_SUCCEEDED" not in res.stdout
            # Host file content remains unmodified
            assert host_canary_path.read_text() == "ORIGINAL_HOST_INTEGRITY_CONTENT"

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
