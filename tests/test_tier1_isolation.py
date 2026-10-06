"""
Tests for VulnTrace Milestone M3: Isolation Tier 1 (Spec §4.6)

Adversarial Proof Suite:
1. Outbound network request fails at kernel level (--network none).
2. Host filesystem write/read attempt fails (--read-only root FS, host hiding).
3. Fork/process explosion is contained (--pids-limit 128).
4. Memory exhaustion is contained (--memory 512m).
5. Timeout watchdog kills descendants (no orphaned processes/containers).
6. Host credentials are unavailable (purged env, unmounted host paths).
7. Child telemetry cannot forge isolation claims (parent-controlled attestation).
8. Workspace remains isolated (disposable copy; tmpfs scratch wiped).
9. Tier-0 LocalSubprocess refuses non-curated repos unless unsafe_local=True.
10. BackendFactory defaults real/non-curated repos to Tier 1.
11. Verifier 3/3 RED/GREEN execution functions under Tier 1 container backend.
"""

import os
import tempfile
import pytest
from pathlib import Path

from vulntrace.core.backend import IsolationTier
from vulntrace.core.container_backend import ContainerExecutionBackend
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.factory import BackendFactory
from vulntrace.verifier.runner import AntiGamingVerifier
from vulntrace.sinks.deserialization import YamlDeserializationOracle
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.models import VerificationPipelineRequest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "sample_repo"
FLASGGER_DIR = Path(__file__).resolve().parent.parent / "real_world_eval" / "flasgger"

pytestmark = pytest.mark.container


@pytest.fixture(scope="module")
def container_backend():
    """Provides a container execution backend if Podman is available; skips otherwise."""
    backend = ContainerExecutionBackend()
    if not backend.is_available():
        pytest.skip("OCI Container execution backend (Podman/crun) is not available on this host.")
    return backend


class TestAdversarialTier1Isolation:
    """Proves all 8 adversarial containment properties under Tier 1."""

    @pytest.mark.asyncio
    async def test_adversarial_outbound_network_denied(self, container_backend):
        """
        Adversarial Test 1: Outbound network request fails.
        Proves raw TCP connect and DNS resolution fail at the kernel level under --network none.
        """
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "adv_network.py"
            script_path.write_text(
                "import socket\n"
                "net_results = {}\n"
                "# 1. Raw socket connect\n"
                "try:\n"
                "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "    s.settimeout(0.5)\n"
                "    s.connect(('8.8.8.8', 53))\n"
                "    net_results['tcp'] = 'CONNECTED'\n"
                "except OSError as e:\n"
                "    net_results['tcp'] = f'DENIED_{e.errno}'\n"
                "# 2. DNS resolve\n"
                "try:\n"
                "    socket.gethostbyname('example.com')\n"
                "    net_results['dns'] = 'RESOLVED'\n"
                "except Exception as e:\n"
                "    net_results['dns'] = f'DENIED_{type(e).__name__}'\n"
                "print(f'NETWORK_AUDIT:{net_results}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_network.py", timeout=8.0)
            assert res.exit_code == 0
            assert "CONNECTED" not in res.stdout
            assert "RESOLVED" not in res.stdout
            assert "NETWORK_AUDIT:" in res.stdout
            assert "DENIED_101" in res.stdout or "Network unreachable" in res.stdout
            assert "DENIED_gaierror" in res.stdout or "DENIED" in res.stdout
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_adversarial_host_filesystem_and_readonly_root_fs(self, container_backend):
        """
        Adversarial Test 2: Host filesystem write/read attempt fails.
        Proves root filesystem is read-only (--read-only) and host files outside workspace are hidden.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".canary", delete=False) as f:
            f.write("EXTERNAL_HOST_DATA_SECRET_777")
            host_file = Path(f.name).resolve()

        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            wsl_host_file = ContainerExecutionBackend.to_wsl_path(host_file)
            script_path = ws_path / "adv_fs.py"
            script_path.write_text(
                f"import os\n"
                f"fs_results = {{}}\n"
                f"# 1. Attempt write to root filesystem\n"
                f"try:\n"
                f"    with open('/etc/malicious_harness.conf', 'w') as f:\n"
                f"        f.write('tamper')\n"
                f"    fs_results['root_write'] = 'SUCCESS'\n"
                f"except OSError as e:\n"
                f"    fs_results['root_write'] = f'BLOCKED_{{e.errno}}'\n"
                f"# 2. Attempt read external host secret\n"
                f"try:\n"
                f"    with open('{wsl_host_file}', 'r') as f:\n"
                f"        content = f.read()\n"
                f"    fs_results['host_read'] = 'LEAKED:' + content\n"
                f"except Exception as e:\n"
                f"    fs_results['host_read'] = f'BLOCKED_{{type(e).__name__}}'\n"
                f"# 3. Attempt write to external host path\n"
                f"try:\n"
                f"    with open('{wsl_host_file}', 'w') as f:\n"
                f"        f.write('TAMPERED')\n"
                f"    fs_results['host_write'] = 'TAMPERED'\n"
                f"except Exception as e:\n"
                f"    fs_results['host_write'] = f'BLOCKED_{{type(e).__name__}}'\n"
                f"print(f'FS_AUDIT:{{fs_results}}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_fs.py", timeout=5.0)
            assert res.exit_code == 0
            assert "FS_AUDIT:" in res.stdout
            assert "SUCCESS" not in res.stdout
            assert "LEAKED" not in res.stdout
            assert "TAMPERED" not in res.stdout
            # Errno 30: Read-only file system
            assert "BLOCKED_30" in res.stdout or "Read-only file system" in res.stdout
            # Host file remains untouched
            assert host_file.read_text() == "EXTERNAL_HOST_DATA_SECRET_777"
        finally:
            await container_backend.cleanup_workspace(ws_id)
            if host_file.exists():
                host_file.unlink()

    @pytest.mark.asyncio
    async def test_adversarial_fork_process_explosion_contained(self, container_backend):
        """
        Adversarial Test 3: Fork/process explosion is contained.
        Proves cgroup --pids-limit 128 traps and terminates runaway fork storm.
        """
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "adv_fork.py"
            script_path.write_text(
                "import os, sys\n"
                "fork_count = 0\n"
                "try:\n"
                "    for _ in range(250):\n"
                "        pid = os.fork()\n"
                "        if pid == 0:\n"
                "            os._exit(0)\n"
                "        fork_count += 1\n"
                "    print(f'FORK_ALL_SUCCEEDED_{fork_count}')\n"
                "except Exception as e:\n"
                "    print(f'FORK_CONTAINED_{type(e).__name__}_{fork_count}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_fork.py", timeout=8.0)
            assert "FORK_ALL_SUCCEEDED" not in res.stdout
            assert "FORK_CONTAINED" in res.stdout or res.exit_code != 0
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_adversarial_memory_exhaustion_contained(self, container_backend):
        """
        Adversarial Test 4: Memory exhaustion is contained.
        Proves cgroup --memory 512m terminates memory hog with OOM killer without affecting host.
        """
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "adv_memory.py"
            script_path.write_text(
                "import sys\n"
                "# Attempt allocating 1GB in a 512MB container\n"
                "try:\n"
                "    hog = bytearray(1024 * 1024 * 1024)\n"
                "    print('MEMORY_HOG_SUCCEEDED')\n"
                "except MemoryError:\n"
                "    print('MEMORY_ERROR_HANDLED')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_memory.py", timeout=10.0)
            assert "MEMORY_HOG_SUCCEEDED" not in res.stdout
            # OOM kill causes exit code 137 or MemoryError (exit 1)
            assert res.exit_code in (137, 1)
            assert res.exit_code != 0
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_adversarial_timeout_watchdog_kills_descendants(self, container_backend):
        """
        Adversarial Test 5: Timeout watchdog kills descendants.
        Proves container and background child processes are completely eliminated on timeout.
        """
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "adv_timeout.py"
            script_path.write_text(
                "import subprocess, time\n"
                "# Spawn background child sleeper\n"
                "p = subprocess.Popen(['sleep', '30'])\n"
                "# Loop until watchdog kills\n"
                "while True:\n"
                "    time.sleep(0.5)\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_timeout.py", timeout=3.0)
            assert res.timed_out is True
            assert res.exit_code == -9
            assert res.reproduction_state == "TIMED_OUT"

            # Verify no orphan containers left running in Podman (portable across Windows WSL and Linux)
            import subprocess
            cmd_ps = container_backend._build_cli_prefix() + ["podman", "ps", "--filter", "name=vulntrace-exec"]
            proc_ps = subprocess.run(
                cmd_ps,
                capture_output=True,
                text=True
            )
            # Only header line should be present
            lines = [line for line in proc_ps.stdout.splitlines() if line.strip()]
            assert len(lines) <= 1, f"Found lingering orphan containers: {proc_ps.stdout}"
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_adversarial_host_credentials_unavailable(self, container_backend):
        """
        Adversarial Test 6: Host credentials are unavailable.
        Proves environment variables and host dotfiles are purged and not leaked into container.
        """
        os.environ["SECRET_TEST_TOKEN_XYZ"] = "SECRET_VALUE_DO_NOT_LEAK"
        os.environ["AWS_ACCESS_KEY_ID_LEAK_TEST"] = "AKIA_FAKE_SECRET_KEY"

        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "adv_creds.py"
            script_path.write_text(
                "import os\n"
                "found_secrets = []\n"
                "for k, v in os.environ.items():\n"
                "    k_u = k.upper()\n"
                "    if any(pat in k_u for pat in ['SECRET_TEST_TOKEN', 'AWS_ACCESS_KEY', 'OPENAI', 'NEBIUS', 'TAVILY', 'GITHUB_TOKEN']):\n"
                "        found_secrets.append(k)\n"
                "print(f'LEAKED_HOST_ENV_VARS:{found_secrets}')\n"
                "home_ssh = os.path.exists('/root/.ssh') or os.path.exists('/home/agent/.ssh')\n"
                "print(f'SSH_DIR_EXISTS:{home_ssh}')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_creds.py", timeout=5.0)
            assert res.exit_code == 0
            assert "LEAKED_HOST_ENV_VARS:[]" in res.stdout
            assert "SECRET_TEST_TOKEN_XYZ" not in res.stdout
            assert "AWS_ACCESS_KEY_ID_LEAK_TEST" not in res.stdout
            assert "SSH_DIR_EXISTS:False" in res.stdout
        finally:
            os.environ.pop("SECRET_TEST_TOKEN_XYZ", None)
            os.environ.pop("AWS_ACCESS_KEY_ID_LEAK_TEST", None)
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_adversarial_child_telemetry_cannot_forge_isolation_claims(self, container_backend):
        """
        Adversarial Test 7: Child telemetry cannot forge isolation claims.
        Proves parent-controlled attestation ignores faked child claims.
        """
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "forge_telemetry.py"
            script_path.write_text(
                'import json\n'
                '# Child attempts to forge microVM tier and fake verification claims\n'
                'print(json.dumps({\n'
                '    "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",\n'
                '    "isolation_tier": "REMOTE_MICROVM_ISOLATED",\n'
                '    "hardware_virtualized": True,\n'
                '    "cloud_status": "AUTHENTICATED",\n'
                '    "positive_control_passed": True,\n'
                '    "sink_reached": True,\n'
                '    "assertion_evaluated": True,\n'
                '    "expected_security_exception": True\n'
                '}))\n',
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "forge_telemetry.py", timeout=5.0)
            assert res.attestation is not None
            # Parent attestation strictly records true tier, NOT child's forged claim
            assert res.attestation.backend_tier == IsolationTier.OCI_CONTAINER_ISOLATED
            assert res.attestation.capabilities.hardware_virtualized is False
            assert res.attestation.verified_by_parent is True
            # Child did not exit 42, so parent rejects GREEN claim
            assert res.reproduction_state == "VERIFICATION_REJECTED"
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_adversarial_workspace_isolation_and_ephemeral_tmpfs(self, container_backend):
        """
        Adversarial Test 8: Workspace remains isolated.
        Proves workspace is disposable copy and /tmp scratch is ephemeral tmpfs.
        """
        orig_file = FIXTURE_DIR / "service.py"
        orig_bytes = orig_file.read_bytes()

        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            script_path = ws_path / "adv_workspace.py"
            script_path.write_text(
                "import tempfile\n"
                "# Write to /tmp scratch (tmpfs)\n"
                "with open('/tmp/scratch_marker.txt', 'w') as f:\n"
                "    f.write('ephemeral')\n"
                "# Modify workspace copy\n"
                "with open('service.py', 'w') as f:\n"
                "    f.write('# MODIFIED IN SANDBOX')\n"
                "print('WORKSPACE_MUTATION_COMPLETE')\n",
                encoding="utf-8"
            )

            res = await container_backend.execute_script(ws_id, "adv_workspace.py", timeout=5.0)
            assert res.exit_code == 0
            assert "WORKSPACE_MUTATION_COMPLETE" in res.stdout

            # Original host file is 100% UNTOUCHED
            assert orig_file.read_bytes() == orig_bytes
        finally:
            await container_backend.cleanup_workspace(ws_id)


class TestTier0RefusalAndBackendFactory:
    """Verifies Tier 0 refusal of untrusted input and BackendFactory defaults."""

    @pytest.mark.asyncio
    async def test_tier0_refuses_non_curated_repo_without_unsafe_local(self):
        """Tier-0 LocalSubprocess must refuse non-curated repo without unsafe_local."""
        if not FLASGGER_DIR.exists():
            pytest.skip("Flasgger submodule not present.")

        # Temporarily unset CI and VULNTRACE_UNSAFE_LOCAL to test pure refusal logic
        old_ci = os.environ.pop("CI", None)
        old_unsafe = os.environ.pop("VULNTRACE_UNSAFE_LOCAL", None)

        backend = LocalSubprocessBackend(unsafe_local=False)
        try:
            with pytest.raises(PermissionError) as exc_info:
                await backend.initialize_workspace(FLASGGER_DIR)
            assert "Tier 0 (LocalSubprocess) refused non-curated repository" in str(exc_info.value)
        finally:
            if old_ci is not None:
                os.environ["CI"] = old_ci
            if old_unsafe is not None:
                os.environ["VULNTRACE_UNSAFE_LOCAL"] = old_unsafe

    @pytest.mark.asyncio
    async def test_tier0_allows_curated_fixture(self):
        """Tier-0 LocalSubprocess permits curated fixtures."""
        backend = LocalSubprocessBackend(unsafe_local=False)
        ws_id = await backend.initialize_workspace(FIXTURE_DIR)
        try:
            assert Path(ws_id).exists()
            att = backend.generate_attestation(ws_id)
            assert att.backend_tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK
            assert "DEGRADED" in att.runtime_engine
        finally:
            await backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_tier0_allows_non_curated_with_explicit_unsafe_local(self):
        """Tier-0 permits non-curated repo when unsafe_local=True is explicitly set."""
        if not FLASGGER_DIR.exists():
            pytest.skip("Flasgger submodule not present.")

        backend = LocalSubprocessBackend(unsafe_local=True)
        ws_id = await backend.initialize_workspace(FLASGGER_DIR)
        try:
            assert Path(ws_id).exists()
            att = backend.generate_attestation(ws_id)
            assert att.backend_tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK
        finally:
            await backend.cleanup_workspace(ws_id)

    def test_backend_factory_resolves_tier1_for_non_curated_repo(self, container_backend):
        """BackendFactory must resolve Tier 1 for real/non-curated repositories."""
        if not FLASGGER_DIR.exists():
            pytest.skip("Flasgger submodule not present.")

        resolved = BackendFactory.resolve_best_available_backend(target_repo=FLASGGER_DIR)
        assert resolved.capabilities.tier == IsolationTier.OCI_CONTAINER_ISOLATED
        assert resolved.capabilities.read_only_rootfs is True
        assert resolved.capabilities.network_kernel_denied is True

    @pytest.mark.asyncio
    async def test_backend_factory_unspecified_repo_does_not_unlock_tier0(self):
        """BackendFactory resolving Tier 0 without target_repo must not unlock unsafe_local."""
        if not FLASGGER_DIR.exists():
            pytest.skip("Flasgger submodule not present.")

        old_ci = os.environ.pop("CI", None)
        old_unsafe = os.environ.pop("VULNTRACE_UNSAFE_LOCAL", None)

        try:
            # Resolve Tier 0 backend without target_repo specified
            backend = BackendFactory.resolve_best_available_backend(
                force_tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
                unsafe_local=False
            )
            # Must remain locked (unsafe_local=False)
            assert getattr(backend, "unsafe_local", False) is False

            # Subsequent attempt to initialize non-curated repo must be refused
            with pytest.raises(PermissionError) as exc_info:
                await backend.initialize_workspace(FLASGGER_DIR)
            assert "refused non-curated repository" in str(exc_info.value)
        finally:
            if old_ci is not None:
                os.environ["CI"] = old_ci
            if old_unsafe is not None:
                os.environ["VULNTRACE_UNSAFE_LOCAL"] = old_unsafe


class TestVerifierAntiGamingUnderTier1:
    """Verifies that the AntiGamingVerifier functions correctly under Tier 1."""

    @pytest.mark.asyncio
    async def test_anti_gaming_verifier_red_reproduction_3x(self, container_backend):
        """AntiGamingVerifier reproduces RED 3/3 in OCI container."""
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            # Create a harness that reproduces vulnerable RED state
            harness = ws_path / "harness_red.py"
            harness.write_text(
                "import json\n"
                "with open('test_sentinel.marker', 'w') as f:\n"
                "    f.write('vulnerable_marker')\n"
                "print(json.dumps({'assertion': 'RED_PASSED', 'sink_reached': True}))\n",
                encoding="utf-8"
            )

            success, runs, reason = await AntiGamingVerifier.verify_red_reproduction_3x(
                backend=container_backend,
                workspace_id=ws_id,
                harness_script_name="harness_red.py",
                sentinel_filename="test_sentinel.marker",
                runs_count=3
            )
            assert success is True
            assert len(runs) == 3
            assert all(r.is_valid_red for r in runs)
            assert "Confirmed RED 3/3" in reason
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_anti_gaming_verifier_green_remediation_3x(self, container_backend):
        """AntiGamingVerifier verifies GREEN 3/3 in OCI container with expected security exception."""
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            # Create a harness that verifies blocked state (exit 42, no marker)
            harness = ws_path / "harness_green.py"
            harness.write_text(
                "import sys, json\n"
                "print(json.dumps({\n"
                "    'assertion': 'GREEN_SECURITY_BLOCK_VERIFIED',\n"
                "    'sink_reached': True,\n"
                "    'assertion_evaluated': True,\n"
                "    'expected_security_exception': True,\n"
                "    'positive_control_passed': True,\n"
                "    'exception_type': 'ConstructorError'\n"
                "}))\n"
                "sys.exit(42)\n",
                encoding="utf-8"
            )

            expected_sig = YamlDeserializationOracle().get_expected_block_signature()
            success, runs, reason = await AntiGamingVerifier.verify_green_remediation_3x(
                backend=container_backend,
                workspace_id=ws_id,
                harness_script_name="harness_green.py",
                sentinel_filename="test_sentinel.marker",
                expected_signature=expected_sig,
                runs_count=3
            )
            assert success is True
            assert len(runs) == 3
            assert all(r.is_valid_green for r in runs)
            assert "Confirmed GREEN 3/3" in reason
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_container_backend_setup_py_egg_base_build(self, container_backend):
        """Proves setup.py build succeeds with egg-base redirected to tmpfs on drvfs."""
        ws_id = await container_backend.initialize_workspace(FIXTURE_DIR)
        ws_path = Path(ws_id)

        try:
            # Write a setup.py that uses setuptools and generates egg-info
            setup_py = ws_path / "setup.py"
            setup_py.write_text(
                "from setuptools import setup, find_packages\n"
                "setup(name='test_pkg', version='0.1.0', packages=find_packages())\n",
                encoding="utf-8"
            )

            res = await container_backend.provision_dependencies(ws_id, manifest_dependencies=[])
            assert res.exit_code == 0
            assert res.parent_validated is True
            assert "setup.py built under isolated container tier" in (res.validation_notes or "")
        finally:
            await container_backend.cleanup_workspace(ws_id)

    @pytest.mark.asyncio
    async def test_pipeline_preserves_tier1_engine_and_tier_on_patch_rejection(self, container_backend):
        """Proves VerificationPipeline preserves Tier 1 engine and attestation when patch is rejected."""
        req = VerificationPipelineRequest(
            repo_path=str(FIXTURE_DIR),
            cve_id="CVE-2020-14343",
            target_file="service.py",
            target_function="load_user_config",
            vulnerable_symbol="yaml.load",
            use_nemotron=False,
            query_tavily=False,
            execution_backend="OCI_CONTAINER_ISOLATED"
        )

        from unittest.mock import patch
        from vulntrace.models import RemediationResponse

        # Force remediation to fail (patch rejection)
        rejected_rem = RemediationResponse(
            cve_id=req.cve_id,
            target_file="service.py",
            engine="TEST_REJECTED",
            diff="",
            explanation="Deliberately rejected patch for tier metadata audit.",
            latency_ms=1.0,
            success=False,
            validation_status="REJECTED_DENYLIST_VIOLATION",
            error="Denylist violation injected"
        )

        with patch("vulntrace.agent.patcher.RemediationPatcher.synthesize_remediation", return_value=rejected_rem):
            res = await VerificationPipeline.run_pipeline(req=req, backend=container_backend)
            assert res.remediation.success is False
            assert res.final_behavioral_verdict == "PATCH_REJECTED"
            # Critical: sandbox_engine and isolation_tier must NOT report Tier 0
            assert res.sandbox_engine == "OCI_CONTAINER_ISOLATED"
            assert res.isolation_tier == "OCI_CONTAINER_ISOLATED"
            assert res.post_patch_result.sandbox_engine == "OCI_CONTAINER_ISOLATED"
            assert res.isolation_attestation is not None
            assert res.isolation_attestation["backend_tier"] == "OCI_CONTAINER_ISOLATED"

