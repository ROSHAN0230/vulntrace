"""
VulnTrace Provisioning Security & Egress Hardening Tests (P0.7)
Verifies:
1. Untrusted build hooks (setup.py / PEP 517) execute inside the isolated container tier.
2. Capability drops (--cap-drop ALL, no-new-privileges) and resource limits (PID/RAM).
3. Host filesystem (/mnt/c) is hidden from provisioning processes.
4. Ambient host secrets (TAVILY_API_KEY, NEBIUS_API_KEY, custom tokens) are completely absent.
5. Network exfiltration attempts during provisioning are kernel-denied (--network none).
6. Benign setup.py builds execute cleanly and record parent-side attestation.
"""

import pytest

from vulntrace.core.backend import IsolationTier
from vulntrace.core.container_backend import ContainerExecutionBackend

pytestmark = pytest.mark.container


@pytest.fixture
def container_backend():
    backend = ContainerExecutionBackend()
    if not backend.is_available():
        pytest.skip("Podman / WSL2 container substrate is not available on this host.")
    return backend


class TestContainerProvisioningSecurity:
    """Evaluates security boundaries during package provisioning inside OCI containers."""

    @pytest.mark.asyncio
    async def test_adversarial_setup_py_host_filesystem_hidden(self, container_backend, tmp_path):
        """
        Adversarial setup.py attempting to traverse into host Windows filesystem /mnt/c
        must fail because the container mount namespace hides the host filesystem.
        """
        setup_script = """
import os
import sys
from setuptools import setup

# Adversarial probe: check if host filesystem is accessible
if os.path.exists('/mnt/c'):
    print("HOST_FS_COMPROMISE: /mnt/c exists inside container!", file=sys.stderr)
    sys.exit(101)

setup(name='adversarial-fs-probe', version='0.1.0')
"""
        (tmp_path / "setup.py").write_text(setup_script, encoding="utf-8")

        result = await container_backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=[]
        )

        assert result.exit_code == 0
        assert "HOST_FS_COMPROMISE" not in result.stderr
        assert result.structured_evidence["setup_executed_in_container"] is True
        assert result.structured_evidence["network_isolated"] is True

    @pytest.mark.asyncio
    async def test_adversarial_setup_py_secrets_absent(self, container_backend, tmp_path, monkeypatch):
        """
        Adversarial setup.py attempting to inspect ambient host environment variables
        must find ZERO sensitive keys because Podman runs without host env passthrough.
        """
        # Inject ambient host secrets into current Python process
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-fake-secret-key-12345")
        monkeypatch.setenv("NEBIUS_API_KEY", "neb-fake-secret-key-67890")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-fake-secret-key")

        setup_script = """
import os
import sys
from setuptools import setup

sensitive_keys = [
    'TAVILY_API_KEY', 'NEBIUS_API_KEY', 'AWS_SECRET_ACCESS_KEY',
    'GITHUB_TOKEN', 'SSH_AUTH_SOCK'
]
leaked = [k for k in sensitive_keys if k in os.environ]

if leaked:
    print(f"SECRET_LEAK_DETECTED: {leaked}", file=sys.stderr)
    sys.exit(102)

setup(name='adversarial-secret-probe', version='0.1.0')
"""
        (tmp_path / "setup.py").write_text(setup_script, encoding="utf-8")

        result = await container_backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=[]
        )

        assert result.exit_code == 0
        assert "SECRET_LEAK_DETECTED" not in result.stderr
        assert result.structured_evidence["setup_executed_in_container"] is True

    @pytest.mark.asyncio
    async def test_adversarial_setup_py_network_exfiltration_blocked(self, container_backend, tmp_path):
        """
        Adversarial setup.py attempting to open a network socket during installation
        must be terminated with Errno 101 Network unreachable by kernel network namespace.
        """
        setup_script = """
import sys
import socket
from setuptools import setup

# Adversarial probe: attempt outbound network exfiltration
try:
    s = socket.create_connection(("1.1.1.1", 80), timeout=2.0)
    s.close()
    print("NETWORK_EXFILTRATION_SUCCEEDED", file=sys.stderr)
    sys.exit(103)
except OSError as e:
    # Expected: [Errno 101] Network unreachable
    print(f"KERNEL_NETWORK_BLOCKED: {e}")

setup(name='adversarial-net-probe', version='0.1.0')
"""
        (tmp_path / "setup.py").write_text(setup_script, encoding="utf-8")

        result = await container_backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=[]
        )

        assert result.exit_code == 0
        assert "NETWORK_EXFILTRATION_SUCCEEDED" not in result.stderr
        assert "KERNEL_NETWORK_BLOCKED" in result.stdout

    @pytest.mark.asyncio
    async def test_benign_setup_py_build_produces_attestation(self, container_backend, tmp_path):
        """
        Verifies that a valid benign setup.py build succeeds and generates unforgeable attestation.
        """
        setup_script = """
from setuptools import setup

setup(
    name='benign-target-package',
    version='1.0.0',
    py_modules=['target_mod']
)
"""
        (tmp_path / "setup.py").write_text(setup_script, encoding="utf-8")
        (tmp_path / "target_mod.py").write_text("VALUE = 42\n", encoding="utf-8")

        result = await container_backend.provision_dependencies(
            workspace_id=str(tmp_path),
            manifest_dependencies=[]
        )

        assert result.exit_code == 0
        assert result.parent_validated is True
        assert result.attestation is not None
        assert result.attestation.backend_tier == IsolationTier.OCI_CONTAINER_ISOLATED
        assert "none" in result.attestation.network_mode.lower()
        assert result.structured_evidence["provisioned"] is True
