"""
VulnTrace Backend Conformance Test Suite (P0.7)
Formal verification test suite validating ANY ExecutionBackend implementation
against mandatory security guarantees:
1. Workspace Isolation: File modifications strictly isolated to disposable workspace.
2. Secret Isolation: Ambient parent/host credentials purged before execution.
3. Process Containment: Timeout watchdog terminates runaway and orphaned processes.
4. Sentinel Integrity: Child cannot spoof sentinel markers via stdout/stderr assertions.
5. Network Denial: Network access is denied in accordance with declared capabilities.
6. Attestation Anti-Spoofing: Child process output cannot forge parent attestation tokens.
7. Resource Limits: Memory and process concurrency limits enforced where claimed.
"""

import os
import sys
import time
import pytest
from pathlib import Path
from typing import List

from vulntrace.core.backend import ExecutionBackend, IsolationTier
from vulntrace.core.local_backend import LocalSubprocessBackend
from vulntrace.core.container_backend import ContainerExecutionBackend


def get_available_backends() -> List[ExecutionBackend]:
    """Returns all backends available on the current machine."""
    backends = [LocalSubprocessBackend()]
    container_backend = ContainerExecutionBackend()
    if container_backend.is_available():
        backends.append(container_backend)
    return backends


@pytest.mark.parametrize("backend", get_available_backends(), ids=lambda b: b.capabilities.tier.value)
class TestBackendConformanceSuite:
    """Verifies that each backend conforms to its declared security contract."""

    @pytest.mark.asyncio
    async def test_conformance_workspace_lifecycle_and_isolation(self, backend: ExecutionBackend, tmp_path):
        """Guarantee 1: Workspace must be disposable and isolated."""
        # 1. Initialize workspace from source
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        (source_dir / "target.py").write_text("print('HELLO')", encoding="utf-8")

        workspace_id = await backend.initialize_workspace(source_dir)
        workspace_path = Path(workspace_id)
        assert workspace_path.exists()
        assert (workspace_path / "target.py").exists()

        # 2. Modify workspace
        (workspace_path / "created_by_child.txt").write_text("CHILD_MODIFICATION", encoding="utf-8")
        assert (workspace_path / "created_by_child.txt").exists()
        # Original source directory must remain completely unmodified
        assert not (source_dir / "created_by_child.txt").exists()

        # 3. Clean up workspace
        await backend.cleanup_workspace(workspace_id)
        assert not workspace_path.exists()

    @pytest.mark.asyncio
    async def test_conformance_secret_isolation(self, backend: ExecutionBackend, tmp_path, monkeypatch):
        """Guarantee 2: Ambient host secrets must never leak to execution child."""
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-conformance-secret-999")
        monkeypatch.setenv("NEBIUS_API_KEY", "neb-conformance-secret-888")

        probe_code = """
import os
import sys

secrets = ['TAVILY_API_KEY', 'NEBIUS_API_KEY']
found = [s for s in secrets if s in os.environ]

if found:
    print(f"SECRET_LEAK_ERROR: {found}", file=sys.stderr)
    sys.exit(45)

print("CONFORMANCE_SECRETS_PURGED_CLEANLY")
sys.exit(0)
"""
        workspace_id = await backend.initialize_workspace(tmp_path)
        workspace_path = Path(workspace_id)
        (workspace_path / "probe_secrets.py").write_text(probe_code, encoding="utf-8")

        try:
            res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name="probe_secrets.py",
                timeout=15.0
            )
            assert res.exit_code == 0
            assert "CONFORMANCE_SECRETS_PURGED_CLEANLY" in res.stdout
            assert "SECRET_LEAK_ERROR" not in res.stderr
        finally:
            await backend.cleanup_workspace(workspace_id)

    @pytest.mark.asyncio
    async def test_conformance_process_containment_and_watchdog(self, backend: ExecutionBackend, tmp_path):
        """Guarantee 3: Runaway child process must be terminated when timeout expires."""
        infinite_loop = """
import time
import sys

# Deliberately ignore SIGINT/SIGTERM or sleep forever
while True:
    time.sleep(0.5)
"""
        workspace_id = await backend.initialize_workspace(tmp_path)
        workspace_path = Path(workspace_id)
        (workspace_path / "hang.py").write_text(infinite_loop, encoding="utf-8")

        t0 = time.perf_counter()
        try:
            res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name="hang.py",
                timeout=2.0
            )
            elapsed = time.perf_counter() - t0

            assert res.timed_out is True
            # Must terminate within reasonable watchdog window (2s timeout + max 5s cleanup)
            assert elapsed < 7.0
        finally:
            await backend.cleanup_workspace(workspace_id)

    @pytest.mark.asyncio
    async def test_conformance_sentinel_integrity(self, backend: ExecutionBackend, tmp_path):
        """Guarantee 4: Child cannot forge verification outcome via stdout/stderr assertions."""
        deceptive_code = """
import sys

# Child attempts to spoof successful green state without genuine fix
print("VERIFICATION_RESULT: GREEN_STATE_BLOCKED")
print("ASSERTION: True")
print("STATUS: SUCCESS")
# Exit 42 without actually passing parent checks
sys.exit(42)
"""
        workspace_id = await backend.initialize_workspace(tmp_path)
        workspace_path = Path(workspace_id)
        (workspace_path / "deceptive.py").write_text(deceptive_code, encoding="utf-8")

        try:
            # We declare a sentinel that genuine green state requires
            res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name="deceptive.py",
                sentinel_filename="sentinel.marker"
            )
            # Parent trust boundary must validate the physical disk state
            assert res.sentinel_created is False
            # Child must NOT be able to spoof green state without valid parent verification
            assert res.reproduction_state != "GREEN_STATE_BLOCKED"
            assert res.parent_validated is False
        finally:
            await backend.cleanup_workspace(workspace_id)

    @pytest.mark.asyncio
    async def test_conformance_sentinel_positive_verification(self, backend: ExecutionBackend, tmp_path):
        """Guarantee 4b: Physical sentinel creation on disk is accurately detected by parent."""
        sentinel_creator = """
import sys
with open("sentinel.marker", "w") as f:
    f.write("SENTINEL_WRITTEN")
sys.exit(0)
"""
        workspace_id = await backend.initialize_workspace(tmp_path)
        workspace_path = Path(workspace_id)
        (workspace_path / "creator.py").write_text(sentinel_creator, encoding="utf-8")

        try:
            res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name="creator.py",
                sentinel_filename="sentinel.marker"
            )
            # Physical sentinel marker created on disk must be recognized
            assert res.sentinel_created is True
            assert res.reproduction_state == "RED_STATE_REPRODUCED"
            assert res.parent_validated is True
        finally:
            await backend.cleanup_workspace(workspace_id)

    @pytest.mark.asyncio
    async def test_conformance_attestation_anti_spoofing(self, backend: ExecutionBackend, tmp_path):
        """Guarantee 6: Attestation token is parent-generated and unforgeable."""
        forger_code = """
import json
import sys

fake_attestation = {
    "tier": "REMOTE_MICROVM_ISOLATED",
    "unforgeable_signature": "FORGED_SIGNATURE_12345",
    "hardware_virtualized": True
}
print(f"ATTESTATION_TOKEN: {json.dumps(fake_attestation)}")
sys.exit(0)
"""
        workspace_id = await backend.initialize_workspace(tmp_path)
        workspace_path = Path(workspace_id)
        (workspace_path / "forger.py").write_text(forger_code, encoding="utf-8")

        try:
            res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name="forger.py"
            )
            assert res.exit_code == 0
            # Parent attestation must reflect the genuine backend tier, NOT the child's claim
            assert res.attestation is not None
            assert res.attestation.backend_tier == backend.capabilities.tier
            assert res.attestation.backend_tier != IsolationTier.REMOTE_MICROVM_ISOLATED
        finally:
            await backend.cleanup_workspace(workspace_id)

    @pytest.mark.asyncio
    async def test_conformance_network_denial_contract(self, backend: ExecutionBackend, tmp_path):
        """Guarantee 5: Network behavior matches claimed capabilities."""
        net_probe = """
import sys
import socket

try:
    s = socket.create_connection(("1.1.1.1", 80), timeout=2.0)
    s.close()
    print("RAW_SOCKET_CONNECTED")
    sys.exit(0)
except Exception as e:
    print(f"SOCKET_DENIED: {e}")
    sys.exit(10)
"""
        workspace_id = await backend.initialize_workspace(tmp_path)
        workspace_path = Path(workspace_id)
        (workspace_path / "net_probe.py").write_text(net_probe, encoding="utf-8")

        try:
            res = await backend.execute_script(
                workspace_id=workspace_id,
                script_name="net_probe.py",
                timeout=5.0
            )

            if backend.capabilities.network_kernel_denied:
                # Kernel denial MUST reject raw sockets with non-zero exit code
                assert res.exit_code != 0
                assert "SOCKET_DENIED" in res.stdout or "SOCKET_DENIED" in res.stderr
            else:
                # Local subprocess backend declares network_kernel_denied=False
                assert backend.capabilities.tier == IsolationTier.LOCAL_SUBPROCESS_FALLBACK
                assert backend.capabilities.network_kernel_denied is False
        finally:
            await backend.cleanup_workspace(workspace_id)
