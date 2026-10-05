"""
VulnTrace Flakiness, Spoofing, and Tampering Tests (Spec §4.4)
"""

import pytest
from vulntrace.verifier.runner import AntiGamingVerifier
from vulntrace.core.backend import ExecutionBackend, ExecutionCommandResult
from vulntrace.sinks import YamlDeserializationOracle


class MockBackend(ExecutionBackend):
    def __init__(self, run_results):
        self.run_results = list(run_results)
        self.call_count = 0

    @property
    def capabilities(self):
        from vulntrace.core.local_backend import LocalSubprocessBackend
        return LocalSubprocessBackend().capabilities

    async def initialize_workspace(self, source_repo):
        return "/tmp/mock_ws"

    async def provision_dependencies(self, workspace_id, manifest_dependencies, on_log=None):
        return ExecutionCommandResult(exit_code=0, stdout="", stderr="", latency_ms=1.0)

    async def execute_script(self, workspace_id, script_name, timeout=10.0, sentinel_filename=None, on_log=None):
        res = self.run_results[self.call_count]
        self.call_count += 1
        return res

    async def check_sentinel_marker(self, workspace_id, sentinel_filename):
        return False

    async def run_regression_suite(self, workspace_id, timeout=30.0, test_file=None):
        return {"passed": True, "test_count": 2, "latency_ms": 1.0}

    async def cleanup_workspace(self, workspace_id):
        pass

    def generate_attestation(self, workspace_id: str):
        from vulntrace.core.backend import ExecutionAttestation, IsolationTier
        return ExecutionAttestation(
            backend_tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            backend_version="1.0",
            workspace_id=workspace_id,
            container_image_digest=None,
            isolation_features={},
            environment_hash="mock_hash",
            timestamp=1.0,
        )


@pytest.mark.asyncio
async def test_red_3_of_3_flake_detection():
    """Proves that a flaking RED run (e.g. 2 passed, 1 failed) is detected and rejected."""
    # Run 1: passes RED (exit 0, sentinel created)
    # Run 2: passes RED (exit 0, sentinel created)
    # Run 3: fails RED (exit 10, sentinel NOT created)
    results = [
        ExecutionCommandResult(exit_code=0, stdout="", stderr="", sentinel_created=True, assertion_result="RED_PASSED", latency_ms=10.0),
        ExecutionCommandResult(exit_code=0, stdout="", stderr="", sentinel_created=True, assertion_result="RED_PASSED", latency_ms=10.0),
        ExecutionCommandResult(exit_code=10, stdout="", stderr="", sentinel_created=False, assertion_result="INCONCLUSIVE_NO_EFFECT", latency_ms=10.0),
    ]
    mock_backend = MockBackend(results)

    ok, runs, reason = await AntiGamingVerifier.verify_red_reproduction_3x(
        backend=mock_backend,
        workspace_id="/tmp/mock_ws",
        harness_script_name="harness.py",
        sentinel_filename="marker.txt",
        runs_count=3,
    )

    assert ok is False
    assert "RED flake/failure on run 3/3" in reason
    assert len(runs) == 3


@pytest.mark.asyncio
async def test_green_3_of_3_flake_detection():
    """Proves that a flaking GREEN run (e.g. 2 passes, 1 failure) is detected and rejected."""
    oracle = YamlDeserializationOracle()
    sig = oracle.get_expected_block_signature()

    green_res = ExecutionCommandResult(
        exit_code=42,
        stdout='{"assertion": "GREEN_SECURITY_BLOCK_VERIFIED"}',
        stderr="",
        sentinel_created=False,
        assertion_result="GREEN_SECURITY_BLOCK_VERIFIED",
        exception_type="ConstructorError",
        structured_evidence={
            "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
            "exception_type": "ConstructorError",
            "positive_control_passed": True,
            "expected_security_exception": True,
        },
        latency_ms=10.0,
    )
    flake_res = ExecutionCommandResult(
        exit_code=1,
        stdout="",
        stderr="Traceback: TypeError",
        sentinel_created=False,
        assertion_result="UNEXPECTED_FAILURE",
        exception_type="TypeError",
        structured_evidence={"assertion": "UNEXPECTED_FAILURE", "positive_control_passed": False},
        latency_ms=10.0,
    )

    mock_backend = MockBackend([green_res, green_res, flake_res])

    ok, runs, reason = await AntiGamingVerifier.verify_green_remediation_3x(
        backend=mock_backend,
        workspace_id="/tmp/mock_ws",
        harness_script_name="harness.py",
        sentinel_filename="marker.txt",
        expected_signature=sig,
        runs_count=3,
    )

    assert ok is False
    assert "GREEN verification failed on run 3/3" in reason
    assert len(runs) == 3


@pytest.mark.asyncio
async def test_harness_crash_exit_42_cannot_forge_green():
    """
    Explicit AC test: A process/harness crash or direct process exit that yields code 42
    WITHOUT valid structured JSON evidence asserting GREEN_SECURITY_BLOCK_VERIFIED
    and positive controls CANNOT produce GREEN.
    """
    oracle = YamlDeserializationOracle()
    sig = oracle.get_expected_block_signature()

    # Process exited with code 42, but stdout is empty or a crash traceback
    crashed_res = ExecutionCommandResult(
        exit_code=42,
        stdout="",
        stderr="Process aborted with exit 42",
        sentinel_created=False,
        assertion_result="",
        structured_evidence=None,
        latency_ms=5.0,
    )
    mock_backend = MockBackend([crashed_res])

    ok, runs, reason = await AntiGamingVerifier.verify_green_remediation_3x(
        backend=mock_backend,
        workspace_id="/tmp/mock_ws",
        harness_script_name="harness.py",
        sentinel_filename="marker.txt",
        expected_signature=sig,
        runs_count=1,
    )

    assert ok is False
    assert "GREEN verification failed" in reason
    assert runs[0].is_valid_green is False


@pytest.mark.asyncio
async def test_wrong_exception_signature_cannot_produce_green():
    """Proves that exit 42 with an unexpected exception type (e.g. ZeroDivisionError) is rejected."""
    oracle = YamlDeserializationOracle()
    sig = oracle.get_expected_block_signature()

    mismatched_res = ExecutionCommandResult(
        exit_code=42,
        stdout="",
        stderr="",
        sentinel_created=False,
        assertion_result="GREEN_SECURITY_BLOCK_VERIFIED",
        exception_type="ZeroDivisionError",
        structured_evidence={
            "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
            "exception_type": "ZeroDivisionError",
            "positive_control_passed": True,
        },
        latency_ms=5.0,
    )
    mock_backend = MockBackend([mismatched_res])

    ok, runs, reason = await AntiGamingVerifier.verify_green_remediation_3x(
        backend=mock_backend,
        workspace_id="/tmp/mock_ws",
        harness_script_name="harness.py",
        sentinel_filename="marker.txt",
        expected_signature=sig,
        runs_count=1,
    )

    assert ok is False
    assert "does not match expected block signature" in reason
