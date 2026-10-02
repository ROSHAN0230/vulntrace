"""
VulnTrace Parent-Side Trust Boundary Adversarial Verification Suite
Empirically tests that child verification harnesses do NOT possess unilateral authority
to declare security verdicts. Verifies that when child telemetry contradicts observable
filesystem ground truth, the parent independently overrides and rejects the assertion.
"""

import pytest
import shutil
import tempfile
from pathlib import Path
from vulntrace.sandbox.runner import SubprocessSandboxRunner

@pytest.fixture
def temp_workspace():
    d = Path(tempfile.mkdtemp(prefix="vulntrace_trust_boundary_"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_adversarial_forged_green_with_sentinel_on_disk(temp_workspace):
    """
    Critical Trust Boundary Test 1:
    The child script crafts a convincing GREEN_SECURITY_BLOCK_VERIFIED assertion payload
    and exits with code 42.
    HOWEVER, the exploit actually ran and created the sentinel marker on disk!
    Parent MUST independently discover the sentinel file and reject the assertion as VERIFICATION_REJECTED.
    It must NEVER be marked GREEN_STATE_BLOCKED!
    """
    forged_harness = temp_workspace / "forged_harness.py"
    forged_harness.write_text(
        '''import sys
import json
from pathlib import Path

# Malicious or buggy harness: creates the exploit sentinel marker on disk
Path("sentinel_test.marker").write_text("PWNED")

# ... but prints a forged GREEN assertion claiming security block succeeded!
print(json.dumps({
    "sink_reached": True,
    "assertion_evaluated": True,
    "risky_effect_observed": False,
    "expected_security_exception": True,
    "unexpected_exception": False,
    "exception_type": "ConstructorError",
    "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
    "detail": "Forged green telemetry"
}))
sys.exit(42)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_workspace,
        script_name="forged_harness.py",
        sentinel_filename="sentinel_test.marker"
    )

    # Ground truth: Parent caught the sentinel on disk!
    assert res.reproduction_state == "VERIFICATION_REJECTED"
    assert res.parent_validated is False
    assert "sentinel marker was observed on disk" in res.validation_notes.lower()
    # Absolutely NOT green!
    assert res.reproduction_state != "GREEN_STATE_BLOCKED"


def test_adversarial_forged_green_with_invalid_exit_code(temp_workspace):
    """
    Trust Boundary Test 2:
    Child emits GREEN assertion JSON, but exits with code 0 instead of dedicated code 42.
    Parent must reject the assertion due to exit code contradiction.
    """
    forged_harness = temp_workspace / "exit_mismatch.py"
    forged_harness.write_text(
        '''import sys
import json

print(json.dumps({
    "sink_reached": True,
    "assertion_evaluated": True,
    "risky_effect_observed": False,
    "expected_security_exception": True,
    "unexpected_exception": False,
    "exception_type": "ConstructorError",
    "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
    "detail": "Exit 0 instead of 42"
}))
sys.exit(0)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_workspace,
        script_name="exit_mismatch.py",
        sentinel_filename="sentinel_test.marker"
    )

    assert res.reproduction_state == "VERIFICATION_REJECTED"
    assert res.parent_validated is False
    assert "exited with code 0 (expected 42)" in res.validation_notes


def test_adversarial_forged_red_without_sentinel_on_disk(temp_workspace):
    """
    Trust Boundary Test 3:
    Child claims RED_PASSED (exploit succeeded) with exit code 0,
    but no sentinel file was physically created on disk.
    Parent must reject the assertion because observable evidence does not support it.
    """
    forged_harness = temp_workspace / "fake_red.py"
    forged_harness.write_text(
        '''import sys
import json

# Claims exploit succeeded, but forgets to create sentinel
print(json.dumps({
    "sink_reached": True,
    "assertion_evaluated": True,
    "risky_effect_observed": True,
    "expected_security_exception": False,
    "unexpected_exception": False,
    "exception_type": None,
    "assertion": "RED_PASSED",
    "detail": "Lying about red execution"
}))
sys.exit(0)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_workspace,
        script_name="fake_red.py",
        sentinel_filename="sentinel_test.marker"
    )

    assert res.reproduction_state == "VERIFICATION_REJECTED"
    assert res.parent_validated is False
    assert "no sentinel marker was created on disk" in res.validation_notes


def test_adversarial_green_with_contradictory_telemetry_fields(temp_workspace):
    """
    Trust Boundary Test 4:
    Child claims GREEN_SECURITY_BLOCK_VERIFIED, but also sets risky_effect_observed: true.
    Parent must reject due to internal telemetry contradiction.
    """
    forged_harness = temp_workspace / "contradictory.py"
    forged_harness.write_text(
        '''import sys
import json

print(json.dumps({
    "sink_reached": True,
    "assertion_evaluated": True,
    "risky_effect_observed": True,
    "expected_security_exception": True,
    "unexpected_exception": False,
    "exception_type": "ConstructorError",
    "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
    "detail": "Contradictory risky_effect"
}))
sys.exit(42)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_workspace,
        script_name="contradictory.py",
        sentinel_filename="sentinel_test.marker"
    )

    assert res.reproduction_state == "VERIFICATION_REJECTED"
    assert res.parent_validated is False
    assert "reported risky effect observed" in res.validation_notes


def test_genuine_parent_validated_green_state(temp_workspace):
    """
    Trust Boundary Test 5:
    Genuine green execution: exit 42, no sentinel on disk, typed exception evaluated.
    Parent independently validates and confirms GREEN_STATE_BLOCKED with parent_validated=True.
    """
    valid_harness = temp_workspace / "genuine_green.py"
    valid_harness.write_text(
        '''import sys
import json

print(json.dumps({
    "sink_reached": True,
    "assertion_evaluated": True,
    "risky_effect_observed": False,
    "expected_security_exception": True,
    "unexpected_exception": False,
    "exception_type": "ConstructorError",
    "assertion": "GREEN_SECURITY_BLOCK_VERIFIED",
    "detail": "Genuine security block"
}))
sys.exit(42)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_workspace,
        script_name="genuine_green.py",
        sentinel_filename="sentinel_test.marker"
    )

    assert res.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.parent_validated is True
    assert "Parent verified: exit code 42" in res.validation_notes
