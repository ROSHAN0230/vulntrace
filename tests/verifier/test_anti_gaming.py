"""
VulnTrace Anti-Gaming Verifier Unit Tests (Spec §4.4)
"""

import tempfile
import shutil
from pathlib import Path
import pytest

from vulntrace.verifier.anti_gaming import (
    PatchDenylistValidator,
    IntegrityAuditor,
)


ORIG_CODE = """import yaml

def load_app_settings(blob: str) -> dict:
    data = yaml.load(blob, Loader=yaml.Loader)
    if isinstance(data, dict):
        return data
    return {"settings": data}
"""

LEGIT_PATCH = """import yaml

def load_app_settings(blob: str) -> dict:
    data = yaml.safe_load(blob)
    if isinstance(data, dict):
        return data
    return {"settings": data}
"""


def test_denylist_passes_legitimate_patch():
    """Proves that authentic safe patches pass all denylist checks."""
    res = PatchDenylistValidator.validate_patch(
        orig_code=ORIG_CODE,
        patched_code=LEGIT_PATCH,
        target_function_name="load_app_settings",
        allowed_target_file="config_parser.py",
    )
    assert res.allowed is True
    assert len(res.violations) == 0


def test_denylist_catches_sys_exit():
    """Proves that injecting sys.exit(42) is caught and rejected."""
    bad_code = """import yaml, sys

def load_app_settings(blob: str) -> dict:
    sys.exit(42)
"""
    res = PatchDenylistValidator.validate_patch(
        orig_code=ORIG_CODE,
        patched_code=bad_code,
        target_function_name="load_app_settings",
    )
    assert res.allowed is False
    assert any("sys.exit" in v for v in res.violations)


def test_denylist_catches_os_exit_and_kill():
    """Proves that os._exit and os.kill are caught and rejected."""
    bad_code_1 = """import yaml, os

def load_app_settings(blob: str) -> dict:
    os._exit(0)
"""
    res_1 = PatchDenylistValidator.validate_patch(ORIG_CODE, bad_code_1)
    assert res_1.allowed is False
    assert any("os._exit" in v for v in res_1.violations)

    bad_code_2 = """import yaml, os

def load_app_settings(blob: str) -> dict:
    os.kill(os.getpid(), 9)
"""
    res_2 = PatchDenylistValidator.validate_patch(ORIG_CODE, bad_code_2)
    assert res_2.allowed is False
    assert any("os.kill" in v for v in res_2.violations)


def test_denylist_catches_builtin_exit():
    """Proves that bare exit() or quit() calls are caught and rejected."""
    bad_code = """import yaml

def load_app_settings(blob: str) -> dict:
    exit()
"""
    res = PatchDenylistValidator.validate_patch(ORIG_CODE, bad_code)
    assert res.allowed is False
    assert any("exit()" in v for v in res.violations)


def test_denylist_catches_broad_except_pass():
    """Proves that wrapping in try/except: pass is caught and rejected."""
    bad_code_1 = """import yaml

def load_app_settings(blob: str) -> dict:
    try:
        return yaml.load(blob, Loader=yaml.Loader)
    except:
        pass
    return {}
"""
    res_1 = PatchDenylistValidator.validate_patch(ORIG_CODE, bad_code_1)
    assert res_1.allowed is False
    assert any("broad try/except: pass" in v for v in res_1.violations)

    bad_code_2 = """import yaml

def load_app_settings(blob: str) -> dict:
    try:
        return yaml.load(blob, Loader=yaml.Loader)
    except Exception:
        return None
"""
    res_2 = PatchDenylistValidator.validate_patch(ORIG_CODE, bad_code_2)
    assert res_2.allowed is False
    assert any("broad try/except: pass" in v for v in res_2.violations)


def test_denylist_catches_function_deletion():
    """Proves that deleting the target function is caught and rejected."""
    bad_code = """import yaml
# load_app_settings was deleted!
"""
    res = PatchDenylistValidator.validate_patch(
        orig_code=ORIG_CODE,
        patched_code=bad_code,
        target_function_name="load_app_settings",
    )
    assert res.allowed is False
    assert any("was deleted" in v for v in res.violations)


def test_denylist_catches_empty_diff():
    """Proves that empty or whitespace diffs are caught and rejected."""
    res_empty = PatchDenylistValidator.validate_patch(ORIG_CODE, "")
    assert res_empty.allowed is False
    assert any("Empty" in v for v in res_empty.violations)

    res_same = PatchDenylistValidator.validate_patch(ORIG_CODE, ORIG_CODE + "   \n")
    assert res_same.allowed is False
    assert any("Empty or whitespace-only" in v for v in res_same.violations)


def test_denylist_catches_file_scope_violations():
    """Proves that modifying restricted files (tests, harness, configs) is caught and rejected."""
    res = PatchDenylistValidator.validate_patch(
        orig_code=ORIG_CODE,
        patched_code=LEGIT_PATCH,
        touched_files=["config_parser.py", "tests/test_config.py"],
        allowed_target_file="config_parser.py",
    )
    assert res.allowed is False
    assert any("restricted file 'tests/test_config.py'" in v for v in res.violations)


@pytest.fixture
def temp_workspace():
    d = Path(tempfile.mkdtemp(prefix="test_integrity_"))
    try:
        (d / "config_parser.py").write_text(ORIG_CODE, encoding="utf-8")
        tests_dir = d / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "test_config.py").write_text("# Test content", encoding="utf-8")
        (d / "harness_eval.py").write_text("# Harness content", encoding="utf-8")
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_integrity_auditor_detects_harness_tampering(temp_workspace):
    """Proves that modifying the harness file fails SHA-256 integrity verification."""
    pre_hashes = IntegrityAuditor.snapshot_hashes(temp_workspace, target_rel_file="config_parser.py")

    # Tamper with harness file
    (temp_workspace / "harness_eval.py").write_text("# Tampered harness!", encoding="utf-8")

    ok, violations = IntegrityAuditor.verify_integrity(pre_hashes, temp_workspace, target_rel_file="config_parser.py")
    assert ok is False
    assert any("harness_eval.py" in v for v in violations)


def test_integrity_auditor_detects_test_tampering(temp_workspace):
    """Proves that modifying test files fails SHA-256 integrity verification."""
    pre_hashes = IntegrityAuditor.snapshot_hashes(temp_workspace, target_rel_file="config_parser.py")

    # Tamper with test file
    (temp_workspace / "tests" / "test_config.py").write_text("def test_dummy(): pass\n", encoding="utf-8")

    ok, violations = IntegrityAuditor.verify_integrity(pre_hashes, temp_workspace, target_rel_file="config_parser.py")
    assert ok is False
    assert any("test_config.py" in v for v in violations)


def test_integrity_auditor_allows_target_file_modifications(temp_workspace):
    """Proves that modifying ONLY the declared target file preserves integrity."""
    pre_hashes = IntegrityAuditor.snapshot_hashes(temp_workspace, target_rel_file="config_parser.py")

    # Legitimate edit to target file
    (temp_workspace / "config_parser.py").write_text(LEGIT_PATCH, encoding="utf-8")

    ok, violations = IntegrityAuditor.verify_integrity(pre_hashes, temp_workspace, target_rel_file="config_parser.py")
    assert ok is True
    assert len(violations) == 0
