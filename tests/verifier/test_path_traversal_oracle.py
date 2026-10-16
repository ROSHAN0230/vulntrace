"""
VulnTrace Path-Traversal Sink-Class Oracle & Bad-Patch Zoo Tests (Spec §4.3, M7)

Comprehensive verification suite:
1. Oracle registration & symbol lookup.
2. Probe safety (behavioral, no shells, no network, non-destructive).
3. Disposable workspace canary containment (inside disposable parent, outside extraction root).
4. Expected block signature matching (rejects generic exceptions, accepts security blocks).
5. Benign contract evaluation.
6. Safe ZIP control verification (Amendment A.4).
7. Vulnerable fixture reproduction (RED 3/3).
8. Fixed fixture verification (GREEN 3/3, positive control, harness hash immutability).
9. Adversarial Bad-Patch Zoo evaluation (10 adversarial mutations, zero false GREENs).
10. Python >= 3.11 compatibility.
"""

import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
import pytest

from vulntrace.agent.harness_synthesizer import HarnessSynthesizer
from vulntrace.models import HarnessGenerateRequest
from vulntrace.sandbox.runner import SubprocessSandboxRunner
from vulntrace.sinks import (
    SinkOracleRegistry,
    TarPathTraversalOracle,
    ZipSafeControlOracle,
    SinkClass,
)
from vulntrace.verifier.anti_gaming import PatchDenylistValidator, IntegrityAuditor

TAR_VULNERABLE_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "path_traversal" / "tar_vulnerable"
)
TAR_FIXED_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "path_traversal" / "tar_fixed"
)


# ==============================================================================
# Unit Tests: Oracle Registration, Probes, Signatures, Safe Control
# ==============================================================================

def test_path_traversal_registry_lookup():
    """Proves SinkOracleRegistry discovers TarPathTraversalOracle and ZipSafeControlOracle."""
    tar_oracle = SinkOracleRegistry.get_oracle_for_symbol("tarfile.extractall")
    assert tar_oracle is not None
    assert isinstance(tar_oracle, TarPathTraversalOracle)
    assert tar_oracle.sink_class == SinkClass.PATH_TRAVERSAL

    zip_oracle = SinkOracleRegistry.get_oracle_for_symbol("zipfile.extractall")
    assert zip_oracle is not None
    assert isinstance(zip_oracle, ZipSafeControlOracle)
    assert zip_oracle.sink_class == SinkClass.PATH_TRAVERSAL


def test_tar_oracle_probe_safety():
    """Proves Tar traversal probe is strictly non-destructive, shell-free, and network-free."""
    oracle = TarPathTraversalOracle()
    probe = oracle.get_probe("sentinel_escape.marker")
    assert probe.is_destructive is False
    assert probe.requires_network is False
    assert probe.requires_shell is False
    assert "sentinel_escape.marker" in probe.payload_expr
    assert "member_escape" in probe.payload_expr


def test_tar_expected_block_signature_matching():
    """Proves that block signatures accept authentic path-traversal exceptions and reject generic crashes."""
    oracle = TarPathTraversalOracle()
    sig = oracle.get_expected_block_signature()

    # Valid security blocks
    assert sig.matches("ValueError") is True
    assert sig.matches("PermissionError") is True
    assert sig.matches("FilterError") is True
    assert sig.matches("tarfile.FilterError") is True
    assert sig.matches("SecurityError") is True
    assert sig.matches("PathTraversalError") is True

    # Generic crashes must NEVER match
    assert sig.matches("Exception") is False
    assert sig.matches("RuntimeError") is False
    assert sig.matches("ZeroDivisionError") is False
    assert sig.matches("TypeError") is False
    assert sig.matches("ImportError") is False
    assert sig.matches("") is False


def test_tar_safe_patterns():
    """Proves that safe patterns provide documented, inspectable remediation examples."""
    oracle = TarPathTraversalOracle()
    patterns = oracle.get_safe_patterns()
    assert len(patterns) >= 2
    pattern_ids = [p.pattern_id for p in patterns]
    assert "tarfile_member_containment_check" in pattern_ids
    assert any("commonpath" in p.example_snippet or "startswith" in p.example_snippet for p in patterns)


def test_tar_benign_contracts():
    """Proves that positive control contracts evaluate benign extraction outputs."""
    oracle = TarPathTraversalOracle()
    contracts = oracle.get_benign_contracts()
    assert len(contracts) >= 2

    contract = next(c for c in contracts if c.case_id == "safe_relative_config")
    ok, _ = oracle.evaluate_benign_output(contract, {"status": "OK", "extracted_files": ["a.txt"]})
    assert ok is True

    # None fails
    ok, msg = oracle.evaluate_benign_output(contract, None)
    assert ok is False
    assert "cannot be None" in msg

    # Missing key fails
    ok, msg = oracle.evaluate_benign_output(contract, {"status": "OK"})
    assert ok is False
    assert "Missing required top-level key" in msg


def test_zip_safe_control_normalizes_relative_paths(tmp_path: Path):
    """
    Proves Amendment A.4: Python stdlib zipfile.ZipFile.extractall inherently strips
    and normalizes '..' member paths, acting as a verified safe control.
    """
    zip_path = tmp_path / "test_traversal.zip"
    dest_dir = tmp_path / "extracted"
    dest_dir.mkdir()

    # Write a zip entry with '../escaped_zip.txt'
    with zipfile.ZipFile(zip_path, "w") as z:
        zinfo = zipfile.ZipInfo("../escaped_zip.txt")
        z.writestr(zinfo, b"ZIP_ESCAPED_DATA")

    # Extract with stdlib zipfile
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(dest_dir)

    # The file must NOT escape to tmp_path; stdlib normalizes to inside dest_dir
    assert not (tmp_path / "escaped_zip.txt").exists()
    assert (dest_dir / "escaped_zip.txt").exists()


def test_tar_traversal_archive_creation(tmp_path: Path):
    """Proves that create_traversal_archive builds a valid tar archive with traversal and benign entries."""
    archive_path = tmp_path / "test.tar"
    TarPathTraversalOracle.create_traversal_archive(archive_path, "canary.txt", "safe.txt")

    assert archive_path.exists()
    with tarfile.open(archive_path, "r") as tar:
        names = tar.getnames()
        assert "../canary.txt" in names
        assert "safe.txt" in names


# ==============================================================================
# Verifier Tests: RED 3/3, GREEN 3/3, Harness Immutability
# ==============================================================================

def test_vulnerable_tar_fixture_produces_red_3_of_3():
    """
    Executes the vulnerable tar fixture 3 times.
    Proves that the canary is created outside 'extracted/', but inside the disposable workspace,
    producing RED_PASSED (Exit 0) 3/3 times.
    """
    for run_idx in range(3):
        temp_dir = Path(tempfile.mkdtemp(prefix=f"red_ws_{run_idx}_"))
        try:
            shutil.copytree(TAR_VULNERABLE_FIXTURE, temp_dir, dirs_exist_ok=True)
            sentinel_name = f"canary_red_{run_idx}.marker"

            hreq = HarnessGenerateRequest(
                repo_path=str(temp_dir),
                cve_id="CVE-2007-4559",
                target_file="archive_extractor.py",
                function_name="extract_archive",
                vulnerable_call="tarfile.extractall",
                sentinel_filename=sentinel_name,
            )
            hres = HarnessSynthesizer.synthesize_harness(hreq)
            harness_path = temp_dir / "harness_verify.py"
            harness_path.write_text(hres.harness_code, encoding="utf-8")

            res = SubprocessSandboxRunner.execute_script(
                disposable_dir=temp_dir,
                script_name="harness_verify.py",
                sentinel_filename=sentinel_name,
            )

            assert res.exit_code == 0, f"Run {run_idx} failed: {res.stdout}\n{res.stderr}"
            assert res.sentinel_created is True
            assert "RED_PASSED" in res.stdout
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


def test_fixed_tar_fixture_produces_green_3_of_3():
    """
    Executes the fixed tar fixture 3 times.
    Proves that:
    1. Traversal member triggers expected security exception (ValueError).
    2. Canary file is absent.
    3. Positive control succeeds (benign files extract).
    4. Exit code is 42 (GREEN_SECURITY_BLOCK_VERIFIED) 3/3 times.
    5. Pre/post harness SHA-256 remains identical.
    """
    import hashlib

    for run_idx in range(3):
        temp_dir = Path(tempfile.mkdtemp(prefix=f"green_ws_{run_idx}_"))
        try:
            shutil.copytree(TAR_FIXED_FIXTURE, temp_dir, dirs_exist_ok=True)
            sentinel_name = f"canary_green_{run_idx}.marker"

            hreq = HarnessGenerateRequest(
                repo_path=str(temp_dir),
                cve_id="CVE-2007-4559",
                target_file="archive_extractor.py",
                function_name="extract_archive",
                vulnerable_call="tarfile.extractall",
                sentinel_filename=sentinel_name,
            )
            hres = HarnessSynthesizer.synthesize_harness(hreq)
            harness_path = temp_dir / "harness_verify.py"
            harness_path.write_text(hres.harness_code, encoding="utf-8")

            # Snapshot pre-execution hash
            pre_hash = hashlib.sha256(harness_path.read_bytes()).hexdigest()

            res = SubprocessSandboxRunner.execute_script(
                disposable_dir=temp_dir,
                script_name="harness_verify.py",
                sentinel_filename=sentinel_name,
            )

            # Post-execution hash check
            post_hash = hashlib.sha256(harness_path.read_bytes()).hexdigest()
            assert pre_hash == post_hash, "Harness was tampered with during execution"

            assert res.exit_code == 42, f"Run {run_idx} did not exit 42: {res.stdout}\n{res.stderr}"
            assert res.sentinel_created is False
            assert "GREEN_SECURITY_BLOCK_VERIFIED" in res.stdout
            assert "ValueError" in res.stdout
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Bad-Patch Zoo for Path Traversal (10 Adversarial Mutations)
# ==============================================================================

@pytest.fixture
def zoo_ws():
    temp_dir = Path(tempfile.mkdtemp(prefix="pt_zoo_ws_"))
    try:
        shutil.copytree(TAR_VULNERABLE_FIXTURE, temp_dir, dirs_exist_ok=True)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _eval_patch(
    workspace: Path,
    patch_code: str,
    target_rel: str = "archive_extractor.py",
    func_name: str = "extract_archive",
    tamper_harness: bool = False,
    tamper_tests: bool = False,
):
    target_path = workspace / target_rel
    orig_code = target_path.read_text(encoding="utf-8")

    pre_hashes = IntegrityAuditor.snapshot_hashes(workspace, target_rel_file=target_rel)

    touched = [target_rel]
    if tamper_tests:
        touched.append("tests/test_extractor.py")
    if tamper_harness:
        touched.append("harness_verify.py")

    denylist_res = PatchDenylistValidator.validate_patch(
        orig_code=orig_code,
        patched_code=patch_code,
        target_function_name=func_name,
        touched_files=touched,
        allowed_target_file=target_rel,
    )
    if not denylist_res.allowed:
        return {"passed": False, "reason": f"DENYLIST_REJECTED: {denylist_res.violations}"}

    # Synthesize harness
    sentinel_name = "zoo_sentinel.marker"
    hreq = HarnessGenerateRequest(
        repo_path=str(workspace),
        cve_id="CVE-2007-4559",
        target_file=target_rel,
        function_name=func_name,
        vulnerable_call="tarfile.extractall",
        sentinel_filename=sentinel_name,
    )
    hres = HarnessSynthesizer.synthesize_harness(hreq)
    harness_path = workspace / "harness_verify.py"
    harness_path.write_text(hres.harness_code, encoding="utf-8")

    # Apply candidate patch
    target_path.write_text(patch_code, encoding="utf-8")

    # Integrity audit
    integrity_ok, integrity_violations = IntegrityAuditor.verify_integrity(
        pre_hashes=pre_hashes,
        current_dir=workspace,
        target_rel_file=target_rel,
    )
    if not integrity_ok:
        return {"passed": False, "reason": f"INTEGRITY_TAMPERING: {integrity_violations}"}

    # Execute harness against candidate patch
    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=workspace,
        script_name="harness_verify.py",
        sentinel_filename=sentinel_name,
    )

    if res.exit_code == 42 and not res.sentinel_created:
        return {"passed": True, "reason": "GREEN_SECURITY_BLOCK_VERIFIED"}
    return {"passed": False, "reason": f"NON_GREEN (Exit {res.exit_code}): {res.stdout.strip()}"}


def test_zoo_1_unconditional_exception(zoo_ws):
    """Bad patch 1: Raises an unconditional exception without performing benign extraction."""
    bad_code = """
import tarfile
def extract_archive(archive_path: str, extract_to: str = 'extracted') -> None:
    raise ValueError('Unconditional block error')
"""
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False
    assert "Contract" in res["reason"] or "NON_GREEN" in res["reason"]


def test_zoo_2_return_none(zoo_ws):
    """Bad patch 2: Returns immediately without extracting."""
    bad_code = """
import tarfile
def extract_archive(archive_path: str, extract_to: str = 'extracted') -> None:
    return None
"""
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False
    assert "INCONCLUSIVE" in res["reason"] or "NON_GREEN" in res["reason"]


def test_zoo_3_delete_target_function(zoo_ws):
    """Bad patch 3: Deletes the target function."""
    bad_code = "# Target function deleted entirely"
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False
    assert "DENYLIST_REJECTED" in res["reason"]


def test_zoo_4_comment_out_sink(zoo_ws):
    """Bad patch 4: Comments out tarfile.extractall."""
    bad_code = """
import tarfile
from pathlib import Path
def extract_archive(archive_path: str, extract_to: str = 'extracted') -> None:
    dest = Path(extract_to)
    dest.mkdir(parents=True, exist_ok=True)
    # tar.extractall commented out
"""
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False


def test_zoo_5_broad_try_except_pass(zoo_ws):
    """Bad patch 5: Wraps sink in broad try/except: pass."""
    bad_code = """
import tarfile
from pathlib import Path
def extract_archive(archive_path: str, extract_to: str = 'extracted') -> None:
    dest = Path(extract_to)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, 'r:*') as tar:
            tar.extractall(path=dest)
    except:
        pass
"""
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False
    assert "DENYLIST_REJECTED" in res["reason"] or "NON_GREEN" in res["reason"]


def test_zoo_6_inject_sys_exit_42(zoo_ws):
    """Bad patch 6: Attempts to forge green by calling sys.exit(42)."""
    bad_code = """
import sys
def extract_archive(archive_path: str, extract_to: str = 'extracted') -> None:
    sys.exit(42)
"""
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False
    assert "DENYLIST_REJECTED" in res["reason"]


def test_zoo_7_modify_harness(zoo_ws):
    """Bad patch 7: Attempts to modify the verification harness."""
    good_patch = TAR_FIXED_FIXTURE.joinpath("archive_extractor.py").read_text(encoding="utf-8")
    res = _eval_patch(zoo_ws, good_patch, tamper_harness=True)
    assert res["passed"] is False
    assert "DENYLIST_REJECTED" in res["reason"] or "INTEGRITY_TAMPERING" in res["reason"]


def test_zoo_8_patch_tests_only(zoo_ws):
    """Bad patch 8: Modifies test files outside allowed target file."""
    good_patch = TAR_FIXED_FIXTURE.joinpath("archive_extractor.py").read_text(encoding="utf-8")
    res = _eval_patch(zoo_ws, good_patch, tamper_tests=True)
    assert res["passed"] is False
    assert "DENYLIST_REJECTED" in res["reason"]


def test_zoo_9_change_sentinel_path(zoo_ws):
    """Bad patch 9: Attempts to change or delete the sentinel variable."""
    bad_code = """
import tarfile
from pathlib import Path
def extract_archive(archive_path: str, extract_to: str = 'extracted') -> None:
    # Deliberately unlinks any sentinel before returning
    p = Path('zoo_sentinel.marker')
    if p.exists():
        p.unlink()
"""
    res = _eval_patch(zoo_ws, bad_code)
    assert res["passed"] is False


def test_zoo_10_empty_diff(zoo_ws):
    """Bad patch 10: Empty diff (unpatched code)."""
    orig_code = TAR_VULNERABLE_FIXTURE.joinpath("archive_extractor.py").read_text(encoding="utf-8")
    res = _eval_patch(zoo_ws, orig_code)
    assert res["passed"] is False
    assert "DENYLIST_REJECTED" in res["reason"]


def test_zoo_legitimate_patch_passes(zoo_ws):
    """Legitimate patch: Passes all verifier gates and achieves GREEN_SECURITY_BLOCK_VERIFIED."""
    legitimate_code = TAR_FIXED_FIXTURE.joinpath("archive_extractor.py").read_text(encoding="utf-8")
    res = _eval_patch(zoo_ws, legitimate_code)
    assert res["passed"] is True
    assert res["reason"] == "GREEN_SECURITY_BLOCK_VERIFIED"
