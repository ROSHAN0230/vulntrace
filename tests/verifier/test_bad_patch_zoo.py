"""
VulnTrace Bad-Patch Zoo (Spec §4.4)

Systematically evaluates at least 8 adversarial patches against the verifier.
Every bad patch must produce a NON-GREEN verdict.
Proves that a legitimate patch achieves GREEN_STATE_VERIFIED (3/3).
"""

import shutil
import tempfile
from pathlib import Path
import pytest

from vulntrace.sandbox.runner import SubprocessSandboxRunner
from vulntrace.agent.harness_synthesizer import HarnessSynthesizer
from vulntrace.engine.verdict_engine import VerdictEngine
from vulntrace.verifier.anti_gaming import PatchDenylistValidator, IntegrityAuditor
from vulntrace.models import (
    HarnessGenerateRequest,
    RepositoryEvidence,
    AdvisoryEvidence,
    ReachabilityEvidence,
    BehaviorEvidence,
    PatchEvidence,
    RegressionEvidence,
    ExecutionEvidence,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "deserialization" / "yaml_vulnerable"


@pytest.fixture
def zoo_workspace():
    temp_dir = Path(tempfile.mkdtemp(prefix="zoo_ws_"))
    try:
        shutil.copytree(FIXTURE_DIR, temp_dir, dirs_exist_ok=True)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_candidate_evaluation(
    workspace: Path,
    patch_code: str,
    target_rel: str = "config_parser.py",
    func_name: str = "load_app_settings",
    tamper_harness: bool = False,
    tamper_tests: bool = False,
):
    """
    Evaluates a candidate patch through the full anti-gaming verifier pipeline:
    1. Pre-patch SHA-256 snapshot
    2. Denylist validation
    3. Harness synthesis & pre-patch RED reproduction
    4. Patch application & post-patch integrity audit
    5. Post-patch harness execution (GREEN check)
    6. Regression test suite
    7. Final VerdictEngine resolution
    """
    target_path = workspace / target_rel
    orig_code = target_path.read_text(encoding="utf-8")

    # Step 1: Pre-patch Integrity Snapshot
    pre_hashes = IntegrityAuditor.snapshot_hashes(workspace, target_rel_file=target_rel)

    # Step 2: Denylist Validation
    touched = [target_rel]
    if tamper_tests:
        touched.append("tests/test_config.py")
    if tamper_harness:
        touched.append("harness_verify.py")

    denylist_res = PatchDenylistValidator.validate_patch(
        orig_code=orig_code,
        patched_code=patch_code,
        target_function_name=func_name,
        touched_files=touched,
        allowed_target_file=target_rel,
    )

    # Step 3: Synthesize and execute pre-patch harness (RED check)
    hreq = HarnessGenerateRequest(
        repo_path=str(workspace),
        cve_id="CVE-2020-14343",
        target_file=target_rel,
        function_name=func_name,
        vulnerable_call="yaml.load",
        sentinel_filename="zoo_sentinel.marker",
    )
    hres = HarnessSynthesizer.synthesize_harness(hreq)
    harness_path = workspace / "harness_verify.py"
    harness_path.write_text(hres.harness_code, encoding="utf-8")

    # Pre-patch run (expect RED)
    pre_res = SubprocessSandboxRunner.execute_script(
        disposable_dir=workspace,
        script_name="harness_verify.py",
        sentinel_filename="zoo_sentinel.marker",
    )

    # Step 4: Apply candidate patch
    if patch_code.strip():
        target_path.write_text(patch_code, encoding="utf-8")

    if tamper_harness:
        # Malicious patch alters harness directly to print spoofed green
        spoofed_harness = """import sys, json
print(json.dumps({"assertion": "GREEN_SECURITY_BLOCK_VERIFIED", "expected_security_exception": True, "positive_control_passed": True, "sink_reached": True, "assertion_evaluated": True, "risky_effect_observed": False, "unexpected_exception": False, "exception_type": "ConstructorError"}))
sys.exit(42)
"""
        harness_path.write_text(spoofed_harness, encoding="utf-8")

    if tamper_tests:
        # Malicious patch alters tests to pass without fixing code
        test_file = workspace / "tests" / "test_config.py"
        test_file.write_text("def test_dummy(): pass\n", encoding="utf-8")

    # Step 5: Post-patch Integrity Audit
    integrity_ok, integrity_violations = IntegrityAuditor.verify_integrity(
        pre_hashes=pre_hashes,
        current_dir=workspace,
        target_rel_file=target_rel,
    )

    # If denylist or integrity failed, patch is immediately rejected
    if not denylist_res.allowed or not integrity_ok:
        patch_status = "REJECTED_DENYLIST_VIOLATION" if not denylist_res.allowed else "REJECTED_INTEGRITY_VIOLATION"
        patch_err = "; ".join(denylist_res.violations + integrity_violations)

        reg_res = SubprocessSandboxRunner.run_pytest(workspace)

        verdict = VerdictEngine.evaluate(
            cve_id="CVE-2020-14343",
            repo_path=str(workspace),
            repo_ev=RepositoryEvidence(repo_path=str(workspace), python_files_count=2),
            advisory_ev=AdvisoryEvidence(cve_id="CVE-2020-14343", found=True, summary="Zoo test", source_url=""),
            reach_ev=ReachabilityEvidence(target_symbol="yaml.load", discovered_call_sites_count=1, reachable_vulnerabilities_count=1, unreachable_dead_code_count=0, verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"),
            behavior_ev=BehaviorEvidence(
                pre_patch_exit_code=pre_res.exit_code,
                pre_patch_sentinel_observed=pre_res.sentinel_created,
                pre_patch_state=pre_res.reproduction_state,
                pre_patch_assertion=pre_res.assertion_result,
                post_patch_exit_code=-1,
                post_patch_sentinel_observed=False,
                post_patch_state="VERIFICATION_REJECTED",
                parent_validated=False,
                validation_notes=patch_err,
            ),
            patch_ev=PatchEvidence(engine="ZOO_TEST", target_file=target_rel, diff="", validation_status=patch_status, latency_ms=1.0, success=False),
            regression_ev=RegressionEvidence(executed=True, passed=reg_res.get("passed", False), test_count=reg_res.get("test_count", 0), latency_ms=1.0),
            exec_ev=ExecutionEvidence(sandbox_engine=SubprocessSandboxRunner.ENGINE_LABEL, cloud_status="DENIED", disposable_dir=str(workspace)),
        )
        return pre_res, None, reg_res, verdict, patch_err

    # Step 6: Post-patch Execution (GREEN check)
    post_res = SubprocessSandboxRunner.execute_script(
        disposable_dir=workspace,
        script_name="harness_verify.py",
        sentinel_filename="zoo_sentinel.marker",
    )

    # Step 7: Regression Tests
    reg_res = SubprocessSandboxRunner.run_pytest(workspace)

    # Step 8: VerdictEngine Decision
    verdict = VerdictEngine.evaluate(
        cve_id="CVE-2020-14343",
        repo_path=str(workspace),
        repo_ev=RepositoryEvidence(repo_path=str(workspace), python_files_count=2),
        advisory_ev=AdvisoryEvidence(cve_id="CVE-2020-14343", found=True, summary="Zoo test", source_url=""),
        reach_ev=ReachabilityEvidence(target_symbol="yaml.load", discovered_call_sites_count=1, reachable_vulnerabilities_count=1, unreachable_dead_code_count=0, verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"),
        behavior_ev=BehaviorEvidence(
            pre_patch_exit_code=pre_res.exit_code,
            pre_patch_sentinel_observed=pre_res.sentinel_created,
            pre_patch_state=pre_res.reproduction_state,
            pre_patch_assertion=pre_res.assertion_result,
            post_patch_exit_code=post_res.exit_code,
            post_patch_sentinel_observed=post_res.sentinel_created,
            post_patch_state=post_res.reproduction_state,
            post_patch_assertion=post_res.assertion_result,
            parent_validated=post_res.parent_validated,
            validation_notes=post_res.validation_notes,
        ),
        patch_ev=PatchEvidence(engine="ZOO_TEST", target_file=target_rel, diff="+ patch", validation_status="ACCEPTED", latency_ms=1.0, success=True),
        regression_ev=RegressionEvidence(executed=True, passed=reg_res.get("passed", False), test_count=reg_res.get("test_count", 0), latency_ms=1.0),
        exec_ev=ExecutionEvidence(sandbox_engine=SubprocessSandboxRunner.ENGINE_LABEL, cloud_status="DENIED", disposable_dir=str(workspace)),
    )

    return pre_res, post_res, reg_res, verdict, None


# Zoo Table tracker for evidence logging
ZOO_RESULTS = []


def _record_zoo_result(patch_id: str, description: str, verdict_state: str, passed_rule: str):
    ZOO_RESULTS.append({
        "patch_id": patch_id,
        "description": description,
        "verdict": verdict_state,
        "rejection_mechanism": passed_rule,
        "is_green": (verdict_state == "GREEN_STATE_VERIFIED"),
    })


def test_bad_patch_1_unconditional_exception(zoo_workspace):
    """Case 1: Patch unconditionally raises ConstructorError."""
    bad_code = """import yaml
def load_app_settings(blob: str) -> dict:
    raise yaml.constructor.ConstructorError("Adversarial fake block")
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert post.assertion_result == "POSITIVE_CONTROL_FAILED"
    _record_zoo_result("1_unconditional_exception", "Unconditional ConstructorError", verdict.terminal_state, "Positive control failure (benign inputs crashed)")


def test_bad_patch_2_return_none(zoo_workspace):
    """Case 2: Patch returns None."""
    bad_code = """import yaml
def load_app_settings(blob: str) -> dict:
    return None
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert reg["passed"] is False
    _record_zoo_result("2_return_none", "Return None stub", verdict.terminal_state, "Regression failure & positive control type check")


def test_bad_patch_3_delete_target_function(zoo_workspace):
    """Case 3: Patch deletes target function completely."""
    bad_code = """import yaml
# load_app_settings deleted
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert "deleted" in (err or "") or verdict.terminal_state == "PATCH_REJECTED"
    _record_zoo_result("3_delete_target_function", "Deleted target function", verdict.terminal_state, "Patch Denylist (target function deletion)")


def test_bad_patch_4_comment_out_sink(zoo_workspace):
    """Case 4: Patch comments out sink and returns empty dict."""
    bad_code = """import yaml
def load_app_settings(blob: str) -> dict:
    # data = yaml.load(blob, Loader=yaml.Loader)
    return {}
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    _record_zoo_result("4_comment_out_sink", "Commented out sink returning {}", verdict.terminal_state, "Positive control (empty dummy container rejected) & regression")


def test_bad_patch_5_broad_try_except_pass(zoo_workspace):
    """Case 5: Patch wraps sink in broad try/except: pass."""
    bad_code = """import yaml
def load_app_settings(blob: str) -> dict:
    try:
        return yaml.load(blob, Loader=yaml.Loader)
    except Exception:
        pass
    return {}
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert "broad try/except: pass" in (err or "") or verdict.terminal_state == "PATCH_REJECTED"
    _record_zoo_result("5_broad_try_except_pass", "Broad try/except: pass around sink", verdict.terminal_state, "Patch Denylist (broad except error suppression)")


def test_bad_patch_6_sys_exit_42(zoo_workspace):
    """Case 6: Patch injects sys.exit(42) to spoof green exit code."""
    bad_code = """import yaml, sys
def load_app_settings(blob: str) -> dict:
    sys.exit(42)
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert "sys.exit" in (err or "") or verdict.terminal_state == "PATCH_REJECTED"
    _record_zoo_result("6_sys_exit_42", "Injected sys.exit(42)", verdict.terminal_state, "Patch Denylist & anti-spoofing structured evidence check")


def test_bad_patch_7_modify_harness(zoo_workspace):
    """Case 7: Patch tampers with harness file directly."""
    vulnerable_code = """import yaml
def load_app_settings(blob: str) -> dict:
    return yaml.load(blob, Loader=yaml.Loader)
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, vulnerable_code, tamper_harness=True)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert "Integrity violation" in (err or "") or verdict.terminal_state in ["PATCH_REJECTED", "VERIFICATION_REJECTED"]
    _record_zoo_result("7_modify_harness", "Tampered verification harness", verdict.terminal_state, "Integrity Auditor (protected harness modified)")


def test_bad_patch_8_patch_tests_only(zoo_workspace):
    """Case 8: Patch modifies regression tests instead of fixing target."""
    vulnerable_code = """import yaml
def load_app_settings(blob: str) -> dict:
    return yaml.load(blob, Loader=yaml.Loader)
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, vulnerable_code, tamper_tests=True)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert "Integrity violation" in (err or "") or verdict.terminal_state in ["PATCH_REJECTED", "VERIFICATION_REJECTED"]
    _record_zoo_result("8_patch_tests_only", "Tampered regression tests", verdict.terminal_state, "Integrity Auditor (tests modified outside target file)")


def test_bad_patch_9_change_sentinel_path(zoo_workspace):
    """Case 9: Patch tries to evade detection by redirecting or writing another file."""
    bad_code = """import yaml
def load_app_settings(blob: str) -> dict:
    with open("evasion_marker.marker", "w") as f:
        f.write("evasion")
    return yaml.load(blob, Loader=yaml.Loader)
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, bad_code)
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert post.exit_code == 0 or post.reproduction_state != "GREEN_STATE_BLOCKED"
    _record_zoo_result("9_change_sentinel_path", "Tampered sentinel redirection", verdict.terminal_state, "Post-patch sentinel creation & red state persists")


def test_bad_patch_10_empty_diff(zoo_workspace):
    """Case 10: Empty or whitespace-only patch diff."""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, "")
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert "Empty" in (err or "") or verdict.terminal_state == "PATCH_REJECTED"
    _record_zoo_result("10_empty_diff", "Empty / whitespace diff", verdict.terminal_state, "Patch Denylist (empty diff rejected)")


def test_good_patch_produces_green_3_of_3(zoo_workspace):
    """Legitimate patch: Uses yaml.safe_load and achieves GREEN_STATE_VERIFIED."""
    good_code = """import yaml
def load_app_settings(blob: str) -> dict:
    data = yaml.safe_load(blob)
    if isinstance(data, dict):
        return data
    return {"settings": data}
"""
    pre, post, reg, verdict, err = _run_candidate_evaluation(zoo_workspace, good_code)
    assert verdict.terminal_state == "GREEN_STATE_VERIFIED"
    assert post.exit_code == 42
    assert post.reproduction_state == "GREEN_STATE_BLOCKED"
    assert reg["passed"] is True
    assert reg["test_count"] == 2
    _record_zoo_result("LEGITIMATE_SAFE_LOAD", "Authentic yaml.safe_load patch", verdict.terminal_state, "VERIFIED GREEN (All positive controls and regressions pass)")

    # Print the Bad-Patch Zoo Table
    print("\n" + "=" * 90)
    print("VULNTRACE BAD-PATCH ZOO VERDICT AUDIT TABLE (Spec §4.4)")
    print("=" * 90)
    print(f"{'Patch ID':<30} | {'Terminal Verdict':<24} | {'Rejection Mechanism'}")
    print("-" * 90)
    for res in ZOO_RESULTS:
        print(f"{res['patch_id']:<30} | {res['verdict']:<24} | {res['rejection_mechanism']}")
    print("=" * 90)

    # Verify that ZERO bad patches produced green
    bad_greens = [r for r in ZOO_RESULTS if r["patch_id"] != "LEGITIMATE_SAFE_LOAD" and r["is_green"]]
    assert len(bad_greens) == 0, f"False GREEN detected in bad-patch zoo: {bad_greens}"
