"""
VulnTrace Verifier Red-Team Adversarial Test Suite (P0.1)
Systematically evaluates deliberately invalid and adversarial remediation patches:
1. raise ConstructorError (unconditional exception)
2. raise YAMLError (domain error)
3. raise generic Exception (runtime crash)
4. delete the target function (symbol removal)
5. return None / destroy expected functionality (empty/null stub)
6. bypass vulnerable operation without preserving required behavior (naive safe_load stripping custom !env_var tag)
7. Positive controls: valid YAML parses, nested YAML functional, custom !env_var functional with legitimate AppSafeLoader.

Acceptance:
- No deliberately broken patch produces GREEN_STATE_VERIFIED.
- Legitimate remediation produces GREEN_STATE_VERIFIED only when exploit is blocked AND positive controls pass.
"""

import pytest
import shutil
from pathlib import Path

from vulntrace.sandbox.runner import SubprocessSandboxRunner
from vulntrace.agent.harness_synthesizer import HarnessSynthesizer
from vulntrace.engine.verdict_engine import VerdictEngine
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

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning"


@pytest.fixture
def redteam_workspace():
    """Provides an isolated disposable workspace cloned from benchmarks/contextual_reasoning."""
    ws = SubprocessSandboxRunner.prepare_disposable_workspace(BENCHMARK_DIR)
    try:
        yield ws
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def _evaluate_candidate_patch(
    workspace: Path,
    patch_code: str,
    target_rel: str = "service/custom_loader.py",
    func_name: str = "parse_app_config",
    cve_id: str = "CVE-2020-14343"
):
    """Applies patch code, synthesizes harness, runs harness & pytest, and computes final verdict."""
    target_path = workspace / target_rel
    target_path.write_text(patch_code, encoding="utf-8")

    # 1. Synthesize harness
    hreq = HarnessGenerateRequest(
        repo_path=str(workspace),
        cve_id=cve_id,
        target_file=target_rel,
        function_name=func_name,
        vulnerable_call="yaml.load",
        sentinel_filename="sentinel_redteam.marker"
    )
    hres = HarnessSynthesizer.synthesize_harness(hreq)
    harness_path = workspace / "harness_verify.py"
    harness_path.write_text(hres.harness_code, encoding="utf-8")

    # 2. Execute post-patch harness
    exec_res = SubprocessSandboxRunner.execute_script(
        disposable_dir=workspace,
        script_name="harness_verify.py",
        sentinel_filename="sentinel_redteam.marker"
    )

    # 3. Execute regression tests
    reg_res = SubprocessSandboxRunner.run_pytest(workspace)

    # 4. Compute final verdict via VerdictEngine
    verdict = VerdictEngine.evaluate(
        cve_id=cve_id,
        repo_path=str(workspace),
        repo_ev=RepositoryEvidence(
            repo_path=str(workspace),
            manifest_files=["requirements.txt"],
            python_files_count=3
        ),
        advisory_ev=AdvisoryEvidence(
            cve_id=cve_id,
            found=True,
            summary="Red-team verifier audit",
            source_url="https://osv.dev"
        ),
        reach_ev=ReachabilityEvidence(
            target_symbol="yaml.load",
            discovered_call_sites_count=1,
            reachable_vulnerabilities_count=1,
            unreachable_dead_code_count=0,
            entrypoints=["service/custom_loader.py"],
            verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
        ),
        behavior_ev=BehaviorEvidence(
            pre_patch_exit_code=0,
            pre_patch_sentinel_observed=True,
            pre_patch_state="RED_STATE_REPRODUCED",
            pre_patch_assertion="RED_PASSED",
            post_patch_exit_code=exec_res.exit_code,
            post_patch_sentinel_observed=exec_res.sentinel_created,
            post_patch_state=exec_res.reproduction_state,
            post_patch_assertion=exec_res.assertion_result,
            parent_validated=exec_res.parent_validated,
            validation_notes=exec_res.validation_notes
        ),
        patch_ev=PatchEvidence(
            engine="ADVERSARIAL_PATCH",
            target_file=target_rel,
            diff="+ patch",
            validation_status="ACCEPTED",
            latency_ms=1.0,
            success=True
        ),
        regression_ev=RegressionEvidence(
            executed=True,
            passed=reg_res.get("passed", False),
            test_count=reg_res.get("test_count", 0),
            latency_ms=reg_res.get("latency_ms", 0.0),
            error=reg_res.get("error")
        ),
        exec_ev=ExecutionEvidence(
            sandbox_engine=SubprocessSandboxRunner.ENGINE_LABEL,
            cloud_status="PERMISSION_DENIED (HTTP 403)",
            disposable_dir=str(workspace)
        )
    )

    return exec_res, reg_res, verdict


def test_adversarial_patch_raise_constructor_error(redteam_workspace):
    """
    Adversarial Case 1: Patch unconditionally raises ConstructorError.
    Harness catches in-harness positive control failure; regression tests fail.
    Verdict MUST NOT be GREEN_STATE_VERIFIED.
    """
    broken_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
def parse_app_config(raw_yaml: str) -> dict:
    raise yaml.constructor.ConstructorError("Adversarial fake security block")
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)

    # In-harness positive control caught that benign input failed
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"

    # Regression tests fail
    assert reg_res["passed"] is False

    # Terminal state MUST NOT be GREEN
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
    assert verdict.terminal_state in ["UNEXPECTED_FAILURE", "REGRESSION_FAILURE"]


def test_adversarial_patch_raise_yaml_error(redteam_workspace):
    """
    Adversarial Case 2: Patch unconditionally raises YAMLError.
    Harness catches in-harness positive control failure; regression tests fail.
    Verdict MUST NOT be GREEN_STATE_VERIFIED.
    """
    broken_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
def parse_app_config(raw_yaml: str) -> dict:
    raise yaml.YAMLError("Adversarial YAML error")
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)

    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert reg_res["passed"] is False
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_raise_generic_exception(redteam_workspace):
    """
    Adversarial Case 3: Patch raises generic Exception / RuntimeError.
    Harness catches unexpected exception; regression tests fail.
    Verdict MUST NOT be GREEN_STATE_VERIFIED.
    """
    broken_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
def parse_app_config(raw_yaml: str) -> dict:
    raise RuntimeError("Adversarial unexpected crash")
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)

    assert exec_res.assertion_result == "UNEXPECTED_FAILURE"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state == "UNEXPECTED_FAILURE"
    assert reg_res["passed"] is False
    assert verdict.terminal_state == "UNEXPECTED_FAILURE"


def test_adversarial_patch_delete_target_function(redteam_workspace):
    """
    Adversarial Case 4: Patch deletes the target function completely.
    Harness fails at import time; regression tests fail.
    Verdict MUST NOT be GREEN_STATE_VERIFIED.
    """
    broken_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
# parse_app_config deleted!
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)

    assert exec_res.assertion_result == "UNEXPECTED_FAILURE"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state == "UNEXPECTED_FAILURE"
    assert reg_res["passed"] is False
    assert verdict.terminal_state == "UNEXPECTED_FAILURE"


def test_adversarial_patch_return_none_destroyed_functionality(redteam_workspace):
    """
    Adversarial Case 5: Patch returns None (or empty stub), destroying expected functionality.
    Harness detects positive control failure or inconclusive; regression tests fail.
    Verdict MUST NOT be GREEN_STATE_VERIFIED.
    """
    broken_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
def parse_app_config(raw_yaml: str) -> dict:
    return None
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)

    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert reg_res["passed"] is False
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_bypass_operation_naive_safeload_regression(redteam_workspace):
    """
    Adversarial Case 6: Naive yaml.safe_load bypasses vulnerable operation but strips !env_var.
    Valid YAML and nested YAML parse, but custom !env_var tag fails in regression tests.
    Verdict Engine correctly flags REGRESSION_FAILURE, NOT GREEN_STATE_VERIFIED.
    """
    naive_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
def _env_tag_constructor(loader, node):
    val = loader.construct_scalar(node)
    return os.environ.get(val, f"DEFAULT_{val}")
AppSafeLoader.add_constructor("!env_var", _env_tag_constructor)
yaml.Loader.add_constructor("!env_var", _env_tag_constructor)

def parse_app_config(raw_yaml: str) -> dict:
    # Naive safe_load does not know about custom !env_var tags registered on Loader/AppSafeLoader
    data = yaml.safe_load(raw_yaml)
    if isinstance(data, dict):
        return data
    return {"config": data}
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, naive_code)

    # Harness: safe_load blocks exploit payload and parses benign standard YAML
    assert exec_res.reproduction_state == "GREEN_STATE_BLOCKED"

    # Regression suite: test_custom_env_tag FAILS because SafeLoader lacks !env_var constructor!
    assert reg_res["passed"] is False

    # Verdict Engine MUST catch the regression and refuse GREEN
    assert verdict.terminal_state == "REGRESSION_FAILURE"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_positive_controls_legitimate_app_safe_loader(redteam_workspace):
    """
    Positive Control: Legitimate AppSafeLoader remediation.
    Proves:
    1. Exploit behavior is safely blocked (ConstructorError on builtins.eval).
    2. Valid YAML parses.
    3. Nested YAML remains functional.
    4. Custom !env_var remains functional.
    5. Regression suite passes 3/3 tests.
    6. Parent confirms exit 42 and clean filesystem.
    7. Final verdict is GREEN_STATE_VERIFIED.
    """
    legit_code = """import yaml, os
class AppSafeLoader(yaml.SafeLoader): pass
def _env_tag_constructor(loader, node):
    val = loader.construct_scalar(node)
    return os.environ.get(val, f"DEFAULT_{val}")
AppSafeLoader.add_constructor("!env_var", _env_tag_constructor)
yaml.Loader.add_constructor("!env_var", _env_tag_constructor)

def parse_app_config(raw_yaml: str) -> dict:
    # Secure contextual remediation: SafeLoader with registered application tags
    data = yaml.load(raw_yaml, Loader=AppSafeLoader)
    if isinstance(data, dict):
        return data
    return {"config": data}
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, legit_code)

    # Exploit blocked; benign input parses; exit 42
    assert exec_res.reproduction_state == "GREEN_STATE_BLOCKED"
    assert exec_res.exit_code == 42
    assert exec_res.parent_validated is True
    assert exec_res.structured_evidence.get("positive_control_passed") is True

    # Regression suite passes all 3 tests (standard YAML, custom tag, nested dict)
    assert reg_res["passed"] is True
    assert reg_res["test_count"] == 3

    # Final verdict is genuinely GREEN_STATE_VERIFIED
    assert verdict.terminal_state == "GREEN_STATE_VERIFIED"
    assert verdict.reason.startswith("Reachable vulnerability reproduced in red state")


def test_adversarial_patch_empty_dict_rejected(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch catches exploit and returns empty dict {}.
    Behavioral preservation oracle MUST reject this as POSITIVE_CONTROL_FAILED.
    Verdict MUST NOT be GREEN_STATE_VERIFIED.
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    return {}
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_empty_string_rejected(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch catches exploit and returns empty string "".
    Oracle rejects type mismatch / empty container.
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    return ""
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_constant_string_rejected(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch returns constant string 'blocked'.
    Oracle rejects type mismatch.
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    return "blocked"
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_constant_integer_rejected(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch returns constant integer 42.
    Oracle rejects type mismatch.
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    return 42
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_structurally_incomplete_rejected(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch returns incomplete dict missing required 'port' key.
    Oracle rejects missing required key.
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    return {"service": "auth"}
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_missing_required_fields_null_value_rejected(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch returns dict with 'port': None.
    Oracle rejects null value for required field.
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    return {"service": "auth", "port": None}
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_patch_split_brain_multi_input_failure(redteam_workspace):
    """
    P0.5.4 Adversarial Test: Patch passes input 1 ('auth') but returns {} on input 2 ('core-api').
    Oracle catches multi-input contract failure on input 2!
    """
    broken_code = """import yaml
def parse_app_config(raw_yaml: str) -> dict:
    if "open(" in str(raw_yaml):
        raise yaml.constructor.ConstructorError("blocked")
    if "auth" in str(raw_yaml):
        return {"service": "auth", "port": 9000}
    return {}
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, broken_code)
    assert exec_res.assertion_result == "POSITIVE_CONTROL_FAILED"
    assert exec_res.exit_code == 1
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"


def test_adversarial_anti_evasion_argv_and_stack_inspection(redteam_workspace):
    """
    P0.5.5 Anti-Evasion Test: Patch attempts to detect test harness via sys.argv.
    Harness normalizes sys.argv so 'harness' is absent.
    Even if it tries to fake defensive block, behavioral contract fails.
    """
    evasive_code = """import sys, inspect, yaml
def parse_app_config(raw_yaml: str) -> dict:
    is_test = any("harness" in str(arg).lower() for arg in sys.argv)
    if is_test:
        raise yaml.constructor.ConstructorError("fake defensive block")
    return yaml.load(raw_yaml, Loader=yaml.Loader)
"""
    exec_res, reg_res, verdict = _evaluate_candidate_patch(redteam_workspace, evasive_code)
    assert exec_res.reproduction_state != "GREEN_STATE_BLOCKED"
    assert verdict.terminal_state != "GREEN_STATE_VERIFIED"
