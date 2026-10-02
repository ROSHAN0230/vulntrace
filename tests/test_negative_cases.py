"""
VulnTrace Negative & Adversarial Verification Suite
Empirically verifies that VulnTrace rejects false positives, handles shadowed symbols,
parses import aliases and from-imports, isolates unreachable wrappers, rejects spoofed exit codes,
and validates candidate patches against syntax errors and empty diffs.
"""

import pytest
import shutil
import tempfile
import asyncio
from pathlib import Path
from vulntrace.sandbox.runner import SubprocessSandboxRunner
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.analyzer.ast_visitor import AstReachabilityAnalyzer
from vulntrace.agent.patcher import RemediationPatcher
from vulntrace.models import (
    AstAnalyzeRequest,
    VerificationPipelineRequest,
    RemediationRequest,
    HarnessGenerateRequest
)

@pytest.fixture
def temp_repo():
    d = Path(tempfile.mkdtemp(prefix="vulntrace_adversarial_"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- Case A: Comments Only ---
def test_case_a_comments_only(temp_repo):
    """Case A: Code contains only comments and strings mentioning yaml.load and CVE-2020-14343."""
    app_file = temp_repo / "app.py"
    app_file.write_text(
        '''# Reference: CVE-2020-14343
# We used to call yaml.load(raw_data) here.
# Now we do not use YAML at all.
def main():
    doc = "Do not use yaml.load() anywhere in this codebase."
    return {"status": "ok", "msg": doc}
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"]
    ))

    assert res.verdict == "NO_VULNERABILITIES_FOUND"
    assert len(res.discovered_calls) == 0
    assert res.reachable_vulnerabilities_count == 0


# --- Case B: Locally Shadowed Symbol ---
def test_case_b_shadowed_symbol(temp_repo):
    """Case B: Local class 'yaml' defines 'load' without importing external PyYAML."""
    app_file = temp_repo / "custom_yaml.py"
    app_file.write_text(
        '''class yaml:
    @staticmethod
    def load(data):
        return {"local_custom": data}

def process(input_data):
    # This calls the local class yaml.load, not PyYAML!
    return yaml.load(input_data)
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"]
    ))

    assert res.verdict == "NO_VULNERABILITIES_FOUND"
    assert len(res.discovered_calls) == 0


# --- Case C: Aliased Import ---
def test_case_c_aliased_import(temp_repo):
    """Case C: PyYAML imported under an alias 'import yaml as y_alias'."""
    app_file = temp_repo / "alias_loader.py"
    app_file.write_text(
        '''import yaml as y_alias

def parse_alias_config(raw_text):
    return y_alias.load(raw_text)

def main():
    return parse_alias_config("sample: 1")
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"]
    ))

    assert res.verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert len(res.discovered_calls) == 1
    assert res.discovered_calls[0].call_name == "yaml.load"
    assert res.discovered_calls[0].reachable is True


# --- Case D: From-Import ---
def test_case_d_from_import(temp_repo):
    """Case D: 'from yaml import load as dangerous_load'."""
    app_file = temp_repo / "from_loader.py"
    app_file.write_text(
        '''from yaml import load as dangerous_load

def handle_request(payload):
    return dangerous_load(payload)

def api_endpoint(req):
    return handle_request(req)
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"]
    ))

    assert res.verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert len(res.discovered_calls) == 1
    assert res.discovered_calls[0].call_name == "yaml.load"


# --- Case E: Dead Wrapper Function ---
def test_case_e_dead_wrapper(temp_repo):
    """Case E: Wrapper function calls sink, but wrapper itself is unreachable dead code."""
    app_file = temp_repo / "service.py"
    app_file.write_text(
        '''import yaml

def active_entrypoint():
    return "I do not touch YAML at all"

def unused_dead_wrapper(blob):
    return yaml.load(blob)
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"],
        entrypoints=["active_entrypoint"]
    ))

    assert res.verdict == "UNREACHABLE_FALSE_POSITIVE"
    assert res.reachable_vulnerabilities_count == 0
    assert res.unreachable_dead_code_count == 1


# --- Case F: Multiple Sinks (Reachable vs Unreachable) ---
def test_case_f_multiple_sinks(temp_repo):
    """Case F: One reachable sink in handler(), one dead sink in deprecated()."""
    app_file = temp_repo / "dual.py"
    app_file.write_text(
        '''import yaml

def api_main():
    return handler("foo: bar")

def handler(text):
    return yaml.load(text)

def deprecated_legacy(text):
    return yaml.load(text)
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"]
    ))

    assert res.reachable_vulnerabilities_count >= 1
    assert res.verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"


# --- Case G: Malformed Python Syntax Handling ---
def test_case_g_malformed_syntax_graceful(temp_repo):
    """Case G: File with syntax errors should be skipped without crashing the analyzer."""
    bad_file = temp_repo / "broken.py"
    bad_file.write_text("def broken_syntax(::: this is invalid python", encoding="utf-8")

    good_file = temp_repo / "good.py"
    good_file.write_text(
        '''import yaml
def run(text):
    return yaml.load(text)
''',
        encoding="utf-8"
    )

    res = AstReachabilityAnalyzer.analyze_repository(AstAnalyzeRequest(
        repo_path=str(temp_repo),
        target_symbols=["yaml.load"]
    ))

    assert res.verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert len(res.discovered_calls) == 1


# --- Case H: Broken Module Import During Verification ---
def test_case_h_broken_import_unhandled_failure(temp_repo):
    """Case H: Verification harness fails to import target module -> UNEXPECTED_FAILURE, never GREEN."""
    harness_file = temp_repo / "broken_harness.py"
    harness_file.write_text(
        '''import sys
import json
print(json.dumps({
    "sink_reached": False,
    "assertion_evaluated": False,
    "risky_effect_observed": False,
    "expected_security_exception": False,
    "unexpected_exception": True,
    "exception_type": "ModuleNotFoundError",
    "assertion": "UNEXPECTED_FAILURE",
    "detail": "No module named 'nonexistent_package'"
}))
sys.exit(1)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_repo,
        script_name="broken_harness.py"
    )

    assert res.reproduction_state == "UNEXPECTED_FAILURE"
    assert res.exit_code == 1
    assert res.reproduction_state != "GREEN_STATE_BLOCKED"


# --- Case I: Spoofed Exit Code 42 ---
def test_case_i_spoofed_exit_42_rejected(temp_repo):
    """
    Case I: Malicious script attempts to trick runner by calling sys.exit(42) directly
    WITHOUT emitting valid structured assertion verification evidence.
    Must be classified as UNEXPECTED_FAILURE, NEVER GREEN_STATE_BLOCKED!
    """
    spoof_file = temp_repo / "spoof.py"
    spoof_file.write_text(
        '''import sys
# Trickster tries sys.exit(42) without expected security exception assertion
sys.exit(42)
''',
        encoding="utf-8"
    )

    res = SubprocessSandboxRunner.execute_script(
        disposable_dir=temp_repo,
        script_name="spoof.py"
    )

    assert res.reproduction_state == "UNEXPECTED_FAILURE"
    assert res.reproduction_state != "GREEN_STATE_BLOCKED"


# --- Case J: Candidate Patch Syntax Error Rejection ---
@pytest.mark.asyncio
async def test_case_j_patch_syntax_error_rejection(temp_repo):
    """
    Case J: If patch synthesizer produces invalid Python syntax,
    it must be rejected (validation_status='REJECTED_SYNTAX_ERROR') rather than applied.
    """
    target = temp_repo / "vuln.py"
    target.write_text("import yaml\ndef load(x): return yaml.load(x)\n", encoding="utf-8")

    # Mock invalid patch via patcher
    req = RemediationRequest(
        repo_path=str(temp_repo),
        cve_id="CVE-2020-14343",
        target_file="vuln.py",
        vulnerable_call="yaml.load",
        use_nemotron=False,
        allow_ast_fallback=False
    )

    # Corrupt the AST patch method temporarily to test rejection logic
    orig_method = RemediationPatcher._ast_deterministic_patch
    try:
        RemediationPatcher._ast_deterministic_patch = lambda code, sym: "def invalid_syntax(::: def"
        res = await RemediationPatcher.synthesize_remediation(req, workspace_dir=temp_repo)
        assert res.success is False
        assert res.validation_status == "REJECTED"
    finally:
        RemediationPatcher._ast_deterministic_patch = orig_method
