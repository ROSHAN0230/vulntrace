"""
Tests for VulnTrace Evidence Correctness, Token Reconciliation, and Path Sanitization (Spec §4.7 / §4.11).
Verifies:
1. Schema v1 evidence bundle extracts authentic per-call LLM records from TokenLedger.
2. Per-call prompt, completion, and reasoning tokens reconcile with ledger aggregate totals.
3. Latency values in call records reflect genuine measurements without synthesis.
4. Source URL and spec requirement sanitize absolute host filesystem paths (e.g. C:\\...).
5. Ed25519 cryptographic signatures verify authentic bundles and reject tampered token counts.
"""

import copy
import pytest

from vulntrace.engine.evidence_export import EvidenceExporter
from vulntrace.evidence.signing import EvidenceSigner
from vulntrace.llm.ledger import TokenLedger
from vulntrace.llm.tier import LLMModelTier
from vulntrace.models import (
    VerificationPipelineResponse,
    HarnessGenerateResponse,
    SandboxExecutionResult,
    RemediationResponse,
    ThreatIntel
)


@pytest.fixture
def sample_pipeline_run():
    """Builds a realistic VerificationPipelineResponse with authentic multi-stage token records."""
    ledger = TokenLedger()
    # Record stage 1: Threat intel triage
    ledger.record_call(
        stage="INTEL",
        model="deepseek-ai/DeepSeek-V3",
        tier=LLMModelTier.SMALL,
        prompt_tokens=450,
        completion_tokens=120,
        reasoning_tokens=0,
        latency_ms=312.5
    )
    # Record stage 2: Harness generation
    ledger.record_call(
        stage="HARNESS",
        model="Qwen/Qwen2.5-Coder-32B-Instruct",
        tier=LLMModelTier.MID,
        prompt_tokens=1200,
        completion_tokens=380,
        reasoning_tokens=64,
        latency_ms=784.2
    )
    # Record stage 3: Surgical patch synthesis
    ledger.record_call(
        stage="PATCH",
        model="deepseek-ai/DeepSeek-R1",
        tier=LLMModelTier.ULTRA,
        prompt_tokens=2100,
        completion_tokens=490,
        reasoning_tokens=512,
        latency_ms=1640.8
    )

    harness = HarnessGenerateResponse(
        cve_id="CVE-2020-14343",
        harness_code="def test_exploit():\n    pass\n",
        target_file="test_target.py",
        function_name="vulnerable_func",
        vulnerable_call="yaml.load",
        sentinel_filename="sentinel.txt",
        latency_ms=15.0
    )

    pre_patch = SandboxExecutionResult(
        exit_code=0,
        reproduction_state="RED_REPRODUCED",
        sentinel_created=True,
        assertion_result="EXPLOIT_SENTINEL_DETECTED",
        exception_type=None,
        parent_validated=True,
        validation_notes="Observed exploit sentinel creation",
        latency_ms=45.0,
        stdout="EXPLOIT_EXECUTED",
        stderr="",
        sandbox_engine="OCI_CONTAINER_ISOLATED"
    )

    post_patch = SandboxExecutionResult(
        exit_code=42,
        reproduction_state="GREEN_SECURITY_BLOCK_VERIFIED",
        sentinel_created=False,
        assertion_result="SECURITY_EXCEPTION_VERIFIED",
        exception_type="SecurityException",
        parent_validated=True,
        validation_notes="Observed expected SecurityException",
        latency_ms=40.0,
        stdout="SECURITY_BLOCKED",
        stderr="",
        sandbox_engine="OCI_CONTAINER_ISOLATED"
    )

    remediation = RemediationResponse(
        cve_id="CVE-2020-14343",
        target_file="test_target.py",
        success=True,
        engine="AST_AWARE_LLM",
        diff="--- a/target.py\n+++ b/target.py\n@@ -1 +1 @@\n-yaml.load(payload)\n+yaml.safe_load(payload)\n",
        explanation="Replaced unsafe yaml.load with yaml.safe_load",
        validation_status="VALIDATED",
        tokens_used=ledger.get_summary().total_tokens,
        reasoning_tokens=ledger.get_summary().total_reasoning_tokens,
        latency_ms=1640.8
    )

    threat_intel = ThreatIntel(
        cve_id="CVE-2020-14343",
        status="ENRICHED",
        query="PyYAML safe_load deserialization exploit",
        source_urls=["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
        response_hash="a" * 64,
        findings=[]
    )

    return VerificationPipelineResponse(
        run_id="run_test_evidence_correctness_01",
        cve_id="CVE-2020-14343",
        repo_path="C:\\AI-Tools\\vulntrace\\benchmarks\\contextual_reasoning",
        reachability_verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED",
        harness=harness,
        pre_patch_result=pre_patch,
        remediation=remediation,
        post_patch_result=post_patch,
        regression_tests={"passed": True, "test_count": 5, "latency_ms": 12.0},
        final_behavioral_verdict="GREEN_STATE_VERIFIED",
        threat_intel=threat_intel,
        token_ledger=ledger.get_summary(),
        sandbox_engine="OCI_CONTAINER_ISOLATED",
        cloud_status="AUTHENTICATED",
        total_pipeline_ms=2832.5,
        isolation_tier="TIER_1_ROOTLESS_CONTAINER"
    )


class TestEvidenceCorrectnessAndTokenReconciliation:
    """Tests authentic call-level token export and cryptographic integrity."""

    def test_schema_v1_exports_per_call_ledger_records(self, sample_pipeline_run):
        bundle = EvidenceExporter.build_schema_v1_bundle(sample_pipeline_run, sign=True)

        assert "llm" in bundle
        assert "calls" in bundle["llm"]
        calls = bundle["llm"]["calls"]
        assert len(calls) == 3

        # Check call stages
        stages = [c["stage"] for c in calls]
        assert stages == ["INTEL", "HARNESS", "PATCH"]

        # Check models
        models = [c["model"] for c in calls]
        assert models == [
            "deepseek-ai/DeepSeek-V3",
            "Qwen/Qwen2.5-Coder-32B-Instruct",
            "deepseek-ai/DeepSeek-R1"
        ]

    def test_call_tokens_reconcile_with_ledger_aggregates(self, sample_pipeline_run):
        bundle = EvidenceExporter.build_schema_v1_bundle(sample_pipeline_run, sign=True)
        calls = bundle["llm"]["calls"]
        ledger_summary = sample_pipeline_run.token_ledger

        sum_prompt = sum(c["prompt_tokens"] for c in calls)
        sum_completion = sum(c["completion_tokens"] for c in calls)
        sum_reasoning = sum(c["reasoning_tokens"] for c in calls)

        # Sum of individual call records must reconcile with aggregate totals
        assert sum_prompt == ledger_summary.total_prompt_tokens
        assert sum_completion == ledger_summary.total_completion_tokens
        assert sum_reasoning == ledger_summary.total_reasoning_tokens

        # Check exact individual tokens: no call has aggregate totals assigned
        assert calls[0]["prompt_tokens"] == 450
        assert calls[0]["completion_tokens"] == 120
        assert calls[0]["reasoning_tokens"] == 0

        assert calls[1]["prompt_tokens"] == 1200
        assert calls[1]["completion_tokens"] == 380
        assert calls[1]["reasoning_tokens"] == 64

        assert calls[2]["prompt_tokens"] == 2100
        assert calls[2]["completion_tokens"] == 490
        assert calls[2]["reasoning_tokens"] == 512

    def test_latency_values_preserved_without_synthesis(self, sample_pipeline_run):
        bundle = EvidenceExporter.build_schema_v1_bundle(sample_pipeline_run, sign=True)
        calls = bundle["llm"]["calls"]

        # Latencies match recorded call latencies
        assert calls[0]["latency_ms"] == 312.5
        assert calls[1]["latency_ms"] == 784.2
        assert calls[2]["latency_ms"] == 1640.8

    def test_path_sanitization_removes_absolute_host_paths(self, sample_pipeline_run):
        bundle_v1 = EvidenceExporter.build_schema_v1_bundle(sample_pipeline_run, sign=True)
        bundle_legacy = EvidenceExporter.build_evidence_bundle(sample_pipeline_run)

        # Source URL must not leak Windows drive or absolute host path
        source_url = bundle_v1["source"]["url"]
        assert "C:\\" not in source_url
        assert "C:/" not in source_url
        assert "AI-Tools" not in source_url
        assert source_url == "local://contextual_reasoning"

        # Spec requirement must not leak Windows drive or absolute host path
        req = bundle_v1["spec"]["requirement"]
        assert "C:\\" not in req
        assert "C:/" not in req
        assert "AI-Tools" not in req
        assert "contextual_reasoning" in req

        # Legacy bundle target repository path must be sanitized
        target_repo = bundle_legacy["target"]["repository_path"]
        assert "C:\\" not in target_repo
        assert "AI-Tools" not in target_repo
        assert target_repo == "contextual_reasoning"

    def test_ed25519_signature_verifies_and_detects_token_tampering(self, sample_pipeline_run):
        bundle = EvidenceExporter.build_schema_v1_bundle(sample_pipeline_run, sign=True)

        # Authentic bundle verifies cleanly
        valid, reason = EvidenceSigner.verify_bundle(bundle)
        assert valid is True
        assert reason == "VERIFICATION_SUCCESSFUL"

        # Tampering with a single token count fails verification
        tampered = copy.deepcopy(bundle)
        tampered["llm"]["calls"][0]["prompt_tokens"] += 1
        tampered_valid, tampered_reason = EvidenceSigner.verify_bundle(tampered)
        assert tampered_valid is False
        assert "mismatch" in tampered_reason.lower() or "signature verification failed" in tampered_reason.lower()
