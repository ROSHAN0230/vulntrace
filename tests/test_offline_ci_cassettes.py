"""
VulnTrace Offline CI & Cassette Isolation Test Suite (Spec §4.7 / §4.8)
Verifies:
1. Unit tests and CI run with zero live network calls by enforcing strict socket blocking.
2. Tavily threat intelligence replays deterministically from offline cassettes with network blocked.
3. Nebius Token Factory tiered LLM client replays deterministically with network blocked.
4. End-to-end pipeline executes offline under socket blocking and produces both ThreatIntel
   and multi-tier TokenLedger records.
"""

import socket
import pytest
from pathlib import Path
from unittest.mock import patch

from vulntrace.intel.tavily_client import TavilyClient
from vulntrace.llm.client import TokenFactoryClient
from vulntrace.llm.tier import LLMModelTier
from vulntrace.llm.ledger import TokenLedger
from vulntrace.models import (
    TriageAnalysisOutput,
    PatchPlanOutput,
    VerificationPipelineRequest
)
from vulntrace.sandbox.pipeline import VerificationPipeline


@pytest.fixture
def block_network():
    """Monkeypatches socket.socket.connect to raise RuntimeError on any outbound external connection attempt."""
    orig_connect = socket.socket.connect

    def forbidden_connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
        if host in ("127.0.0.1", "::1", "localhost"):
            return orig_connect(self, address, *args, **kwargs)
        raise RuntimeError(f"Forbidden outbound network call to {address} during offline test execution!")

    with patch.object(socket.socket, "connect", forbidden_connect):
        yield


@pytest.mark.asyncio
async def test_tavily_offline_cassette_zero_network(block_network):
    """Verifies that Tavily queries resolve from cassette with 100% blocked network."""
    client = TavilyClient()
    intel = await client.query_threat_intel("CVE-2020-14343")

    assert intel.cve_id == "CVE-2020-14343"
    assert len(intel.source_urls) > 0
    assert len(intel.response_hash) == 64
    assert len(intel.findings) > 0
    assert "yaml.load" in intel.affected_symbols or "yaml.full_load" in intel.affected_symbols


@pytest.mark.asyncio
async def test_llm_tiered_offline_cassette_zero_network(block_network):
    """Verifies that SMALL, MID, and ULTRA LLM tiers resolve from cassettes with 100% blocked network."""
    ledger = TokenLedger()
    client = TokenFactoryClient(ledger=ledger)

    # 1. SMALL Tier (Triage)
    triage, t_rec = await client.generate_structured(
        tier=LLMModelTier.SMALL,
        response_model=TriageAnalysisOutput,
        messages=[{"role": "user", "content": "Triage CVE-2020-14343"}],
        stage="triage_classification"
    )
    assert triage is not None
    assert t_rec.success is True

    # 2. MID Tier (Planning)
    plan, p_rec = await client.generate_structured(
        tier=LLMModelTier.MID,
        response_model=PatchPlanOutput,
        messages=[{"role": "user", "content": "Plan fix"}],
        stage="patch_planning"
    )
    assert plan is not None
    assert p_rec.success is True

    # 3. ULTRA Tier (Patching)
    content, u_rec = await client.generate_chat(
        tier=LLMModelTier.ULTRA,
        messages=[{"role": "user", "content": "Generate diff"}],
        stage="surgical_patch"
    )
    assert len(content) > 0
    assert u_rec.success is True

    # Confirm ledger has multiple tiers
    assert ledger.has_multiple_tiers(2) is True
    summary = ledger.get_summary()
    assert summary.total_calls == 3


@pytest.mark.asyncio
async def test_pipeline_offline_execution_zero_network(block_network):
    """
    Verifies that the entire defensive verification pipeline can execute
    with network strictly blocked, producing valid ThreatIntel and TokenLedger evidence.
    """
    repo_path = (Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning").resolve()
    assert repo_path.exists()

    req = VerificationPipelineRequest(
        repo_path=str(repo_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=True
    )

    res = await VerificationPipeline.run_pipeline(req)

    # Verification checks
    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert res.pre_patch_result.reproduction_state == "RED_STATE_REPRODUCED"
    assert res.remediation.success is True
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # M4 Evidence Guarantees: ThreatIntel + TokenLedger
    assert res.threat_intel is not None
    assert res.threat_intel.cve_id == "CVE-2020-14343"
    assert len(res.threat_intel.response_hash) == 64

    assert res.token_ledger is not None
    assert res.token_ledger.total_calls >= 2
    assert res.token_ledger.total_tokens > 0
    assert "SMALL" in res.token_ledger.tier_breakdown or "ULTRA" in res.token_ledger.tier_breakdown
