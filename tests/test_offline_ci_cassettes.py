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
import shutil
import time
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from unittest.mock import patch

import httpx
import pytest

from vulntrace.intel.cassette import IntelCassetteManager
from vulntrace.intel.tavily_client import TavilyClient
from vulntrace.llm.client import TokenFactoryClient
from vulntrace.llm.cassette import LLMCassetteManager
from vulntrace.llm.tier import LLMModelTier
from vulntrace.llm.ledger import TokenLedger
from vulntrace.core.backend import (
    ExecutionBackend,
    BackendCapabilities,
    IsolationTier,
    ExecutionCommandResult,
    ExecutionAttestation,
)
from vulntrace.core.policy import (
    SecurityPolicyEngine,
    PolicyDecision,
    AssuranceLevel,
)
from vulntrace.models import (
    TriageAnalysisOutput,
    PatchPlanOutput,
    VerificationPipelineRequest,
    RegressionEvidence,
    BehaviorEvidence,
    PatchEvidence,
    RepositoryEvidence,
    AdvisoryEvidence,
    ReachabilityEvidence,
    ExecutionEvidence,
)
from vulntrace.engine.verdict_engine import VerdictEngine
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.config import settings

_RealAsyncClient = httpx.AsyncClient


@pytest.fixture
def block_network():
    """Monkeypatches socket.socket.connect to track and block outbound external connection attempts at the Python socket layer."""
    orig_connect = socket.socket.connect
    intercepted_attempts: List[Any] = []

    def forbidden_connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
        if host in ("127.0.0.1", "::1", "localhost"):
            return orig_connect(self, address, *args, **kwargs)
        intercepted_attempts.append(address)
        raise RuntimeError(f"Forbidden outbound network call to {address} during offline test execution!")

    with patch.object(socket.socket, "connect", forbidden_connect):
        class SocketController:
            attempts = intercepted_attempts
        yield SocketController()


@pytest.fixture
def mock_httpx_transport(monkeypatch):
    """
    Wires an in-memory httpx.MockTransport into httpx.AsyncClient for both
    TokenFactoryClient and TavilyClient.
    Captures all outbound requests in memory; never opens network sockets.
    """
    intercepted_requests: List[httpx.Request] = []
    custom_responses: Dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        intercepted_requests.append(request)
        url_str = str(request.url)
        for pattern, resp_factory in custom_responses.items():
            if pattern in url_str:
                return resp_factory(request)
        # Default mock response
        if "tavily" in url_str:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "title": "Advisory Default Mock",
                            "url": "https://example.com/advisory",
                            "content": "Default advisory content mentioning target CVE."
                        }
                    ]
                }
            )
        # Default LLM response
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "Mocked LLM completion response."
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 150,
                    "completion_tokens": 50,
                    "total_tokens": 200
                }
            }
        )

    transport = httpx.MockTransport(handler)

    def create_mock_client(*args, **kwargs):
        kwargs["transport"] = transport
        return _RealAsyncClient(*args, **kwargs)

    monkeypatch.setattr("vulntrace.llm.client.httpx.AsyncClient", create_mock_client)
    monkeypatch.setattr("vulntrace.intel.tavily_client.httpx.AsyncClient", create_mock_client)

    class TransportController:
        requests = intercepted_requests
        responses = custom_responses

        def set_response(self, url_pattern: str, response_factory):
            custom_responses[url_pattern] = response_factory

    return TransportController()


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
async def test_pipeline_offline_execution_zero_network(block_network, monkeypatch):
    """
    Verifies that the entire defensive verification pipeline can execute
    with network strictly blocked and ambient credentials stripped, producing valid
    ThreatIntel and TokenLedger evidence from offline cassettes.
    """
    from vulntrace.config import settings
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    monkeypatch.setattr(settings, "tavily_api_key", None)

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


@pytest.mark.asyncio
async def test_pipeline_offline_execution_zero_ambient_keys(block_network, monkeypatch):
    """
    Verifies that the entire defensive verification pipeline completes offline
    when NEBIUS_API_KEY and TAVILY_API_KEY are completely stripped from the environment,
    exactly matching the clean, unauthenticated GitHub Actions CI runner.
    """
    from vulntrace.config import settings
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    monkeypatch.setattr(settings, "tavily_api_key", None)

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
    assert res.remediation.engine == "NVIDIA_NEMOTRON_3_ULTRA"
    assert res.post_patch_result.reproduction_state == "GREEN_STATE_BLOCKED"
    assert res.final_behavioral_verdict == "GREEN_STATE_VERIFIED"

    # M4 Evidence Guarantees: ThreatIntel + TokenLedger under zero credentials
    assert res.threat_intel is not None
    assert res.threat_intel.cve_id == "CVE-2020-14343"
    assert len(res.threat_intel.response_hash) == 64

    assert res.token_ledger is not None
    assert res.token_ledger.total_calls >= 2
    assert res.token_ledger.total_tokens > 0
    assert "ULTRA" in res.token_ledger.tier_breakdown


# ===========================================================================
# Section 2: TokenFactoryClient Fail-Closed & Replay Test Matrix
# ===========================================================================

@pytest.mark.asyncio
async def test_llm_offline_key_present_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live disabled + credential present + cassette hit: replay succeeds; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "Triage CVE-2020-14343"}],
        stage="triage_classification"
    )
    assert rec.success is True
    assert len(content) > 0
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_offline_key_present_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live disabled + credential present + cassette miss: structured offline failure; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "unrecorded_unique_prompt_xyz_12345"}],
        stage="nonexistent_stage_abc_9999"
    )
    assert rec.success is False
    assert content == ""
    assert "Offline mode: No cassette found" in rec.error
    assert "Live calls disabled" in rec.error
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_offline_generate_structured_cassette_miss(mock_httpx_transport, monkeypatch):
    """
    Live disabled + credential present + structured generation cassette miss:
    Verifies that TokenFactoryClient.generate_structured() exhausts retries cleanly,
    returns (None, last_record), records structured failure, issues zero outbound
    transport requests across all retry attempts, and raises no unhandled exceptions.
    """
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")

    result, rec = await client.generate_structured(
        tier=LLMModelTier.SMALL,
        response_model=TriageAnalysisOutput,
        messages=[{"role": "user", "content": "Triage analysis prompt"}],
        stage="triage_classification",
        max_retries=2
    )

    assert result is None
    assert rec.success is False
    assert "Offline mode: No cassette found" in rec.error
    assert "Live calls disabled" in rec.error
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_offline_key_absent_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live disabled + credential absent + cassette hit: replay succeeds; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    client = TokenFactoryClient(api_key=None)
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "Triage CVE-2020-14343"}],
        stage="triage_classification"
    )
    assert rec.success is True
    assert len(content) > 0
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_offline_key_absent_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live disabled + credential absent + cassette miss: structured offline failure; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)
    client = TokenFactoryClient(api_key=None)
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "unrecorded_unique_prompt_xyz_12345"}],
        stage="nonexistent_stage_abc_9999"
    )
    assert rec.success is False
    assert content == ""
    assert "Offline mode: No cassette found" in rec.error
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_live_key_absent_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live enabled + credential absent + cassette hit: preserve existing cassette-replay behavior."""
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    client = TokenFactoryClient(api_key=None)
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "Triage CVE-2020-14343"}],
        stage="triage_classification"
    )
    assert rec.success is True
    assert len(content) > 0
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_live_key_absent_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live enabled + credential absent + cassette miss: structured missing-credential failure; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.setattr(settings, "nebius_api_key", None)
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)
    client = TokenFactoryClient(api_key=None)
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "unrecorded_unique_prompt_xyz_12345"}],
        stage="nonexistent_stage_abc_9999"
    )
    assert rec.success is False
    assert content == ""
    assert "Nebius Token Factory API key not configured" in rec.error
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_llm_live_key_present_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live enabled + credential present + cassette miss: one request intercepted by MockTransport, never real network."""
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "unrecorded_unique_prompt_xyz_12345"}],
        stage="nonexistent_stage_abc_9999"
    )
    assert rec.success is True
    assert content == "Mocked LLM completion response."
    assert len(mock_httpx_transport.requests) == 1
    req = mock_httpx_transport.requests[0]
    assert req.headers["Authorization"] == "Bearer test-dummy-nebius-key"


@pytest.mark.asyncio
async def test_llm_live_key_present_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live enabled + credential present + cassette hit: live precedence enters live path; intercepted by MockTransport."""
    monkeypatch.setenv("LIVE_LLM", "1")
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "Triage CVE-2020-14343"}],
        stage="triage_classification"
    )
    assert rec.success is True
    assert len(mock_httpx_transport.requests) == 1


# ===========================================================================
# Section 3: TavilyClient Fail-Closed & Replay Test Matrix
# ===========================================================================

@pytest.mark.asyncio
async def test_tavily_offline_key_present_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live disabled + credential present + cassette hit: replay succeeds; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    report = await client.search_with_relevance("CVE-2020-14343")
    assert report.status_code == 200
    assert len(report.findings) > 0
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_offline_key_present_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live disabled + credential present + cassette miss: structured offline failure; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    report = await client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 412  # Local synthetic marker: Precondition Failed (offline fixture missing)
    assert len(report.findings) == 0
    assert "Offline mode: No threat intelligence cassette found" in report.rejection_reasons[0]
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_offline_key_absent_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live disabled + credential absent + cassette hit: replay succeeds; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(settings, "tavily_api_key", None)
    client = TavilyClient(api_key=None)
    report = await client.search_with_relevance("CVE-2020-14343")
    assert report.status_code == 200
    assert len(report.findings) > 0
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_offline_key_absent_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live disabled + credential absent + cassette miss: structured offline failure; zero transport requests."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(settings, "tavily_api_key", None)
    client = TavilyClient(api_key=None)
    report = await client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 412  # Local synthetic marker
    assert len(report.findings) == 0
    assert "Offline mode: No threat intelligence cassette found" in report.rejection_reasons[0]
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_live_key_absent_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live enabled + credential absent + cassette hit: preserve existing cassette-replay behavior."""
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(settings, "tavily_api_key", None)
    client = TavilyClient(api_key=None)
    report = await client.search_with_relevance("CVE-2020-14343")
    assert report.status_code == 200
    assert len(report.findings) > 0
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_live_key_absent_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live enabled + credential absent + cassette miss: structured missing-credential failure; zero transport requests."""
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(settings, "tavily_api_key", None)
    client = TavilyClient(api_key=None)
    report = await client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 401
    assert report.rejection_reasons == ["Tavily API key not configured."]
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_live_key_present_cassette_miss(mock_httpx_transport, monkeypatch):
    """Live enabled + credential present + cassette miss: one request intercepted by MockTransport, never real network."""
    monkeypatch.setenv("LIVE_INTEL", "1")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    mock_httpx_transport.set_response(
        "tavily",
        lambda req: httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "CVE-9999-99999 Advisory Fix",
                        "url": "https://example.com/cve-9999-99999",
                        "content": "Advisory for CVE-9999-99999 vulnerability fix commit."
                    }
                ]
            }
        )
    )
    report = await client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 200
    assert len(report.findings) == 1
    assert len(mock_httpx_transport.requests) == 1


@pytest.mark.asyncio
async def test_tavily_live_key_present_cassette_hit(mock_httpx_transport, monkeypatch):
    """Live enabled + credential present + cassette hit: live precedence enters live path; intercepted by MockTransport."""
    monkeypatch.setenv("LIVE_INTEL", "1")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    mock_httpx_transport.set_response(
        "tavily",
        lambda req: httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "CVE-2020-14343 Live Advisory",
                        "url": "https://example.com/cve-2020-14343",
                        "content": "Live fetched advisory for CVE-2020-14343."
                    }
                ]
            }
        )
    )
    report = await client.search_with_relevance("CVE-2020-14343")
    assert report.status_code == 200
    assert len(mock_httpx_transport.requests) == 1


# ===========================================================================
# Section 4: Edge Cases, Error Handling & Degradation Semantics
# ===========================================================================

@pytest.mark.asyncio
async def test_tavily_offline_miss_pipeline_degradation(mock_httpx_transport, monkeypatch):
    """Verifies that Tavily query_threat_intel converts local 412 into status='degraded' without raising exceptions."""
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    intel = await client.query_threat_intel("CVE-9999-99999")
    assert intel.status == "degraded"
    assert intel.confidence == 0.30
    assert "No threat intelligence cassette found" in intel.error
    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_tavily_live_http_non_200_response(mock_httpx_transport, monkeypatch):
    """Verifies that non-200 HTTP response in live mode is parsed into TavilySearchReport."""
    monkeypatch.setenv("LIVE_INTEL", "1")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    mock_httpx_transport.set_response(
        "tavily",
        lambda req: httpx.Response(429, json={"error": "Rate limit exceeded"})
    )
    report = await client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 429
    assert len(report.findings) == 0
    assert "HTTP 429 error" in report.rejection_reasons[0]


@pytest.mark.asyncio
async def test_tavily_live_transport_exception(mock_httpx_transport, monkeypatch):
    """Verifies that transport connection exceptions in live mode return status_code=500 report."""
    monkeypatch.setenv("LIVE_INTEL", "1")
    client = TavilyClient(api_key="tvly-test-dummy-key")
    def raise_connect_error(req):
        raise httpx.ConnectError("Network connection refused", request=req)
    mock_httpx_transport.set_response("tavily", raise_connect_error)
    report = await client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 500
    assert "Network connection refused" in report.rejection_reasons[0]


@pytest.mark.asyncio
async def test_llm_live_http_non_200_response(mock_httpx_transport, monkeypatch):
    """Verifies that upstream HTTP error during live inference is recorded as failure in TokenLedger."""
    monkeypatch.setenv("LIVE_LLM", "1")
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    mock_httpx_transport.set_response(
        "chat/completions",
        lambda req: httpx.Response(503, text="Service Unavailable")
    )
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "live call"}],
        stage="triage_classification"
    )
    assert rec.success is False
    assert content == ""
    assert "HTTP 503" in rec.error


@pytest.mark.asyncio
async def test_llm_live_transport_timeout(mock_httpx_transport, monkeypatch):
    """Verifies that httpx.TimeoutException during live inference is recorded as failure in TokenLedger."""
    monkeypatch.setenv("LIVE_LLM", "1")
    client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    def raise_timeout(req):
        raise httpx.TimeoutException("Read timed out after 30s")
    mock_httpx_transport.set_response("chat/completions", raise_timeout)
    content, rec = await client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "live call"}],
        stage="triage_classification"
    )
    assert rec.success is False
    assert "timed out" in rec.error.lower()


# ===========================================================================
# Section 5: Decoupled Egress Configuration Permutations (Task A)
# ===========================================================================

@pytest.mark.asyncio
async def test_config_permutation_live_llm_1_live_intel_0(mock_httpx_transport, monkeypatch):
    """
    Decoupled permutation: LIVE_LLM=1, LIVE_INTEL=0.
    Verifies:
    - LLMCassetteManager.is_live_enabled() is True
    - IntelCassetteManager.is_live_enabled() is False
    - TokenFactoryClient enters live path on cassette miss (intercepted by MockTransport)
    - TavilyClient fails closed on cassette miss without live egress
    """
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "0")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)

    assert LLMCassetteManager.is_live_enabled() is True
    assert IntelCassetteManager.is_live_enabled() is False

    # LLM permitted live path on miss
    llm_client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await llm_client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "test_permutation_1"}],
        stage="unrecorded_stage_perm_1"
    )
    assert rec.success is True
    assert content == "Mocked LLM completion response."
    assert len(mock_httpx_transport.requests) == 1

    # Tavily fails closed on miss without attempting egress
    tavily_client = TavilyClient(api_key="tvly-test-dummy-key")
    report = await tavily_client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 412
    assert "Offline mode: No threat intelligence cassette found" in report.rejection_reasons[0]
    # No additional outbound requests from Tavily
    assert len(mock_httpx_transport.requests) == 1


@pytest.mark.asyncio
async def test_config_permutation_live_llm_0_live_intel_1(mock_httpx_transport, monkeypatch):
    """
    Decoupled permutation: LIVE_LLM=0, LIVE_INTEL=1.
    Verifies:
    - LLMCassetteManager.is_live_enabled() is False
    - IntelCassetteManager.is_live_enabled() is True
    - TavilyClient enters live path on cassette miss (intercepted by MockTransport)
    - TokenFactoryClient fails closed on cassette miss without live egress
    """
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)

    assert LLMCassetteManager.is_live_enabled() is False
    assert IntelCassetteManager.is_live_enabled() is True

    # Tavily permitted live path on miss
    tavily_client = TavilyClient(api_key="tvly-test-dummy-key")
    report = await tavily_client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 200
    assert len(mock_httpx_transport.requests) == 1

    # LLM fails closed on miss without attempting egress
    llm_client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await llm_client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "test_permutation_2"}],
        stage="unrecorded_stage_perm_2"
    )
    assert rec.success is False
    assert content == ""
    assert "Offline mode" in rec.error
    # No additional outbound requests from LLM
    assert len(mock_httpx_transport.requests) == 1


@pytest.mark.asyncio
async def test_config_permutation_both_offline(mock_httpx_transport, monkeypatch):
    """
    Decoupled permutation: LIVE_LLM=0, LIVE_INTEL=0.
    Verifies:
    - Both managers return is_live_enabled() is False
    - Both clients fail closed on cassette miss
    - Exactly 0 outbound HTTP transport requests
    """
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)

    assert LLMCassetteManager.is_live_enabled() is False
    assert IntelCassetteManager.is_live_enabled() is False

    llm_client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await llm_client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "test_permutation_3"}],
        stage="unrecorded_stage_perm_3"
    )
    assert rec.success is False
    assert "Offline mode" in rec.error

    tavily_client = TavilyClient(api_key="tvly-test-dummy-key")
    report = await tavily_client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 412
    assert "Offline mode" in report.rejection_reasons[0]

    assert len(mock_httpx_transport.requests) == 0


@pytest.mark.asyncio
async def test_config_permutation_both_live(mock_httpx_transport, monkeypatch):
    """
    Decoupled permutation: LIVE_LLM=1, LIVE_INTEL=1.
    Verifies:
    - Both managers return is_live_enabled() is True
    - Both clients permit live path (intercepted in memory by MockTransport)
    - Exactly 2 intercepted outbound requests (1 LLM, 1 Tavily)
    """
    monkeypatch.setenv("LIVE_LLM", "1")
    monkeypatch.setenv("LIVE_INTEL", "1")
    monkeypatch.setattr(LLMCassetteManager, "load_cassette", lambda *args, **kwargs: None)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", lambda *args, **kwargs: None)

    assert LLMCassetteManager.is_live_enabled() is True
    assert IntelCassetteManager.is_live_enabled() is True

    llm_client = TokenFactoryClient(api_key="test-dummy-nebius-key")
    content, rec = await llm_client.generate_chat(
        tier=LLMModelTier.SMALL,
        messages=[{"role": "user", "content": "test_permutation_4"}],
        stage="unrecorded_stage_perm_4"
    )
    assert rec.success is True

    tavily_client = TavilyClient(api_key="tvly-test-dummy-key")
    report = await tavily_client.search_with_relevance("CVE-9999-99999")
    assert report.status_code == 200

    assert len(mock_httpx_transport.requests) == 2


# ===========================================================================
# Section 6: In-Memory Mock Backend & Pipeline Integration Test (Task B)
# ===========================================================================

_AUTHORIZED_TEST_CAPABILITY_IDS: set[int] = set()


class InMemoryMockExecutionBackend(ExecutionBackend):
    """
    Mock backend for offline pipeline testing.
    Simulates script execution within temporary filesystem workspaces.
    Spawns zero child subprocesses and executes zero container runtimes.
    Does not enforce kernel network denial; network egress prevention is
    verified at the HTTP transport and Python socket layer by test fixtures.
    """

    def __init__(self, tmp_dir: Path):
        self._tmp_dir = tmp_dir
        self._workspace_path: Optional[Path] = None
        self._execution_count: int = 0
        self.simulated_script_execution: bool = True
        self.temporary_workspace_created: bool = False
        self.zero_child_subprocesses: bool = True
        self.zero_container_runtimes: bool = True

    @property
    def capabilities(self) -> BackendCapabilities:
        caps = BackendCapabilities(
            tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            filesystem_jailed=False,
            host_fs_hidden=False,
            network_kernel_denied=False,
            process_tree_contained=False,
            resource_limits_enforced=False,
            description="In-memory mock execution backend for offline integration testing (simulated turns).",
            boundary_caveats=[
                "TEST DOUBLE: In-memory simulation fixture for offline pipeline orchestration testing only.",
                "NO OS CONTAINMENT: Does not enforce Win32 Job Object limits, cgroups, or process tree containment.",
                "NO KERNEL NETWORK DENIAL: Network isolation is simulated in memory; no OS-level network denial is enforced by this backend.",
                "SIMULATED VERIFICATION: Emitted results simulate execution turns and do not prove real-world exploit reproduction, patch correctness, or sandbox security."
            ]
        )
        _AUTHORIZED_TEST_CAPABILITY_IDS.add(id(caps))
        return caps

    def is_available(self) -> bool:
        return True

    async def initialize_workspace(self, source_repo: Path) -> str:
        workspace_dir = self._tmp_dir / f"ws_{source_repo.name}_{int(time.time() * 1000)}"
        if workspace_dir.exists():
            shutil.rmtree(workspace_dir)
        shutil.copytree(source_repo, workspace_dir)
        self._workspace_path = workspace_dir
        self.temporary_workspace_created = True
        return str(workspace_dir)

    async def provision_dependencies(
        self,
        workspace_id: str,
        manifest_dependencies: List[str],
        timeout: float = 90.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        if on_log:
            on_log("In-memory mock dependency provisioning skipped (test double).")
        current_py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        return ExecutionCommandResult(
            exit_code=0,
            stdout="In-memory mock dependency provisioning skipped (simulated; no host packages installed).",
            stderr="",
            latency_ms=0.0,
            parent_validated=False,
            validation_notes="Mock simulation turn: dependency provisioning skipped (test double; no host packages installed).",
            structured_evidence={
                "supplied_manifest_dependencies": manifest_dependencies,
                "installed_dependencies": [],
                "discovery_performed": False,
                "provisioning_performed": False,
                "host_runner_python": current_py,
                "target_environment_established": False,
                "python_version": "",
                "network_isolated": False,
                "simulated": True,
                "build_output": "In-memory mock dependency provisioning skipped (simulated; no host packages installed).",
            }
        )

    async def execute_script(
        self,
        workspace_id: str,
        script_name: str,
        timeout: float = 10.0,
        sentinel_filename: Optional[str] = None,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        self._execution_count += 1
        if on_log:
            on_log(f"In-memory mock script execution skipped ({script_name}; test double).")
        return ExecutionCommandResult(
            exit_code=0,
            stdout="",
            stderr="",
            latency_ms=0.0,
            sentinel_created=False,
            reproduction_state="SIMULATION_UNVERIFIED",
            assertion_result="SIMULATION_ONLY",
            parent_validated=False,
            validation_notes="Mock simulation turn: in-memory script execution not verified by parent (test double)."
        )

    async def check_sentinel_marker(self, workspace_id: str, sentinel_filename: str) -> bool:
        return False

    async def apply_remediation_diff(
        self,
        workspace_id: str,
        patch_diff: str
    ) -> Dict[str, Any]:
        return {
            "applied": False,
            "target_file": "",
            "hunk_count": 0,
            "latency_ms": 0.0,
            "error": "SKIPPED_SIMULATION",
            "assessment": "SIMULATION_SKIPPED",
            "notes": "Patch application skipped: in-memory mock backend does not apply diffs to target files."
        }

    async def execute_intent_acceptance_test(
        self,
        workspace_id: str,
        target_file: str,
        cve_id: str,
        test_suite_code: str,
        timeout: float = 30.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        if on_log:
            on_log("In-memory mock acceptance test execution skipped (simulated double).")
        return {
            "test_type": "intent_acceptance_suite",
            "executed": False,
            "passed": False,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "latency_ms": 0.0,
            "parent_validated": False,
            "security_control_blocked": False,
            "canary_absence_verified": False,
            "preservation_suite_passed": False,
            "positive_control_passed": False,
            "exact_exception_type": None,
            "is_valid_green": False,
            "error": "SKIPPED_SIMULATION",
            "assessment": "SIMULATION_SKIPPED",
            "notes": "Acceptance test suite not executed: in-memory mock test double does not execute acceptance tests in a verified runtime."
        }

    async def execute_assertion_script(
        self,
        workspace_id: str,
        script_code: str,
        timeout: float = 10.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        if on_log:
            on_log("In-memory mock assertion script execution skipped (simulated double).")
        return ExecutionCommandResult(
            exit_code=0,
            stdout="",
            stderr="",
            latency_ms=0.0,
            sentinel_created=False,
            reproduction_state="SIMULATION_UNVERIFIED",
            assertion_result="SIMULATION_ONLY",
            parent_validated=False,
            validation_notes="Mock simulation turn: assertion script execution not verified by parent."
        )

    async def execute_harness(
        self,
        workspace_id: str,
        harness_code: str,
        sentinel_filename: str,
        timeout: float = 10.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        if on_log:
            on_log("In-memory mock harness execution skipped (simulated double).")
        return ExecutionCommandResult(
            exit_code=0,
            stdout="",
            stderr="",
            latency_ms=0.0,
            sentinel_created=False,
            reproduction_state="SIMULATION_UNVERIFIED",
            assertion_result="SIMULATION_ONLY",
            parent_validated=False,
            validation_notes="Mock simulation turn: harness execution not verified by parent."
        )

    async def run_regression_suite(
        self,
        workspace_id: str,
        timeout: float = 30.0,
        test_file: Optional[str] = None
    ) -> Dict[str, Any]:
        suite_kind = f"Acceptance suite ({test_file})" if test_file else "Regression testing"
        return {
            "executed": False,
            "passed": False,
            "test_count": 0,
            "latency_ms": 0.0,
            "stdout": "",
            "stderr": "",
            "error": "SKIPPED_SIMULATION",
            "assessment": "SIMULATION_SKIPPED",
            "notes": f"{suite_kind} skipped: in-memory mock test double does not spawn a test runner subprocess."
        }

    async def cleanup_workspace(self, workspace_id: str) -> None:
        p = Path(workspace_id)
        if p.exists() and p.is_dir():
            shutil.rmtree(p, ignore_errors=True)

    def generate_attestation(self, workspace_id: str) -> ExecutionAttestation:
        return ExecutionAttestation(
            backend_tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            runtime_engine="in_memory_mock_simulation",
            runtime_version="1.0.0",
            workspace_id=workspace_id,
            network_mode="simulated_no_network",
            capabilities=self.capabilities,
            attestation_timestamp=time.time(),
            verified_by_parent=False,
            boundary_caveats=self.capabilities.boundary_caveats
        )


@pytest.mark.asyncio
async def test_pipeline_offline_structured_cassette_miss_degradation(mock_httpx_transport, block_network, monkeypatch, tmp_path):
    """
    Pipeline integration test verifying structured LLM cassette-miss degradation (Spec §4.7 / §4.8).

    SCOPE & LIMITATIONS (Explicitly Defined):
    - Tests orchestration robustness when structured LLM calls (triage & planning) miss cassettes in offline mode.
    - Demonstrates that the pipeline handles missing structured responses gracefully, records failures in TokenLedger,
      and continues execution via permitted fallback/deterministic repair logic without unhandled exceptions.
    - SIMULATION ONLY: Uses an in-memory test double (InMemoryMockExecutionBackend). Exercises orchestration flow only;
      because parent_validated is truthfully False, VerdictEngine refuses to certify GREEN_STATE_VERIFIED and emits
      UNEXPECTED_FAILURE. Does NOT prove real-world exploit prevention, real patch correctness, or Tier 1 container isolation.
    - BOUNDARIES: Verifies that zero outbound HTTP requests were captured by HTTPX MockTransport and zero
      intercepted socket.socket.connect attempts were observed by the block_network fixture during the test.
      Does not claim universal OS-level or process-wide network denial. Zero container runtimes and zero child
      subprocesses are spawned.
    """
    monkeypatch.setenv("LIVE_LLM", "0")
    monkeypatch.setenv("LIVE_INTEL", "0")
    monkeypatch.setenv("NEBIUS_API_KEY", "test-dummy-nebius-key")
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-dummy-key")
    monkeypatch.setattr(settings, "nebius_api_key", "test-dummy-nebius-key")
    monkeypatch.setattr(settings, "tavily_api_key", "tvly-test-dummy-key")

    # Narrowly scoped, test-only seam permitting in-memory mock backend execution while
    # truthfully maintaining its AssuranceLevel.INSUFFICIENT_ISOLATION classification.
    orig_enforce = SecurityPolicyEngine.enforce_operation_policy

    def mock_test_seam_enforce(operation, capabilities, require_high_assurance=False):
        if id(capabilities) in _AUTHORIZED_TEST_CAPABILITY_IDS:
            return PolicyDecision(
                allowed=True,
                operation=operation,
                assurance_level=AssuranceLevel.INSUFFICIENT_ISOLATION,
                backend_tier=capabilities.tier,
                missing_capabilities=["process_tree_contained", "resource_limits_enforced"],
                policy_violations=[],
                boundary_caveats=capabilities.boundary_caveats,
                rationale="Test seam: explicitly authorized in-memory mock permitted for offline degradation orchestration testing."
            )
        return orig_enforce(operation, capabilities, require_high_assurance=require_high_assurance)

    monkeypatch.setattr(SecurityPolicyEngine, "enforce_operation_policy", mock_test_seam_enforce)

    # Simulate cassette misses for structured LLM stages (triage and planning)
    orig_load_cassette = LLMCassetteManager.load_cassette
    orig_find_cassette = LLMCassetteManager.find_cassette_by_keyword

    miss_fingerprints = {"448e93bd199f4d97487e", "f18d8891ca50513965f3", "a65ff1c7c0fd187805ce", "e5f792557520e9954e22"}

    def mocked_load_cassette(fingerprint: str):
        if fingerprint in miss_fingerprints:
            return None
        return orig_load_cassette(fingerprint)

    def mocked_find_cassette(keyword: str):
        kw_l = keyword.lower()
        if any(k in kw_l for k in ["nano", "super", "small", "mid", "ultra", "nemotron", "triage", "plan"]):
            return None
        return orig_find_cassette(keyword)

    monkeypatch.setattr(LLMCassetteManager, "load_cassette", mocked_load_cassette)
    monkeypatch.setattr(LLMCassetteManager, "find_cassette_by_keyword", mocked_find_cassette)

    repo_path = (Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning").resolve()
    assert repo_path.exists()

    mock_backend = InMemoryMockExecutionBackend(tmp_path)

    req = VerificationPipelineRequest(
        repo_path=str(repo_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=True
    )

    captured_events = []
    res = await VerificationPipeline.run_pipeline(req, on_event=captured_events.append, backend=mock_backend)

    # 1. Pipeline execution under simulated mock turns:
    # Because pre_patch execution is simulated/unverified (reproduction_state="SIMULATION_UNVERIFIED",
    # parent_validated=False), the pipeline deliberately halts before patch synthesis (Stage 2 early stop).
    # It does NOT fabricate a RED reproduction or patch application, and VerdictEngine emits UNEXPECTED_FAILURE.
    assert res.reachability_verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    assert res.pre_patch_result.reproduction_state == "SIMULATION_UNVERIFIED"
    assert res.pre_patch_result.sentinel_created is False
    assert res.pre_patch_result.parent_validated is False
    assert res.remediation.engine == "SKIPPED"
    assert res.remediation.success is False
    assert res.remediation.validation_status == "SKIPPED"
    assert res.post_patch_result.reproduction_state == "SIMULATION_UNVERIFIED"
    assert res.post_patch_result.parent_validated is False
    assert res.final_behavioral_verdict == "UNEXPECTED_FAILURE"
    assert "unexpected state" in res.verdict_record.reason.lower()

    # Verify event truthfulness: deliberate early stop on unverified pre-patch state
    assert any(e.stage == "REPRODUCTION" and "PRE-PATCH STATE: SIMULATION_UNVERIFIED" in e.message for e in captured_events)
    assert any(e.stage == "PATCH" and "Halting automated patch synthesis" in e.message for e in captured_events)
    assert any(e.stage == "REGRESSION" and "Baseline regression suite SKIPPED" in e.message for e in captured_events)
    assert not any("RED STATE REPRODUCED" in e.message for e in captured_events)
    assert not any("GREEN STATE VERIFIED" in e.message for e in captured_events)
    assert not any("POST-PATCH RE-TEST SIMULATED" in e.message for e in captured_events)
    assert not any("POST-PATCH ACCEPTANCE" in e.message for e in captured_events)

    # 2. Mock backend attestation and policy reflect truthful test double semantics
    assert res.isolation_attestation is not None
    assert res.isolation_attestation["runtime_engine"] == "in_memory_mock_simulation"
    assert res.isolation_attestation["network_mode"] == "simulated_no_network"
    assert res.isolation_attestation["verified_by_parent"] is False
    assert len(res.isolation_attestation["boundary_caveats"]) == 4
    assert res.policy_decision["assurance_level"] == "INSUFFICIENT_ISOLATION"

    # 3. Threat intel resolved deterministically from local cassette
    assert res.threat_intel is not None
    assert res.threat_intel.cve_id == "CVE-2020-14343"

    # 4. Structured LLM degradation verification under cassette misses:
    # Directly exercises triage, planning, and remediation fallback under cassette misses.
    from vulntrace.agent.patcher import RemediationPatcher
    from vulntrace.models import RemediationRequest

    test_ledger = TokenLedger()
    token_client = TokenFactoryClient(ledger=test_ledger)
    file_snippet = "import yaml\ndef parse_app_config(s):\n    return yaml.load(s)\n"

    # Triage under cassette miss -> records failure, 0 tokens, no unhandled exception
    triage_out, triage_rec = await token_client.generate_structured(
        tier=LLMModelTier.SMALL,
        response_model=TriageAnalysisOutput,
        messages=[{"role": "user", "content": file_snippet}],
        stage="triage_classification"
    )
    assert triage_out is None
    assert triage_rec.success is False
    assert triage_rec.total_tokens == 0
    assert triage_rec.prompt_tokens == 0
    assert triage_rec.completion_tokens == 0
    assert "Offline mode" in (triage_rec.error or "")

    # Planning under cassette miss -> records failure, 0 tokens, no unhandled exception
    plan_out, plan_rec = await token_client.generate_structured(
        tier=LLMModelTier.MID,
        response_model=PatchPlanOutput,
        messages=[{"role": "user", "content": file_snippet}],
        stage="patch_planning"
    )
    assert plan_out is None
    assert plan_rec.success is False
    assert plan_rec.total_tokens == 0
    assert plan_rec.prompt_tokens == 0
    assert plan_rec.completion_tokens == 0
    assert "Offline mode" in (plan_rec.error or "")

    summary = test_ledger.get_summary()
    assert summary.total_calls >= 2
    failed_calls = [c for c in summary.calls if not c.success]
    assert len(failed_calls) == summary.total_calls
    assert len(failed_calls) >= 2

    # Remediation synthesis fallback -> AST deterministic codemod succeeds gracefully
    target_file = tmp_path / "service" / "custom_loader.py"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(file_snippet, encoding="utf-8")
    rem_req = RemediationRequest(
        repo_path=str(tmp_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        vulnerable_call="yaml.load",
        use_nemotron=True,
        allow_ast_fallback=True
    )
    rem_out = await RemediationPatcher.synthesize_remediation(rem_req, workspace_dir=tmp_path, ledger=test_ledger)
    assert rem_out.success is True
    assert rem_out.engine == "AST_DETERMINISTIC_CODEMOD"
    assert rem_out.validation_status == "ACCEPTED"
    assert "safe_load" in target_file.read_text(encoding="utf-8")

    # 5. Network boundary: Distinguish client-level HTTP transport from Python socket.socket.connect attempts
    # - HTTPX client transport captured exactly 0 HTTP requests
    assert len(mock_httpx_transport.requests) == 0
    # - block_network fixture observed exactly 0 intercepted socket.socket.connect attempts during the test
    assert len(block_network.attempts) == 0

    # 6. Backend execution boundary: simulated execution, temporary workspace, zero subprocesses, zero containers
    assert mock_backend.simulated_script_execution is True
    assert mock_backend.temporary_workspace_created is True
    assert mock_backend.zero_child_subprocesses is True
    assert mock_backend.zero_container_runtimes is True

    # 7. Truthful simulation evidence fields (regression, dependency inputs, zero simulation latencies)
    assert res.regression_tests["executed"] is False
    assert res.regression_tests["passed"] is False
    assert res.regression_tests["assessment"] == "SIMULATION_SKIPPED"
    assert res.regression_tests["test_count"] == 0
    assert res.regression_tests["latency_ms"] == 0.0
    assert res.environment is not None
    assert res.environment.build_duration_ms == 0.0
    assert res.environment.python_version == ""
    assert res.environment.has_manifest is True
    assert len(res.environment.detected_dependencies) > 0
    assert res.pre_patch_result.latency_ms == 0.0
    assert res.post_patch_result.latency_ms == 0.0
    assert res.final_behavioral_verdict == "UNEXPECTED_FAILURE"
    assert res.verdict_record.evidence_summary["regression_passed"] is False
    assert res.verdict_record.evidence_summary["regression_test_count"] == 0


def test_regression_evidence_contract_semantics():
    """
    Unit verification of RegressionEvidence contract and VerdictEngine gating (Spec §4.11 / §5).
    Verifies:
    1. Unexecuted regression (executed=False, passed=False) does NOT trigger REGRESSION_FAILURE;
       falls through to UNEXPECTED_FAILURE when parent_validated=False.
    2. Executed regression failure (executed=True, passed=False) DOES trigger REGRESSION_FAILURE.
    3. Executed passing regression (executed=True, passed=True) with parent_validated=False
       cannot obtain GREEN_STATE_VERIFIED (emits UNEXPECTED_FAILURE).
    4. Backward-compatible default: when a backend dictionary omits 'executed',
       pipeline default regression_res.get('executed', True) resolves to True.
    """
    repo_ev = RepositoryEvidence(repo_path="/fake/repo", manifest_files=["requirements.txt"], python_files_count=1)
    advisory_ev = AdvisoryEvidence(cve_id="CVE-2020-14343", found=True, summary="test", source_url="https://osv.dev")
    reach_ev = ReachabilityEvidence(
        target_symbol="yaml.load",
        discovered_call_sites_count=1,
        reachable_vulnerabilities_count=1,
        unreachable_dead_code_count=0,
        entrypoints=["main.py"],
        verdict="REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
    )
    exec_ev = ExecutionEvidence(sandbox_engine="LOCAL_SUBPROCESS_FALLBACK", cloud_status="PERMISSION_DENIED (HTTP 403)")
    patch_ev = PatchEvidence(engine="MOCK", target_file="test.py", diff="+safe", validation_status="ACCEPTED", latency_ms=0.0, success=True)

    # Case 1: Skipped regression (executed=False, passed=False) -> MUST NOT emit REGRESSION_FAILURE
    behavior_ev_mock = BehaviorEvidence(
        pre_patch_exit_code=0, pre_patch_sentinel_observed=True, pre_patch_state="RED_STATE_REPRODUCED",
        post_patch_exit_code=0, post_patch_sentinel_observed=False, post_patch_state="GREEN_STATE_BLOCKED",
        parent_validated=False
    )
    reg_skipped = RegressionEvidence(executed=False, passed=False, test_count=0, latency_ms=0.0, error="SKIPPED_SIMULATION")
    verdict_1 = VerdictEngine.evaluate("CVE-2020-14343", "/repo", repo_ev, advisory_ev, reach_ev, behavior_ev_mock, patch_ev, reg_skipped, exec_ev)
    assert verdict_1.terminal_state == "UNEXPECTED_FAILURE"
    assert verdict_1.terminal_state != "REGRESSION_FAILURE"
    assert verdict_1.evidence_summary["regression_passed"] is False

    # Case 2: Genuine executed regression failure (executed=True, passed=False) -> MUST emit REGRESSION_FAILURE
    reg_failed = RegressionEvidence(executed=True, passed=False, test_count=3, latency_ms=12.5, error="pytest failed: 1 failure")
    verdict_2 = VerdictEngine.evaluate("CVE-2020-14343", "/repo", repo_ev, advisory_ev, reach_ev, behavior_ev_mock, patch_ev, reg_failed, exec_ev)
    assert verdict_2.terminal_state == "REGRESSION_FAILURE"
    assert "regressions" in verdict_2.reason.lower()

    # Case 3: Executed passing regression (executed=True, passed=True) with parent_validated=False -> CANNOT obtain GREEN_STATE_VERIFIED
    reg_passed = RegressionEvidence(executed=True, passed=True, test_count=5, latency_ms=15.0)
    verdict_3 = VerdictEngine.evaluate("CVE-2020-14343", "/repo", repo_ev, advisory_ev, reach_ev, behavior_ev_mock, patch_ev, reg_passed, exec_ev)
    assert verdict_3.terminal_state == "UNEXPECTED_FAILURE"
    assert verdict_3.terminal_state != "GREEN_STATE_VERIFIED"

    # Case 4: Backward-compatible backend result dictionary omitting 'executed'
    legacy_backend_dict = {"passed": True, "exit_code": 0, "test_count": 4, "latency_ms": 11.2}
    resolved_exec_4 = legacy_backend_dict.get("executed", True)
    assert resolved_exec_4 is True
    reg_legacy = RegressionEvidence(
        executed=resolved_exec_4,
        passed=legacy_backend_dict["passed"],
        test_count=legacy_backend_dict["test_count"],
        latency_ms=legacy_backend_dict["latency_ms"]
    )
    assert reg_legacy.executed is True
    assert reg_legacy.passed is True

    # Case 5: Legacy backend failing regression omitting 'executed' -> triggers REGRESSION_FAILURE
    legacy_failed_dict = {"passed": False, "exit_code": 1, "test_count": 2, "latency_ms": 9.5, "error": "pytest failure"}
    resolved_exec_5 = legacy_failed_dict.get("executed", True)
    assert resolved_exec_5 is True
    reg_legacy_failed = RegressionEvidence(
        executed=resolved_exec_5,
        passed=legacy_failed_dict["passed"],
        test_count=legacy_failed_dict["test_count"],
        latency_ms=legacy_failed_dict["latency_ms"],
        error=legacy_failed_dict["error"]
    )
    verdict_5 = VerdictEngine.evaluate("CVE-2020-14343", "/repo", repo_ev, advisory_ev, reach_ev, behavior_ev_mock, patch_ev, reg_legacy_failed, exec_ev)
    assert verdict_5.terminal_state == "REGRESSION_FAILURE"

    # Case 6: Contradictory backend result {"executed": False, "passed": True}
    # Normalization contract: When executed=False, passed MUST be normalized to False
    contradictory_dict = {"executed": False, "passed": True, "test_count": 0, "latency_ms": 0.0}
    resolved_exec_6 = contradictory_dict.get("executed", True)
    resolved_passed_6 = contradictory_dict.get("passed", False) if resolved_exec_6 else False
    reg_contradictory = RegressionEvidence(
        executed=resolved_exec_6,
        passed=resolved_passed_6,
        test_count=contradictory_dict["test_count"],
        latency_ms=contradictory_dict["latency_ms"]
    )
    assert reg_contradictory.executed is False
    assert reg_contradictory.passed is False


@pytest.mark.asyncio
async def test_pipeline_production_regression_and_acceptance_contracts(tmp_path, monkeypatch):
    """
    Directly exercises VerificationPipeline production code paths for:
    1. Truthful mock simulation claims for remediation and acceptance tests.
    2. Genuine executed regression failure producing REGRESSION_FAILURE in Stage 5.
    3. Legacy backend omitting 'executed' handled as executed=True by the actual pipeline.
    4. Early-return unreachable code regression logging accurately reporting genuine failure.
    5. Simulated acceptance test (executed=False) handled as skipped / unverified.
    6. Genuinely executed failing acceptance test producing RED_STATE_PERSISTS.
    7. Legacy backend omitting 'executed' on acceptance defaulting to executed=True.
    8. Early stop on unverified simulation backend at Stage 2.
    9. Contradictory backend regression (executed=False, passed=True) normalized to passed=False.
    10. Unvalidated RED state halting Stage 2 with VERIFICATION_REJECTED.
    11. Section D acceptance skip semantics certifying green state cannot be verified without executed acceptance.
    12. Post-patch behavioral persistence with skipped acceptance: supplied validated RED preserved vs unverified normalized to UNEXPECTED_FAILURE.
    """
    from vulntrace.models import AstAnalyzeResponse
    from vulntrace.analyzer.ast_visitor import AstReachabilityAnalyzer
    from vulntrace.core.policy import ExecutionOperation

    # Test-scoped policy seam for in-memory mock backend
    orig_enforce = SecurityPolicyEngine.enforce_operation_policy
    def mock_test_seam_enforce(operation, capabilities, require_high_assurance=False):
        if id(capabilities) in _AUTHORIZED_TEST_CAPABILITY_IDS:
            return PolicyDecision(
                allowed=True,
                operation=operation,
                assurance_level=AssuranceLevel.INSUFFICIENT_ISOLATION,
                backend_tier=capabilities.tier,
                missing_capabilities=["process_tree_contained", "resource_limits_enforced"],
                policy_violations=[],
                boundary_caveats=capabilities.boundary_caveats,
                rationale="Test seam: explicitly authorized in-memory test double permitted for contract testing."
            )
        return orig_enforce(operation, capabilities, require_high_assurance=require_high_assurance)

    monkeypatch.setattr(SecurityPolicyEngine, "enforce_operation_policy", mock_test_seam_enforce)

    # Adversarial check: descriptive strings alone cannot grant policy allowance to un-registered backends
    unauthorized_spoofed_caps = BackendCapabilities(
        tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
        description="In-memory mock execution backend for offline integration testing (simulated turns).",
        boundary_caveats=[]
    )
    spoofed_decision = SecurityPolicyEngine.enforce_operation_policy(
        ExecutionOperation.DEPENDENCY_PROVISIONING,
        unauthorized_spoofed_caps
    )
    assert spoofed_decision.allowed is False
    assert "Backend lacks minimal process tree containment and memory caps." in spoofed_decision.policy_violations

    # 1. Truthful simulation methods on InMemoryMockExecutionBackend
    backend = InMemoryMockExecutionBackend(tmp_path)
    rem_res = await backend.apply_remediation_diff("ws-1", "diff")
    assert rem_res["applied"] is False
    assert rem_res["hunk_count"] == 0
    assert rem_res["assessment"] == "SIMULATION_SKIPPED"

    acc_res = await backend.execute_intent_acceptance_test("ws-1", "test.py", "CVE-1", "code")
    assert acc_res["executed"] is False
    assert acc_res["passed"] is False
    assert acc_res["security_control_blocked"] is False
    assert acc_res["canary_absence_verified"] is False
    assert acc_res["is_valid_green"] is False
    assert acc_res["assessment"] == "SIMULATION_SKIPPED"

    assert (await backend.execute_harness("ws-1", "code", "marker")).parent_validated is False
    assert (await backend.execute_assertion_script("ws-1", "code")).parent_validated is False

    repo_path = (Path(__file__).resolve().parent.parent / "benchmarks" / "contextual_reasoning").resolve()

    # 2. Pipeline Stage 5: Genuine executed regression failure producing REGRESSION_FAILURE
    class ExecutedBaseBackend(InMemoryMockExecutionBackend):
        """
        Synthetic test double with controlled observer for test-scoped downstream contract validation.
        Scopes parent-validated turns specifically to verify Stage 4 acceptance and Stage 5
        regression failure paths without running containers or subprocesses.
        """
        @property
        def capabilities(self) -> BackendCapabilities:
            caps = BackendCapabilities(
                tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
                filesystem_jailed=False,
                host_fs_hidden=False,
                network_kernel_denied=False,
                process_tree_contained=False,
                resource_limits_enforced=False,
                description="Synthetic test double with controlled observer for downstream contract testing.",
                boundary_caveats=[
                    "TEST DOUBLE: Synthetic controlled execution fixture for testing downstream contract branches.",
                    "NO OS CONTAINMENT: Does not enforce Win32 Job Object limits, cgroups, or process tree containment.",
                    "NO KERNEL NETWORK DENIAL: Network isolation is simulated in memory.",
                    "SYNTHETIC VERIFICATION: Emitted results simulate verified turns for testing failure branches and do not prove real sandbox security."
                ]
            )
            _AUTHORIZED_TEST_CAPABILITY_IDS.add(id(caps))
            return caps

        async def execute_script(
            self,
            workspace_id: str,
            script_name: str,
            timeout: float = 10.0,
            sentinel_filename: Optional[str] = None,
            on_log: Optional[Callable[[str], None]] = None
        ) -> ExecutionCommandResult:
            self._execution_count += 1
            ws_path = Path(workspace_id)
            if self._execution_count == 1:
                # Turn 1 (Pre-patch): physically write the sentinel marker on disk to allow real observation
                if sentinel_filename:
                    (ws_path / sentinel_filename).write_text("synthetic sentinel marker", encoding="utf-8")
                return ExecutionCommandResult(
                    exit_code=0,
                    stdout="RED_PASSED",
                    stderr="",
                    latency_ms=10.0,
                    sentinel_created=True,
                    reproduction_state="RED_STATE_REPRODUCED",
                    assertion_result="EXPLOIT_SENTINEL_TRIGGERED",
                    parent_validated=True,
                    validation_notes="Synthetic observer: sentinel marker created on disk with exit code 0."
                )
            else:
                # Turn 2 (Post-patch): remove sentinel marker on disk so observer confirms absence
                if sentinel_filename and (ws_path / sentinel_filename).exists():
                    (ws_path / sentinel_filename).unlink()
                return ExecutionCommandResult(
                    exit_code=42,
                    stdout="GREEN_SECURITY_BLOCK_VERIFIED",
                    stderr="",
                    latency_ms=10.0,
                    sentinel_created=False,
                    reproduction_state="GREEN_STATE_BLOCKED",
                    assertion_result="GREEN_SECURITY_BLOCK_VERIFIED",
                    parent_validated=True,
                    validation_notes="Synthetic observer: exit code 42, zero sentinel markers."
                )

        async def check_sentinel_marker(self, workspace_id: str, sentinel_filename: str) -> bool:
            """Physical observer: checks actual on-disk marker existence in workspace."""
            return (Path(workspace_id) / sentinel_filename).exists()

        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            if test_file:
                return await super().run_regression_suite(workspace_id, timeout, test_file)
            return {
                "executed": True,
                "passed": True,
                "test_count": 5,
                "latency_ms": 12.0,
                "stdout": "5 passed in 0.01s",
                "stderr": ""
            }

    class FailingRegressionBackend(ExecutedBaseBackend):
        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            if test_file:
                return await super().run_regression_suite(workspace_id, timeout, test_file)
            return {
                "executed": True,
                "passed": False,
                "test_count": 5,
                "latency_ms": 14.2,
                "stdout": "",
                "stderr": "FAILED tests/test_core.py - 1 failure",
                "error": "pytest failure"
            }

    failing_backend = FailingRegressionBackend(tmp_path)
    events_fail = []
    req_fail = VerificationPipelineRequest(
        repo_path=str(repo_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=False
    )
    res_fail = await VerificationPipeline.run_pipeline(req_fail, on_event=events_fail.append, backend=failing_backend)
    assert res_fail.regression_tests["executed"] is True
    assert res_fail.regression_tests["passed"] is False
    assert res_fail.verdict_record.terminal_state == "REGRESSION_FAILURE"
    assert any(e.stage == "REGRESSION" and "REGRESSION FAILURE" in e.message for e in events_fail)

    # 3. Pipeline Stage 5: Legacy backend omitting 'executed' handled as executed=True
    class LegacyOmittingBackend(ExecutedBaseBackend):
        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            if test_file:
                return await super().run_regression_suite(workspace_id, timeout, test_file)
            return {
                "passed": False,
                "test_count": 2,
                "latency_ms": 11.0,
                "stderr": "legacy pytest failed"
            }

    legacy_backend = LegacyOmittingBackend(tmp_path)
    events_legacy = []
    res_legacy = await VerificationPipeline.run_pipeline(req_fail, on_event=events_legacy.append, backend=legacy_backend)
    assert res_legacy.regression_tests.get("executed", True) is True
    assert res_legacy.regression_tests["passed"] is False
    assert res_legacy.verdict_record.terminal_state == "REGRESSION_FAILURE"
    assert any(e.stage == "REGRESSION" and "REGRESSION FAILURE" in e.message for e in events_legacy)

    # 4. Pipeline Site 1: Early-return unreachable false positive logging genuine regression failure
    class EarlyFailingBackend(InMemoryMockExecutionBackend):
        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            return {
                "executed": True,
                "passed": False,
                "test_count": 3,
                "latency_ms": 8.0,
                "stderr": "baseline test failure",
                "error": "baseline test failure"
            }

    early_backend = EarlyFailingBackend(tmp_path)
    events_early = []
    orig_ast_analyze = AstReachabilityAnalyzer.analyze_repository
    monkeypatch.setattr(
        AstReachabilityAnalyzer,
        "analyze_repository",
        lambda *args, **kwargs: AstAnalyzeResponse(
            repo_path=str(repo_path),
            analyzed_files=[],
            total_functions=0,
            discovered_calls=[],
            reachable_vulnerabilities_count=0,
            unreachable_dead_code_count=0,
            verdict="UNREACHABLE_FALSE_POSITIVE",
            nodes=[],
            edges=[],
            latency_ms=1.0
        )
    )

    req_unreachable = VerificationPipelineRequest(
        repo_path=str(repo_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        use_nemotron=False
    )
    res_unreachable = await VerificationPipeline.run_pipeline(req_unreachable, on_event=events_early.append, backend=early_backend)
    assert res_unreachable.reachability_verdict == "UNREACHABLE_FALSE_POSITIVE"
    assert res_unreachable.final_behavioral_verdict == "UNREACHABLE_FALSE_POSITIVE"
    assert res_unreachable.verdict_record.evidence_summary["regression_passed"] is False
    # Site 1 accurately logged REGRESSION FAILURE instead of falsely claiming tests passed
    assert any(e.stage == "REGRESSION" and "REGRESSION FAILURE" in e.message for e in events_early)
    assert not any("tests passed" in e.message for e in events_early if e.stage == "REGRESSION")

    # Restore reachability analyzer for end-to-end acceptance test verification
    monkeypatch.setattr(AstReachabilityAnalyzer, "analyze_repository", orig_ast_analyze)

    # 5. Simulated acceptance test (executed=False) is explicitly skipped/unverified;
    # does NOT emit real acceptance failure or green confirmed events, and does not claim RED_STATE_PERSISTS
    events_acc = []
    backend_acc = ExecutedBaseBackend(tmp_path)
    req_acc = VerificationPipelineRequest(
        repo_path=str(repo_path),
        cve_id="CVE-2020-14343",
        target_file="service/custom_loader.py",
        target_function="parse_app_config",
        vulnerable_symbol="yaml.load",
        intent_requirement="Reject dangerous YAML loading while preserving custom safe tags",
        use_nemotron=True
    )
    res_acc = await VerificationPipeline.run_pipeline(req_acc, on_event=events_acc.append, backend=backend_acc)
    assert not any("POST-PATCH ACCEPTANCE GREEN CONFIRMED" in e.message for e in events_acc)
    assert not any("POST-PATCH ACCEPTANCE FAILED" in e.message for e in events_acc)
    assert any(e.stage == "ACCEPTANCE" and "Post-patch acceptance test SKIPPED (UNVERIFIED)" in e.message for e in events_acc)
    assert res_acc.final_behavioral_verdict == "UNEXPECTED_FAILURE"
    assert res_acc.final_behavioral_verdict != "GREEN_STATE_VERIFIED"
    assert res_acc.final_behavioral_verdict != "RED_STATE_PERSISTS"

    # 6. Genuinely executed, failing acceptance test follows established failure path
    class FailingAcceptanceBackend(ExecutedBaseBackend):
        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            if test_file:
                return {
                    "executed": True,
                    "passed": False,
                    "test_count": 1,
                    "latency_ms": 15.0,
                    "stdout": "test_security_probe_rejection FAILED",
                    "stderr": "AssertionError: probe was not blocked"
                }
            return await super().run_regression_suite(workspace_id, timeout, test_file)

    events_failing_acc = []
    backend_failing_acc = FailingAcceptanceBackend(tmp_path)
    res_failing_acc = await VerificationPipeline.run_pipeline(req_acc, on_event=events_failing_acc.append, backend=backend_failing_acc)
    assert not any("POST-PATCH ACCEPTANCE GREEN CONFIRMED" in e.message for e in events_failing_acc)
    assert any(e.stage == "ACCEPTANCE" and "POST-PATCH ACCEPTANCE FAILED" in e.message for e in events_failing_acc)
    assert res_failing_acc.final_behavioral_verdict == "RED_STATE_PERSISTS"
    assert "Vulnerability still active post-patch" in res_failing_acc.verdict_record.reason

    # 7. Legacy backend omitting 'executed' on acceptance tests defaults to executed=True (backward-compatible failure path)
    class LegacyAcceptanceBackend(ExecutedBaseBackend):
        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            if test_file:
                return {
                    "passed": False,
                    "test_count": 1,
                    "latency_ms": 10.0,
                    "stdout": "test_security_probe_rejection FAILED",
                    "stderr": "AssertionError: probe was not blocked"
                }
            return await super().run_regression_suite(workspace_id, timeout, test_file)

    events_legacy_acc = []
    backend_legacy_acc = LegacyAcceptanceBackend(tmp_path)
    res_legacy_acc = await VerificationPipeline.run_pipeline(req_acc, on_event=events_legacy_acc.append, backend=backend_legacy_acc)
    assert any(e.stage == "ACCEPTANCE" and "POST-PATCH ACCEPTANCE FAILED" in e.message for e in events_legacy_acc)
    assert res_legacy_acc.final_behavioral_verdict == "RED_STATE_PERSISTS"

    # 8. Real pipeline deliberate early stop on unverified simulation backend:
    # Verifies that when InMemoryMockExecutionBackend is used directly, the pipeline halts at Stage 2
    # without fabricating exploit reproduction or patch application.
    events_early_stop = []
    backend_unverified = InMemoryMockExecutionBackend(tmp_path)
    res_unverified = await VerificationPipeline.run_pipeline(req_acc, on_event=events_early_stop.append, backend=backend_unverified)
    assert res_unverified.pre_patch_result.reproduction_state == "SIMULATION_UNVERIFIED"
    assert res_unverified.pre_patch_result.sentinel_created is False
    assert res_unverified.pre_patch_result.parent_validated is False
    assert res_unverified.remediation.engine == "SKIPPED"
    assert res_unverified.remediation.validation_status == "SKIPPED"
    assert res_unverified.remediation.diff == ""
    assert res_unverified.remediation.success is False
    assert res_unverified.post_patch_result.reproduction_state == "SIMULATION_UNVERIFIED"
    assert res_unverified.post_patch_result.parent_validated is False
    assert res_unverified.final_behavioral_verdict == "UNEXPECTED_FAILURE"
    assert any(e.stage == "REPRODUCTION" and "PRE-PATCH STATE: SIMULATION_UNVERIFIED" in e.message for e in events_early_stop)
    assert any(e.stage == "PATCH" and "Halting automated patch synthesis" in e.message for e in events_early_stop)
    assert not any("RED STATE REPRODUCED" in e.message for e in events_early_stop)
    assert not any("GREEN STATE VERIFIED" in e.message for e in events_early_stop)

    # 9. Pipeline encountering contradictory regression {"executed": False, "passed": True} normalizes passed=False
    class ContradictoryRegressionBackend(ExecutedBaseBackend):
        async def run_regression_suite(self, workspace_id: str, timeout: float = 30.0, test_file: Optional[str] = None) -> Dict[str, Any]:
            if test_file:
                return await super().run_regression_suite(workspace_id, timeout, test_file)
            return {
                "executed": False,
                "passed": True,  # Contradictory assertion from backend
                "test_count": 0,
                "latency_ms": 0.0,
                "notes": "Backend claimed passed despite not running tests"
            }

    contradictory_backend = ContradictoryRegressionBackend(tmp_path)
    events_contra = []
    res_contra = await VerificationPipeline.run_pipeline(req_fail, on_event=events_contra.append, backend=contradictory_backend)
    assert res_contra.regression_tests["executed"] is False
    assert res_contra.regression_tests["passed"] is False
    assert res_contra.regression_tests == {
        "executed": False,
        "passed": False,
        "test_count": 0,
        "latency_ms": 0.0,
        "notes": "Backend claimed passed despite not running tests"
    }
    assert res_contra.verdict_record.evidence_summary["regression_passed"] is False
    assert any(e.stage == "REGRESSION" and "Regression suite SKIPPED" in e.message for e in events_contra)
    assert not any("Regression suite PASSED" in e.message for e in events_contra)

    # 10. Pre-patch RED with parent_validated=False halts at Stage 2 with skipped remediation,
    # emits unverified warning, no verified RED event, and produces VERIFICATION_REJECTED
    class UnvalidatedRedBackend(InMemoryMockExecutionBackend):
        async def execute_script(
            self,
            workspace_id: str,
            script_name: str,
            timeout: float = 10.0,
            sentinel_filename: Optional[str] = None,
            on_log: Optional[Callable[[str], None]] = None
        ) -> ExecutionCommandResult:
            return ExecutionCommandResult(
                exit_code=0,
                stdout="RED_STATE_OBSERVED_WITHOUT_ATTESTATION",
                stderr="",
                latency_ms=1.0,
                sentinel_created=True,
                reproduction_state="RED_STATE_REPRODUCED",
                assertion_result="EXPLOIT_SENTINEL_TRIGGERED",
                parent_validated=False,  # Unvalidated RED state!
                validation_notes="Unvalidated observer: missing trust attestation"
            )

    unvalidated_red_backend = UnvalidatedRedBackend(tmp_path)
    events_unvalidated_red = []
    res_unvalidated_red = await VerificationPipeline.run_pipeline(req_acc, on_event=events_unvalidated_red.append, backend=unvalidated_red_backend)
    assert res_unvalidated_red.remediation.engine == "SKIPPED"
    assert res_unvalidated_red.remediation.diff == ""
    assert res_unvalidated_red.remediation.success is False
    assert res_unvalidated_red.remediation.validation_status == "SKIPPED"
    assert res_unvalidated_red.final_behavioral_verdict == "VERIFICATION_REJECTED"
    assert res_unvalidated_red.final_behavioral_verdict != "GREEN_STATE_VERIFIED"
    assert res_unvalidated_red.verdict_record.terminal_state == "VERIFICATION_REJECTED"
    assert not any("GREEN STATE VERIFIED" in e.message for e in events_unvalidated_red)
    assert any(e.stage == "REPRODUCTION" and "PRE-PATCH REPRODUCTION UNVERIFIED: RED state reported without parent validation" in e.message for e in events_unvalidated_red)
    assert not any(e.stage == "REPRODUCTION" and "RED STATE REPRODUCED" in e.message for e in events_unvalidated_red)
    assert any(e.stage == "PATCH" and "Halting automated patch synthesis" in e.message for e in events_unvalidated_red)

    # 11. Section D acceptance test skip semantics:
    # A candidate GREEN state cannot be certified when required post-patch acceptance test was skipped / unverified;
    # a skipped acceptance suite does not itself manufacture RED_STATE_PERSISTS.
    assert res_acc.verdict_record.terminal_state == "UNEXPECTED_FAILURE"
    assert "Required post-patch acceptance test was skipped / unverified" in res_acc.verdict_record.reason
    assert res_acc.verdict_record.is_safe_claim is False
    assert res_acc.verdict_record.evidence_summary["terminal_state"] == "UNEXPECTED_FAILURE"

    # 12. Post-patch behavioral result and skipped acceptance test reconciliation:
    # 12A: Preserving RED_STATE_PERSISTS when post-patch behavioral turn supplies parent_validated=True:
    # Emits a synthetic, contract-shaped RED_STATE_PERSISTS result where parent_validated=True is
    # manually supplied by the test double to test pipeline verdict reconciliation.
    # NOTE: parent_validated=True is manually supplied by this test double and does not independently
    # establish real parent validation.
    # Downstream pipeline logic preserves the supplied validated RED_STATE_PERSISTS verdict even when
    # the post-patch acceptance suite returns executed=False.
    class PersistentRedBackend(ExecutedBaseBackend):
        """
        Synthetic test double for Case 12A.
        Manually supplies parent_validated=True on a contract-shaped RED_STATE_PERSISTS
        turn to test downstream pipeline preservation when acceptance tests are skipped.
        Does NOT execute real exploits, verify files on disk, or perform real parent validation.
        """
        async def execute_script(
            self,
            workspace_id: str,
            script_name: str,
            timeout: float = 10.0,
            sentinel_filename: Optional[str] = None,
            on_log: Optional[Callable[[str], None]] = None
        ) -> ExecutionCommandResult:
            self._execution_count += 1
            if self._execution_count == 1:
                return ExecutionCommandResult(
                    exit_code=0,
                    stdout="SYNTHETIC_RED_PRE_PATCH",
                    stderr="",
                    latency_ms=10.0,
                    sentinel_created=False,
                    reproduction_state="RED_STATE_REPRODUCED",
                    assertion_result="SYNTHETIC_CONTRACT_RED",
                    parent_validated=True,
                    validation_notes="Synthetic test double: pre-patch contract-shaped red state (parent_validated manually supplied by test double; not real parent validation)."
                )
            else:
                return ExecutionCommandResult(
                    exit_code=0,
                    stdout="SYNTHETIC_RED_POST_PATCH_PERSISTENCE",
                    stderr="",
                    latency_ms=10.0,
                    sentinel_created=False,
                    reproduction_state="RED_STATE_PERSISTS",
                    assertion_result="SYNTHETIC_CONTRACT_PERSISTENCE",
                    parent_validated=True,
                    validation_notes="Synthetic test double: post-patch contract-shaped persistence (parent_validated manually supplied by test double; not real parent validation)."
                )

    events_pers_red = []
    backend_pers_red = PersistentRedBackend(tmp_path)
    res_pers_red = await VerificationPipeline.run_pipeline(req_acc, on_event=events_pers_red.append, backend=backend_pers_red)
    assert res_pers_red.post_patch_result.reproduction_state == "RED_STATE_PERSISTS"
    assert res_pers_red.post_patch_result.parent_validated is True
    assert res_pers_red.post_patch_result.assertion_result == "SYNTHETIC_CONTRACT_PERSISTENCE"
    assert res_pers_red.post_patch_result.validation_notes == "Synthetic test double: post-patch contract-shaped persistence (parent_validated manually supplied by test double; not real parent validation)."
    assert res_pers_red.final_behavioral_verdict == "RED_STATE_PERSISTS"
    assert res_pers_red.verdict_record.terminal_state == "RED_STATE_PERSISTS"
    assert res_pers_red.verdict_record.is_safe_claim is False
    assert "acceptance_note" in res_pers_red.verdict_record.evidence_summary
    assert "independently justified" in res_pers_red.verdict_record.evidence_summary["acceptance_note"]

    # 12B: Unverified behavioral persistence with skipped acceptance suite:
    # Post-patch reports RED_STATE_PERSISTS with parent_validated=False and acceptance suite executed=False.
    # Lacking parent validation, the skipped acceptance suite cannot justify RED_STATE_PERSISTS,
    # and the result is classified as UNEXPECTED_FAILURE.
    class UnverifiedPersistentRedBackend(ExecutedBaseBackend):
        """
        Synthetic test double for Case 12B.
        Supplies parent_validated=False on a contract-shaped RED_STATE_PERSISTS turn
        to verify that unverified persistence is normalized to UNEXPECTED_FAILURE
        when acceptance tests are skipped.
        """
        async def execute_script(
            self,
            workspace_id: str,
            script_name: str,
            timeout: float = 10.0,
            sentinel_filename: Optional[str] = None,
            on_log: Optional[Callable[[str], None]] = None
        ) -> ExecutionCommandResult:
            self._execution_count += 1
            if self._execution_count == 1:
                return ExecutionCommandResult(
                    exit_code=0,
                    stdout="SYNTHETIC_RED_PRE_PATCH",
                    stderr="",
                    latency_ms=10.0,
                    sentinel_created=False,
                    reproduction_state="RED_STATE_REPRODUCED",
                    assertion_result="SYNTHETIC_CONTRACT_RED",
                    parent_validated=True,
                    validation_notes="Synthetic test double: pre-patch contract-shaped red state (parent_validated manually supplied by test double; not real parent validation)."
                )
            else:
                return ExecutionCommandResult(
                    exit_code=0,
                    stdout="SYNTHETIC_UNVERIFIED_PERSISTENCE",
                    stderr="",
                    latency_ms=1.0,
                    sentinel_created=False,
                    reproduction_state="RED_STATE_PERSISTS",
                    assertion_result="SYNTHETIC_CONTRACT_PERSISTENCE",
                    parent_validated=False,
                    validation_notes="Synthetic test double: unverified post-patch persistence (parent_validated=False; unvalidated simulation turn)."
                )

    events_unver_red = []
    backend_unver_red = UnverifiedPersistentRedBackend(tmp_path)
    res_unver_red = await VerificationPipeline.run_pipeline(req_acc, on_event=events_unver_red.append, backend=backend_unver_red)
    assert res_unver_red.post_patch_result.reproduction_state == "RED_STATE_PERSISTS"
    assert res_unver_red.post_patch_result.parent_validated is False
    assert res_unver_red.post_patch_result.assertion_result == "SYNTHETIC_CONTRACT_PERSISTENCE"
    assert res_unver_red.final_behavioral_verdict == "UNEXPECTED_FAILURE"
    assert res_unver_red.verdict_record.terminal_state == "UNEXPECTED_FAILURE"
    assert "behavioral persistence lacked independent parent validation" in res_unver_red.verdict_record.reason
    assert res_unver_red.verdict_record.is_safe_claim is False

