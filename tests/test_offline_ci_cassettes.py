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
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import patch

import httpx
import pytest

from vulntrace.intel.tavily_client import TavilyClient
from vulntrace.llm.client import TokenFactoryClient
from vulntrace.llm.cassette import LLMCassetteManager
from vulntrace.llm.tier import LLMModelTier
from vulntrace.llm.ledger import TokenLedger
from vulntrace.models import (
    TriageAnalysisOutput,
    PatchPlanOutput,
    VerificationPipelineRequest
)
from vulntrace.sandbox.pipeline import VerificationPipeline
from vulntrace.config import settings

_RealAsyncClient = httpx.AsyncClient


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

