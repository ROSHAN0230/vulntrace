"""
VulnTrace Threat Intelligence & Tavily Integration Test Suite (Spec §4.7 / §4.8)
Verifies:
1. Canonical ThreatIntel normalization: query, timestamp, source URLs, response SHA-256 hash.
2. Resilient degradation: bad API key / network failure produces status="degraded" without crashing.
3. Demonstrable behavioral change: ThreatIntel materially selects candidate symbols and sink oracles.
4. Strict CVE relevance filtering: cross-CVE pollution is filtered out.
"""

import pytest
import time
from vulntrace.intel.tavily_client import TavilyClient
from vulntrace.models import ThreatIntel, PocFinding
from vulntrace.sinks import SinkOracleRegistry, YamlDeserializationOracle, PickleDeserializationOracle


@pytest.mark.asyncio
async def test_threat_intel_canonical_normalization():
    """Verifies that Tavily responses are normalized into canonical ThreatIntel with deterministic hash."""
    client = TavilyClient()
    # Query using benchmark CVE (replays from seeded cassette CVE-2020-14343_default.json)
    intel = await client.query_threat_intel("CVE-2020-14343")

    assert isinstance(intel, ThreatIntel)
    assert intel.cve_id == "CVE-2020-14343"
    assert "CVE-2020-14343" in intel.query
    assert intel.timestamp > 0
    assert len(intel.source_urls) > 0
    assert len(intel.response_hash) == 64  # SHA-256 hex length
    assert intel.status in ["ok", "fresh", "cached"]
    assert len(intel.findings) > 0

    # Verify extracted symbols and sink classes
    assert "yaml.load" in intel.affected_symbols or "yaml.full_load" in intel.affected_symbols
    assert "deserialization" in intel.sink_classes
    assert any("safe_load" in p for p in intel.safe_patterns)


@pytest.mark.asyncio
async def test_threat_intel_resilient_degradation():
    """Verifies that Tavily errors or bad keys produce status='degraded' without raising exceptions."""
    # Invalid API key with live forced
    broken_client = TavilyClient(api_key="tvly-invalid-key-for-test-99999")
    
    # Simulate a network/API failure by querying an uncached CVE with invalid credentials
    intel = await broken_client.query_threat_intel("CVE-0000-0000-NONEXISTENT")

    assert isinstance(intel, ThreatIntel)
    assert intel.cve_id == "CVE-0000-0000-NONEXISTENT"
    assert intel.status == "degraded"
    assert intel.error is not None
    assert isinstance(intel.findings, list)
    assert isinstance(intel.source_urls, list)


def test_threat_intel_materially_changes_behavior():
    """
    Proves that ThreatIntel demonstrably changes system behavior:
    Different threat intelligence selects different candidate symbols and sink oracles.
    """
    # 1. PyYAML Deserialization Intel
    yaml_intel = ThreatIntel(
        cve_id="CVE-2020-14343",
        query='"CVE-2020-14343" PyYAML yaml.load arbitrary code execution',
        timestamp=time.time(),
        source_urls=["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
        response_hash="a" * 64,
        findings=[
            PocFinding(
                title="PyYAML arbitrary code execution in yaml.load",
                url="https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
                snippet="In PyYAML before 5.4, yaml.load allows arbitrary object instantiation.",
                source="Tavily",
                relevant_to_cve=True
            )
        ],
        affected_symbols=["yaml.load", "yaml.full_load"],
        sink_classes=["deserialization"],
        safe_patterns=["yaml.safe_load"],
        status="fresh"
    )

    yaml_candidates = SinkOracleRegistry.get_candidate_symbols_for_intel(yaml_intel)
    yaml_oracle = SinkOracleRegistry.get_oracle_for_intel(yaml_intel)

    assert "yaml.load" in yaml_candidates
    assert isinstance(yaml_oracle, YamlDeserializationOracle)
    assert not isinstance(yaml_oracle, PickleDeserializationOracle)

    # 2. Pickle Deserialization Intel
    pickle_intel = ThreatIntel(
        cve_id="CVE-2022-9999",
        query='"CVE-2022-9999" Python pickle.loads arbitrary code execution',
        timestamp=time.time(),
        source_urls=["https://nvd.nist.gov/vuln/detail/CVE-2022-9999"],
        response_hash="b" * 64,
        findings=[
            PocFinding(
                title="Python pickle.loads unsafe deserialization",
                url="https://nvd.nist.gov/vuln/detail/CVE-2022-9999",
                snippet="Untrusted data passed to pickle.loads allows arbitrary command execution.",
                source="Tavily",
                relevant_to_cve=True
            )
        ],
        affected_symbols=["pickle.loads", "pickle.load"],
        sink_classes=["deserialization"],
        safe_patterns=[],
        status="fresh"
    )

    pickle_candidates = SinkOracleRegistry.get_candidate_symbols_for_intel(pickle_intel)
    pickle_oracle = SinkOracleRegistry.get_oracle_for_intel(pickle_intel)

    assert "pickle.loads" in pickle_candidates
    assert isinstance(pickle_oracle, PickleDeserializationOracle)

    # Verify that the two intels yield DIFFERENT symbols
    assert yaml_candidates != pickle_candidates

    # 3. Degraded Mode Intel
    degraded_intel = ThreatIntel(
        cve_id="CVE-UNKNOWN",
        query="unknown",
        timestamp=time.time(),
        response_hash="none",
        status="degraded",
        error="Network down"
    )
    fallback_candidates = SinkOracleRegistry.get_candidate_symbols_for_intel(degraded_intel)
    assert len(fallback_candidates) >= 5
    assert "yaml.load" in fallback_candidates
    assert "pickle.loads" in fallback_candidates


def test_tavily_relevance_filter():
    """Verifies that Tavily search relevance filter eliminates cross-CVE contamination."""
    # Matches target CVE
    assert TavilyClient.is_result_relevant(
        "CVE-2020-14343",
        "Advisory for CVE-2020-14343 in PyYAML",
        "https://example.com/advisory",
        "Arbitrary code execution discovered."
    ) is True

    # Variant formats (lowercase, spaces)
    assert TavilyClient.is_result_relevant(
        "CVE-2020-14343",
        "Security Fix",
        "https://example.com",
        "Fixes cve-2020-14343 in parser"
    ) is True

    # Mismatched CVE (cross-CVE false positive)
    assert TavilyClient.is_result_relevant(
        "CVE-2020-14343",
        "Vulnerability in Apache Log4j (CVE-2021-44228)",
        "https://example.com/log4j",
        "Remote code execution in JNDI lookup."
    ) is False
