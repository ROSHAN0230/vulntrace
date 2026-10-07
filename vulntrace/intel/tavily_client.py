"""
Tavily Search Client for VulnTrace (Spec §4.8)
Queries Tavily Search API for real-time CVE advisories, GitHub exploit PoCs,
and security writeups. Normalizes output into canonical ThreatIntel and supports
deterministic cassette recording and offline replay.
"""

import time
import httpx
from typing import List, Optional, Dict, Any
from vulntrace.config import settings
from vulntrace.models import PocFinding, TavilySearchReport, ThreatIntel
from vulntrace.intel.cassette import IntelCassetteManager
from vulntrace.intel.threat_intel import ThreatIntelNormalizer


class TavilyClient:
    ENDPOINT = "https://api.tavily.com/search"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 12.0):
        self.api_key = api_key or settings.tavily_api_key
        self.timeout = timeout

    @classmethod
    def is_result_relevant(cls, cve_id: str, title: str, url: str, content: str) -> bool:
        """
        Validates whether a raw search result from Tavily actually references the requested CVE.
        Prevents cross-CVE contamination and generic security writeup false positives.
        """
        target = cve_id.lower().strip()
        corpus = f"{title} {url} {content}".lower()

        # 1. Direct CVE ID match (e.g., "cve-2020-14343")
        if target in corpus:
            return True

        # 2. Check normalized space/underscore variants
        target_space = target.replace("-", " ")
        if target_space in corpus:
            return True

        target_underscore = target.replace("-", "_")
        if target_underscore in corpus:
            return True

        return False

    async def search_with_relevance(self, cve_id: str, max_results: int = 6) -> TavilySearchReport:
        """
        Executes search with relevance validation.
        Checks cassette store when live calls are disabled (default in CI/testing).
        """
        query_str = f'"{cve_id}" vulnerable function fix commit exploit'

        # 1. Check offline cassette if live calls are not enabled or no API key
        if not IntelCassetteManager.is_live_enabled() or not self.api_key:
            cassette_data = IntelCassetteManager.load_cassette(cve_id, query_str)
            if cassette_data:
                raw_items = cassette_data.get("results", [])
                retained_findings: List[PocFinding] = []
                rejection_reasons: List[str] = []

                for item in raw_items:
                    title = item.get("title", "Advisory Reference")
                    url = item.get("url", "")
                    content = item.get("content", "")
                    snippet = content[:280] + "..." if len(content) > 280 else content

                    if self.is_result_relevant(cve_id, title, url, content):
                        retained_findings.append(PocFinding(
                            title=title,
                            url=url,
                            snippet=snippet,
                            source="Tavily Intelligence API (Cassette Replay)",
                            relevant_to_cve=True
                        ))
                    else:
                        rejection_reasons.append(f"Excluded: '{title}' ({url}) does not reference target {cve_id}")

                return TavilySearchReport(
                    cve_id=cve_id,
                    query=query_str,
                    status_code=200,
                    latency_ms=1.5,
                    raw_results_count=len(raw_items),
                    retained_results_count=len(retained_findings),
                    filtered_out_count=len(raw_items) - len(retained_findings),
                    findings=retained_findings,
                    rejection_reasons=rejection_reasons
                )

        if not self.api_key:
            return TavilySearchReport(
                cve_id=cve_id,
                query=query_str,
                status_code=401,
                latency_ms=0.0,
                raw_results_count=0,
                retained_results_count=0,
                filtered_out_count=0,
                findings=[],
                rejection_reasons=["Tavily API key not configured."]
            )

        payload = {
            "api_key": self.api_key,
            "query": query_str,
            "search_depth": "basic",
            "max_results": max_results,
            "include_answer": False
        }

        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.ENDPOINT, json=payload)
                dt = round((time.perf_counter() - t0) * 1000.0, 2)

                if resp.status_code != 200:
                    return TavilySearchReport(
                        cve_id=cve_id,
                        query=query_str,
                        status_code=resp.status_code,
                        latency_ms=dt,
                        raw_results_count=0,
                        retained_results_count=0,
                        filtered_out_count=0,
                        findings=[],
                        rejection_reasons=[f"HTTP {resp.status_code} error from Tavily API."]
                    )

                data = resp.json()
                raw_items = data.get("results", [])
                retained_findings: List[PocFinding] = []
                rejection_reasons: List[str] = []

                for item in raw_items:
                    title = item.get("title", "Advisory Reference")
                    url = item.get("url", "")
                    content = item.get("content", "")
                    snippet = content[:280] + "..." if len(content) > 280 else content

                    if self.is_result_relevant(cve_id, title, url, content):
                        retained_findings.append(PocFinding(
                            title=title,
                            url=url,
                            snippet=snippet,
                            source="Tavily Intelligence API (Verified Relevant)",
                            relevant_to_cve=True
                        ))
                    else:
                        rejection_reasons.append(f"Excluded: '{title}' ({url}) does not reference target {cve_id}")

                # Save cassette for offline replay in CI when explicitly requested
                if IntelCassetteManager.is_recording_enabled():
                    IntelCassetteManager.save_cassette(cve_id, query_str, data)

                return TavilySearchReport(
                    cve_id=cve_id,
                    query=query_str,
                    status_code=200,
                    latency_ms=dt,
                    raw_results_count=len(raw_items),
                    retained_results_count=len(retained_findings),
                    filtered_out_count=len(raw_items) - len(retained_findings),
                    findings=retained_findings,
                    rejection_reasons=rejection_reasons
                )
        except Exception as e:
            dt = round((time.perf_counter() - t0) * 1000.0, 2)
            return TavilySearchReport(
                cve_id=cve_id,
                query=query_str,
                status_code=500,
                latency_ms=dt,
                raw_results_count=0,
                retained_results_count=0,
                filtered_out_count=0,
                findings=[],
                rejection_reasons=[f"Exception during Tavily query: {e}"]
            )

    async def query_threat_intel(self, cve_id: str, max_results: int = 6) -> ThreatIntel:
        """
        Executes runtime Tavily query and normalizes into canonical ThreatIntel.
        Handles degradation without raising exceptions.
        """
        query_str = f'"{cve_id}" vulnerable function fix commit exploit'
        report = await self.search_with_relevance(cve_id, max_results=max_results)

        # Retrieve raw items if cassette or report generated
        raw_items: List[Dict[str, Any]] = []
        cassette_data = IntelCassetteManager.load_cassette(cve_id, query_str)
        if cassette_data:
            raw_items = cassette_data.get("results", [])

        error_msg = None
        if report.status_code != 200:
            error_msg = report.rejection_reasons[0] if report.rejection_reasons else f"HTTP {report.status_code}"

        return ThreatIntelNormalizer.build_threat_intel(
            cve_id=cve_id,
            query=query_str,
            raw_items=raw_items,
            retained_findings=report.findings,
            status_code=report.status_code,
            rejection_reasons=report.rejection_reasons,
            error_msg=error_msg,
            latency_ms=report.latency_ms
        )

    async def search_cve_pocs(self, cve_id: str, max_results: int = 6) -> List[PocFinding]:
        """Convenience method returning only CVE-validated findings."""
        report = await self.search_with_relevance(cve_id, max_results=max_results)
        return report.findings
