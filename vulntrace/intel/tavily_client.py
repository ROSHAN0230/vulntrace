"""
Tavily Search Client for VulnTrace
Queries Tavily Search API for real-time CVE advisories, GitHub exploit PoCs,
and security writeups.
"""

import time
import httpx
from typing import List, Optional
from vulntrace.config import settings
from vulntrace.models import PocFinding

class TavilyClient:
    ENDPOINT = "https://api.tavily.com/search"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 12.0):
        self.api_key = api_key or settings.tavily_api_key
        self.timeout = timeout

    async def search_cve_pocs(self, cve_id: str, max_results: int = 4) -> List[PocFinding]:
        if not self.api_key:
            return []

        payload = {
            "api_key": self.api_key,
            "query": f"{cve_id} exploit proof of concept advisory GitHub writeup",
            "search_depth": "basic",
            "max_results": max_results,
            "include_answer": False
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.ENDPOINT, json=payload)
                if resp.status_code != 200:
                    return []
                    
                data = resp.json()
                findings: List[PocFinding] = []
                for item in data.get("results", []):
                    title = item.get("title", "Advisory Reference")
                    url = item.get("url", "")
                    snippet = item.get("content", "")[:280] + "..." if len(item.get("content", "")) > 280 else item.get("content", "")
                    findings.append(PocFinding(
                        title=title,
                        url=url,
                        snippet=snippet,
                        source="Tavily Intelligence API"
                    ))
                return findings
        except Exception:
            return []
