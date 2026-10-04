"""
OSV.dev REST Client for VulnTrace
Queries open source vulnerability database for official CVE/GHSA advisories,
affected versions, and git commit fix ranges.
Zero API key required; open public API.
"""

import time
import httpx
from typing import List
from vulntrace.models import (
    CveQueryResponse,
    AffectedPackage,
    AdvisoryCommitRange
)

class OsvClient:
    BASE_URL = "https://api.osv.dev/v1/vulns"

    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout

    async def fetch_cve(self, cve_id: str) -> CveQueryResponse:
        cve_id = cve_id.strip().upper()
        url = f"{self.BASE_URL}/{cve_id}"
        t0 = time.perf_counter()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                dt = (time.perf_counter() - t0) * 1000.0
                
                if resp.status_code == 404:
                    return CveQueryResponse(
                        cve_id=cve_id,
                        found=False,
                        aliases=[],
                        summary="Advisory not found in OSV database.",
                        details=f"No record returned for identifier {cve_id}.",
                        affected_packages=[],
                        cvss_score=None,
                        pocs=[],
                        source_url=url,
                        latency_ms=round(dt, 2),
                        error=f"HTTP 404: {cve_id} not indexed in OSV.dev"
                    )
                
                if resp.status_code != 200:
                    return CveQueryResponse(
                        cve_id=cve_id,
                        found=False,
                        aliases=[],
                        summary="Failed to fetch advisory.",
                        details=resp.text,
                        affected_packages=[],
                        cvss_score=None,
                        pocs=[],
                        source_url=url,
                        latency_ms=round(dt, 2),
                        error=f"HTTP {resp.status_code}: {resp.text[:200]}"
                    )
                    
                data = resp.json()
                aliases = data.get("aliases", [])
                summary = data.get("summary") or (data.get("details", "")[:160] + "...")
                details = data.get("details", "")
                
                # Extract affected packages
                affected_list: List[AffectedPackage] = []
                for item in data.get("affected", []):
                    pkg_info = item.get("package", {})
                    pkg_name = pkg_info.get("name", "unknown")
                    ecosystem = pkg_info.get("ecosystem", "PyPI")
                    
                    ranges_list: List[AdvisoryCommitRange] = []
                    for r in item.get("ranges", []):
                        r_type = r.get("type", "GIT")
                        repo_url = r.get("repo")
                        intro, fixed, last_aff = None, None, None
                        for ev in r.get("events", []):
                            if "introduced" in ev:
                                intro = ev["introduced"]
                            if "fixed" in ev:
                                fixed = ev["fixed"]
                            if "last_affected" in ev:
                                last_aff = ev["last_affected"]
                                
                        ranges_list.append(AdvisoryCommitRange(
                            type=r_type,
                            repo=repo_url,
                            introduced=intro,
                            fixed=fixed,
                            last_affected=last_aff
                        ))
                        
                    db_specific = item.get("database_specific", {})
                    cpe = db_specific.get("cpe")
                    
                    affected_list.append(AffectedPackage(
                        package_name=pkg_name,
                        ecosystem=ecosystem,
                        ranges=ranges_list,
                        database_cpe=cpe
                    ))
                    
                # Extract CVSS score if present in severity
                cvss_score = None
                for sev in data.get("severity", []):
                    score_str = sev.get("score")
                    if score_str and isinstance(score_str, (int, float)):
                        cvss_score = float(score_str)
                        break

                return CveQueryResponse(
                    cve_id=data.get("id", cve_id),
                    found=True,
                    aliases=aliases,
                    summary=summary,
                    details=details,
                    affected_packages=affected_list,
                    cvss_score=cvss_score,
                    pocs=[],
                    source_url=url,
                    latency_ms=round(dt, 2),
                    error=None
                )
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000.0
            return CveQueryResponse(
                cve_id=cve_id,
                found=False,
                aliases=[],
                summary="Connection exception querying OSV API.",
                details=str(e),
                affected_packages=[],
                cvss_score=None,
                pocs=[],
                source_url=url,
                latency_ms=round(dt, 2),
                error=f"{type(e).__name__}: {str(e)}"
            )
