import pytest
from vulntrace.intel.osv_client import OsvClient

@pytest.mark.asyncio
async def test_osv_live_cve_lookup():
    client = OsvClient()
    res = await client.fetch_cve("CVE-2020-14343")
    assert res.found is True
    assert res.cve_id == "CVE-2020-14343"
    assert len(res.affected_packages) > 0
    assert any("seldonio" in (p.ranges[0].repo or "") or "yaml" in (p.ranges[0].repo or "") for p in res.affected_packages if p.ranges and p.ranges[0].repo)

@pytest.mark.asyncio
async def test_osv_nonexistent_cve():
    client = OsvClient()
    res = await client.fetch_cve("CVE-9999-999999")
    assert res.found is False
    assert "404" in (res.error or "")
