"""
Acceptance Tests for VulnTrace OSV Client (Spec §4.7 / §4.8).
Verifies:
1. Deterministic offline resolution of CVE advisory records from cassettes with 100% blocked network.
2. Graceful 404 handling for nonexistent CVE records in offline mode.
3. Live network lookups isolated behind @pytest.mark.live_network.
"""

import socket
import pytest
from unittest.mock import patch

from vulntrace.intel.osv_client import OsvClient


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
async def test_osv_cve_lookup_offline_cassette(block_network):
    """Verifies that OSV queries resolve deterministically from offline cassette with 100% blocked network."""
    client = OsvClient()
    res = await client.fetch_cve("CVE-2020-14343")

    assert res.found is True
    assert res.cve_id == "CVE-2020-14343"
    assert len(res.affected_packages) > 0
    assert any("pyyaml" in (p.package_name or "").lower() or "yaml" in (p.ranges[0].repo or "").lower()
               for p in res.affected_packages if p.ranges and p.ranges[0].repo)


@pytest.mark.asyncio
async def test_osv_nonexistent_cve_offline_cassette(block_network):
    """Verifies that nonexistent CVE records return honest 404 with 100% blocked network."""
    client = OsvClient()
    res = await client.fetch_cve("CVE-9999-999999")

    assert res.found is False
    assert "404" in (res.error or "")


@pytest.mark.live_network
@pytest.mark.asyncio
async def test_osv_live_network_lookup():
    """Live network test: only executed when specifically targeted with -m live_network."""
    client = OsvClient()
    res = await client.fetch_cve("CVE-2020-14343")

    assert res.found is True
    assert res.cve_id == "CVE-2020-14343"
    assert len(res.affected_packages) > 0
