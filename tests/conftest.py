"""
Pytest configuration for VulnTrace test suite.
"""

import pytest
from vulntrace.core.backend import TrustedFixtureRegistry


@pytest.fixture(autouse=True)
def _register_conformance_fixture(request):
    """
    In conformance tests (test_backend_conformance.py) and envbuild pipeline tests (test_envbuild.py),
    register the test's temporary workspace in TrustedFixtureRegistry so Tier 0 LocalSubprocessBackend
    can execute the unit probes under application-controlled trust.
    """
    if "test_backend_conformance" in request.node.nodeid and "tmp_path" in request.fixturenames:
        tmp_path = request.getfixturevalue("tmp_path")
        with TrustedFixtureRegistry.temporary_trusted_fixture(tmp_path):
            yield
    elif "test_envbuild" in request.node.nodeid and "temp_repo_dir" in request.fixturenames:
        temp_repo_dir = request.getfixturevalue("temp_repo_dir")
        with TrustedFixtureRegistry.temporary_trusted_fixture(temp_repo_dir):
            yield
    else:
        yield
