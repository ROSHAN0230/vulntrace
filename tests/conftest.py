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
    mod_name = getattr(request.module, "__name__", "")
    if mod_name in ("test_backend_conformance", "tests.test_backend_conformance") and "tmp_path" in request.fixturenames:
        tmp_path = request.getfixturevalue("tmp_path")
        with TrustedFixtureRegistry.temporary_trusted_fixture(tmp_path):
            yield
    elif mod_name in ("test_envbuild", "tests.test_envbuild") and "temp_repo_dir" in request.fixturenames:
        temp_repo_dir = request.getfixturevalue("temp_repo_dir")
        with TrustedFixtureRegistry.temporary_trusted_fixture(temp_repo_dir):
            yield
    else:
        yield
