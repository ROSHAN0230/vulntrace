"""Unit regression test suite for deep callchain."""
import pytest
from api.gateway import handle_request

def test_gateway_valid_config():
    payload = "server:\n  port: 8080\n  host: 0.0.0.0\nenabled: true\n"
    res = handle_request(payload)
    assert res["server"]["port"] == 8080
    assert res["enabled"] is True

def test_gateway_empty_check():
    with pytest.raises(ValueError):
        handle_request("")
