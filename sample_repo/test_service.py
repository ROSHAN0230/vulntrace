import pytest
from service import public_api_handler, get_service_status

def test_valid_config():
    cfg = public_api_handler("app:\n  timeout: 30\n")
    assert cfg["app"]["timeout"] == 30

def test_service_status():
    st = get_service_status()
    assert st["status"] == "ONLINE"
