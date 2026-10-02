"""Tests for guarded config loader"""
import pytest
from service.loader import load_guarded_config

def test_guarded_loader_valid():
    sample = "app: billing\nversion: 2\n"
    res = load_guarded_config(sample)
    assert res["app"] == "billing"
    assert res["version"] == 2

def test_guard_rejects_tags():
    with pytest.raises(ValueError, match="forbidden by pre-filter guard"):
        load_guarded_config("malicious: !!python/object/apply:os.system []")
