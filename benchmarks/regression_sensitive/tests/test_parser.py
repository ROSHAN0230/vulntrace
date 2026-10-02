"""Regression test suite guarding essential parser semantics."""
import pytest
from service.parser import parse_manifest

def test_valid_manifest_dict():
    sample = "service_name: payment_processor\nreplicas: 4\ncanary: false\n"
    out = parse_manifest(sample)
    assert out["service_name"] == "payment_processor"
    assert out["replicas"] == 4
    assert out["canary"] is False

def test_nested_manifest_config():
    sample = "database:\n  pool_size: 20\n  ssl: true\n"
    out = parse_manifest(sample)
    assert out["database"]["pool_size"] == 20
    assert out["database"]["ssl"] is True

def test_invalid_types():
    with pytest.raises(ValueError):
        parse_manifest("just a scalar string")
