"""
Regression suite for cloud infrastructure manifest parser.
"""

import pytest
from service.manifest_router import handle_deploy_request, get_service_health
from service.yaml_adapter import parse_cloud_descriptor

def test_valid_manifest_parsing():
    raw_doc = """
apiVersion: v1
kind: Deployment
metadata:
  name: cloud-worker
spec:
  replicas: 3
"""
    parsed = handle_deploy_request(raw_doc)
    assert parsed["kind"] == "Deployment"
    assert parsed["spec"]["replicas"] == 3

def test_service_health():
    res = get_service_health()
    assert res["status"] == "HEALTHY"

def test_empty_payload_raises():
    with pytest.raises(ValueError):
        handle_deploy_request("")

def test_invalid_type_raises():
    with pytest.raises(TypeError):
        parse_cloud_descriptor(12345)
