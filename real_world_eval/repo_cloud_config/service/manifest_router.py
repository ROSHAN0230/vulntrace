"""
Cloud Infrastructure Manifest Parser Service
Independent real-world microservice for parsing cloud deployment descriptors.
"""

from typing import Dict, Any
from service.yaml_adapter import parse_cloud_descriptor

def handle_deploy_request(payload: str) -> Dict[str, Any]:
    """Public handler for incoming deployment request payloads."""
    if not payload:
        raise ValueError("Payload cannot be empty")
    return parse_cloud_descriptor(payload)

def get_service_health() -> Dict[str, str]:
    """Healthcheck endpoint."""
    return {"status": "HEALTHY", "engine": "cloud_manifest_router"}
