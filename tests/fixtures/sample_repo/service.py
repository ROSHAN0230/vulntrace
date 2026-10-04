"""
Payment Configuration Microservice
Vulnerability: CVE-2020-14343 (PyYAML unsafe load)
"""
import yaml

def public_api_handler(user_payload: str) -> dict:
    """Public web API entrypoint."""
    return load_user_config(user_payload)

def load_user_config(raw_payload: str) -> dict:
    """Parses user-supplied YAML configuration using unsafe Loader."""
    return yaml.load(raw_payload, Loader=yaml.Loader)

def get_service_status() -> dict:
    return {"status": "ONLINE", "version": "2.4.1"}
