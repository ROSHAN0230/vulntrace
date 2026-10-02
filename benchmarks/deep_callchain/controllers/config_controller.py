"""Config Controller Layer"""
from services.yaml_parser import parse_custom_config

def process_incoming_config(config_str: str) -> dict:
    """Validates envelope and delegates to parser service."""
    if not config_str or not isinstance(config_str, str):
        raise ValueError("Empty or invalid config payload")
    return parse_custom_config(config_str)
