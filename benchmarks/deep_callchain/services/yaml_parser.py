"""YAML Parser Service"""
import yaml

def parse_custom_config(raw_yaml: str) -> dict:
    """Parses arbitrary YAML configuration payload."""
    # Vulnerable deserialization sink (CVE-2020-14343)
    data = yaml.load(raw_yaml, Loader=yaml.Loader)
    if isinstance(data, dict):
        return data
    return {"parsed": data}
