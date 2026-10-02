"""Regression Sensitive Config Parser Service"""
import yaml

def parse_manifest(raw_text: str) -> dict:
    """
    Parses service manifest.
    Must return a Python dictionary preserving integer and boolean types.
    """
    if not raw_text or not isinstance(raw_text, str):
        raise ValueError("Invalid manifest text")
    # Vulnerable sink (CVE-2020-14343)
    parsed = yaml.load(raw_text, Loader=yaml.Loader)
    if not isinstance(parsed, dict):
        raise ValueError("Manifest must evaluate to a dictionary")
    return parsed
