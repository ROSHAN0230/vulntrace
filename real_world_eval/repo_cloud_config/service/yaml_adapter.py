"""
YAML adapter module for cloud configuration parsing.
"""

import yaml
from typing import Dict, Any

def parse_cloud_descriptor(raw_yaml: str) -> Dict[str, Any]:
    """
    Parses arbitrary cloud descriptor YAML.
    Vulnerable sink: uses unsafe Loader=yaml.Loader (CVE-2020-14343).
    """
    if not isinstance(raw_yaml, str):
        raise TypeError("raw_yaml must be string")
    
    # Insecure deserialization of untrusted cloud config
    result = yaml.load(raw_yaml, Loader=yaml.Loader)
    if not isinstance(result, dict):
        raise ValueError("Descriptor must evaluate to a dictionary")
    return result
