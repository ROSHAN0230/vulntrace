"""Guarded Configuration Loader"""
import yaml

def load_guarded_config(raw_yaml_str: str) -> dict:
    """
    Configuration loader protected by pre-validation input filtering guard.
    Blocks exploit probes (!! tags) before reaching yaml.load.
    """
    if not raw_yaml_str or not isinstance(raw_yaml_str, str):
        raise ValueError("Empty or invalid config string")

    # Pre-validation guard: Rejects untrusted python object tags before sink is reached
    if "!!" in raw_yaml_str or "python/object" in raw_yaml_str:
        raise ValueError("Security violation: object tags forbidden by pre-filter guard")

    # Vulnerable sink downstream of the guard
    parsed = yaml.load(raw_yaml_str, Loader=yaml.Loader)
    if isinstance(parsed, dict):
        return parsed
    return {"parsed": parsed}
