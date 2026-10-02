"""Dead Legacy Importer - Contains dangerous deserialization sink but 0 callers"""
import yaml

def dangerous_import(untrusted_blob: str):
    """Orphaned legacy function with zero incoming call edges."""
    return yaml.load(untrusted_blob, Loader=yaml.Loader)
