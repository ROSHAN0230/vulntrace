"""
Unreferenced legacy utilities module (not invoked by public_api_handler).
"""
import yaml

def legacy_backup_loader(raw_data: str):
    """Dead code function containing vulnerable yaml.full_load."""
    return yaml.full_load(raw_data)
