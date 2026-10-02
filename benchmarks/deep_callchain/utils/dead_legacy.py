"""Unused Legacy Utility Module"""
import yaml

def dead_legacy_helper(untrusted_blob: str):
    """Orphaned function never imported or invoked by gateway."""
    return yaml.load(untrusted_blob, Loader=yaml.Loader)
