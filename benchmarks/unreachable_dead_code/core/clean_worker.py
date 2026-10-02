"""Clean Worker Module - completely decoupled from legacy parser"""
import json

def run_job(job_name: str) -> dict:
    """Executes clean worker task using safe built-in json handling."""
    config = json.loads('{"active": true, "worker": "default"}')
    config["job"] = job_name
    return config
