import yaml


def load_app_settings(blob: str) -> dict:
    """Safe YAML load using yaml.safe_load."""
    data = yaml.safe_load(blob)
    if isinstance(data, dict):
        return data
    return {"settings": data}
