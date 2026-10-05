import yaml


def load_app_settings(blob: str) -> dict:
    """Unsafe YAML load vulnerable to CVE-2020-14343 object instantiation."""
    data = yaml.load(blob, Loader=yaml.Loader)
    if isinstance(data, dict):
        return data
    return {"settings": data}
