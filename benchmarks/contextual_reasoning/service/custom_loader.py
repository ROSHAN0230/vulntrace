import yaml
import os

class AppSafeLoader(yaml.SafeLoader):
    """Secure application loader supporting internal configuration tags."""
    pass

def _env_tag_constructor(loader, node):
    val = loader.construct_scalar(node)
    return os.environ.get(val, f"DEFAULT_{val}")

AppSafeLoader.add_constructor("!env_var", _env_tag_constructor)
yaml.Loader.add_constructor("!env_var", _env_tag_constructor)

def parse_app_config(raw_yaml: str) -> dict:
    """
    Parses application configuration.
    Must maintain support for !env_var custom tag.
    Vulnerable sink: currently uses unsafe yaml.load with default Loader.
    """
    # Vulnerable sink (CVE-2020-14343)
    data = yaml.load(raw_yaml, Loader=yaml.Loader)
    if isinstance(data, dict):
        return data
    return {"config": data}
