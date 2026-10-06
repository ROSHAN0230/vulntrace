from service.custom_loader import parse_app_config

def test_standard_yaml():
    res = parse_app_config("service: auth\nport: 9000")
    assert res.get("service") == "auth"
    assert res.get("port") == 9000

def test_custom_env_tag():
    # Requires custom tag handler !env_var to work
    # Standard yaml.safe_load fails on custom tags unless the custom SafeLoader is passed!
    res = parse_app_config("database_host: !env_var DB_HOST")
    assert "database_host" in res
    assert res["database_host"].startswith("DEFAULT_") or len(res["database_host"]) > 0

def test_nested_dictionary():
    res = parse_app_config("server:\n  workers: 4\n  debug: false")
    assert res["server"]["workers"] == 4
    assert res["server"]["debug"] is False
