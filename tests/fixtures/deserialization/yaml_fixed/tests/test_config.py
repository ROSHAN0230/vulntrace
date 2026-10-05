from config_parser import load_app_settings


def test_load_valid_settings():
    res = load_app_settings("service: web\nport: 8080")
    assert res.get("service") == "web"
    assert res.get("port") == 8080


def test_nested_settings():
    res = load_app_settings("database:\n  host: localhost\n  port: 5432")
    assert isinstance(res.get("database"), dict)
    assert res["database"].get("port") == 5432
