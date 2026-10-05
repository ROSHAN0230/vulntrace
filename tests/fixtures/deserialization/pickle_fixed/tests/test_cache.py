import pickle
from cache_loader import unpack_cached_session


def test_load_valid_cache():
    raw = pickle.dumps({"user": "alice", "role": "admin"})
    res = unpack_cached_session(raw)
    assert res.get("user") == "alice"
    assert res.get("role") == "admin"


def test_load_nested_cache():
    raw = pickle.dumps({"service": "auth", "nested": {"workers": 4}})
    res = unpack_cached_session(raw)
    assert res.get("service") == "auth"
    assert res["nested"].get("workers") == 4
