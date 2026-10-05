import pickle


def unpack_cached_session(blob: bytes) -> dict:
    """Unsafe pickle deserialization vulnerable to arbitrary object instantiation."""
    data = pickle.loads(blob)
    if isinstance(data, dict):
        return data
    return {"session": data}
