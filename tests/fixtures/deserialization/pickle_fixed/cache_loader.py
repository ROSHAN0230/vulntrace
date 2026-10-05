import io
import pickle

SAFE_CLASSES = {
    ("builtins", "dict"),
    ("builtins", "list"),
    ("builtins", "str"),
    ("builtins", "int"),
    ("builtins", "bool"),
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in SAFE_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Blocked untrusted class deserialization: {module}.{name}")


def unpack_cached_session(blob: bytes) -> dict:
    """Safe pickle deserialization with restricted class whitelist."""
    unpickler = RestrictedUnpickler(io.BytesIO(blob))
    data = unpickler.load()
    if isinstance(data, dict):
        return data
    return {"session": data}
