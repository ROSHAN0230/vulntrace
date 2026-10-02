"""API Gateway Entrypoint"""
from controllers.config_controller import process_incoming_config

def handle_request(raw_payload: str) -> dict:
    """Gateway handler routing config payloads."""
    return process_incoming_config(raw_payload)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(handle_request(sys.argv[1]))
