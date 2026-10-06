"""
LLM Cassette Storage & Replay Layer (Spec §4.7)
Provides deterministic record and replay for Nebius Token Factory inference.
Guarantees zero-network execution during pytest runs and GitHub Actions CI.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List

CASSETTE_DIR = Path(__file__).resolve().parent / "cassettes"


class LLMCassetteManager:
    """Manages recording and replaying LLM responses."""

    @classmethod
    def is_live_enabled(cls) -> bool:
        """Checks if live internet calls are allowed via LIVE_LLM environment variable."""
        return os.environ.get("LIVE_LLM", "0") == "1"

    @classmethod
    def compute_fingerprint(cls, model: str, messages: List[Dict[str, str]]) -> str:
        """Computes deterministic hash from model ID and message contents."""
        content_blob = f"{model.strip()}::" + "::".join(
            f"{m.get('role', '')}:{m.get('content', '')}" for m in messages
        )
        return hashlib.sha256(content_blob.encode("utf-8")).hexdigest()[:20]

    @classmethod
    def load_cassette(cls, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Loads a recorded response for the given request fingerprint."""
        path = CASSETTE_DIR / f"{fingerprint}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    @classmethod
    def find_cassette_by_keyword(cls, keyword: str) -> Optional[Dict[str, Any]]:
        """Finds any cassette matching a keyword in its file name or metadata."""
        if not CASSETTE_DIR.exists():
            return None
        for f in CASSETTE_DIR.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if keyword.lower() in str(data).lower():
                    return data
            except Exception:
                pass
        return None

    @classmethod
    def save_cassette(cls, fingerprint: str, response_data: Dict[str, Any]) -> None:
        """Saves a response to disk for offline replay."""
        CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
        path = CASSETTE_DIR / f"{fingerprint}.json"
        path.write_text(json.dumps(response_data, indent=2), encoding="utf-8")
