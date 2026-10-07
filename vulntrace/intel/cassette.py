"""
VulnTrace Intel Cassette Storage & Replay Layer (Spec §4.7 / §4.8)
Provides deterministic record/replay of Tavily threat intelligence search queries.
Enables zero-network test execution and CI reproducibility.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any

CASSETTE_DIR = Path(__file__).resolve().parent / "cassettes"

class IntelCassetteManager:
    """Manages recording and replaying Tavily threat intelligence responses."""

    @classmethod
    def is_live_enabled(cls) -> bool:
        """Checks if live internet calls are allowed via LIVE_LLM or LIVE_INTEL environment variables."""
        return os.environ.get("LIVE_LLM", "0") == "1" or os.environ.get("LIVE_INTEL", "0") == "1"

    @classmethod
    def is_recording_enabled(cls) -> bool:
        """Checks if recording new cassettes is explicitly enabled via RECORD_CASSETTES."""
        return os.environ.get("RECORD_CASSETTES", "0") == "1"

    @classmethod
    def _compute_key(cls, cve_id: str, query: str) -> str:
        norm = f"{cve_id.strip().upper()}:{query.strip().lower()}"
        return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def get_cassette_path(cls, cve_id: str, query: str) -> Path:
        key = cls._compute_key(cve_id, query)
        safe_cve = cve_id.strip().upper().replace("/", "_")
        return CASSETTE_DIR / f"{safe_cve}_{key}.json"

    @classmethod
    def load_cassette(cls, cve_id: str, query: str) -> Optional[Dict[str, Any]]:
        """Loads a recorded Tavily response if available."""
        path = cls.get_cassette_path(cve_id, query)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        # Fallback to any cassette matching this CVE
        safe_cve = cve_id.strip().upper().replace("/", "_")
        if CASSETTE_DIR.exists():
            for f in CASSETTE_DIR.glob(f"{safe_cve}_*.json"):
                try:
                    return json.loads(f.read_text(encoding="utf-8"))
                except Exception:
                    pass
        return None

    @classmethod
    def save_cassette(cls, cve_id: str, query: str, data: Dict[str, Any]) -> None:
        """Saves a raw Tavily response to disk for offline replay."""
        CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
        path = cls.get_cassette_path(cve_id, query)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
