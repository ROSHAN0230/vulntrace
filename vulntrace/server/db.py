"""
VulnTrace SQLite Database Layer (Spec §4.12)
Manages persistent state for studio runs, SSE events, exported artifacts, and token ledger accounting.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_DIR = Path.home() / ".vulntrace"
DEFAULT_DB_PATH = DB_DIR / "vulntrace.db"


class StudioDatabase:
    """Manages SQLite tables: runs, events, artifacts, llm_calls."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or DEFAULT_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    created_at REAL,
                    status TEXT,
                    source_type TEXT,
                    source_ref TEXT,
                    cve_id TEXT,
                    verdict TEXT,
                    repo_dir TEXT,
                    plan TEXT,
                    bundle TEXT,
                    diff TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    event_type TEXT,
                    stage TEXT,
                    message TEXT,
                    payload TEXT,
                    created_at REAL
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    artifact_type TEXT,
                    filename TEXT,
                    content BLOB,
                    created_at REAL
                );

                CREATE TABLE IF NOT EXISTS llm_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    stage TEXT,
                    model TEXT,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    reasoning_tokens INTEGER,
                    latency_ms REAL,
                    created_at REAL
                );
            """)

    def create_run(
        self,
        run_id: str,
        source_type: str,
        source_ref: str,
        cve_id: Optional[str] = None,
        repo_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO runs (id, created_at, status, source_type, source_ref, cve_id, repo_dir)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, now, "INITIALIZED", source_type, source_ref, cve_id, repo_dir)
            )
        return {
            "id": run_id,
            "created_at": now,
            "status": "INITIALIZED",
            "source_type": source_type,
            "source_ref": source_ref,
            "cve_id": cve_id
        }

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row:
                return dict(row)
        return None

    def update_run_status(
        self,
        run_id: str,
        status: str,
        verdict: Optional[str] = None,
        bundle: Optional[str] = None,
        diff: Optional[str] = None
    ):
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE runs
                SET status = ?, verdict = COALESCE(?, verdict), bundle = COALESCE(?, bundle), diff = COALESCE(?, diff)
                WHERE id = ?
                """,
                (status, verdict, bundle, diff, run_id)
            )

    def set_run_plan(self, run_id: str, plan_json: str):
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE runs SET plan = ? WHERE id = ?",
                (plan_json, run_id)
            )

    def add_event(
        self,
        run_id: str,
        event_type: str,
        stage: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        payload_data = payload or {}
        payload_str = json.dumps(payload_data)
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (run_id, event_type, stage, message, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (run_id, event_type, stage, message, payload_str, now)
            )
            event_id = cur.lastrowid
        return {
            "id": event_id,
            "run_id": run_id,
            "event_type": event_type,
            "stage": stage,
            "message": message,
            "payload": payload_data,
            "created_at": now
        }

    def get_events(self, run_id: str, after_id: int = 0) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE run_id = ? AND id > ? ORDER BY id ASC",
                (run_id, after_id)
            ).fetchall()
            return [dict(r) for r in rows]

    def add_llm_call(
        self,
        run_id: str,
        stage: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        reasoning_tokens: int,
        latency_ms: float
    ):
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO llm_calls (run_id, stage, model, prompt_tokens, completion_tokens, reasoning_tokens, latency_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, stage, model, prompt_tokens, completion_tokens, reasoning_tokens, latency_ms, now)
            )

    record_llm_call = add_llm_call

    def get_llm_calls(self, run_id: str) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM llm_calls WHERE run_id = ? ORDER BY id ASC",
                (run_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def add_artifact(self, run_id: str, artifact_type: str, filename: str, content: bytes):
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (run_id, artifact_type, filename, content, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, artifact_type, filename, content, now)
            )

    def get_artifact(self, run_id: str, artifact_type: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE run_id = ? AND artifact_type = ? ORDER BY id DESC LIMIT 1",
                (run_id, artifact_type)
            ).fetchone()
            if row:
                return dict(row)
        return None
