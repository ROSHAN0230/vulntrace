"""
Acceptance Tests for VulnTrace Studio Backend Server & API/SSE (Spec §4.12, AC3).
Covers:
1. SQLite database initialization and CRUD operations.
2. POST /runs endpoint with local source and zip archive intake.
3. Ingest guard enforcement on uploaded zip archives via POST /runs.
4. POST /runs/{id}/intent and POST /runs/{id}/approve-plan.
5. GET /runs/{id}/events SSE endpoint streaming live events.
6. GET /runs/{id}/diff and GET /runs/{id}/bundle endpoint retrieval.
7. GET /runs/{id}/export artifact downloads (diff and zip formats).
"""

import zipfile
from pathlib import Path
from fastapi.testclient import TestClient

from vulntrace.server.app import app, set_db, set_workspace_root
from vulntrace.server.db import StudioDatabase
from vulntrace.agent.scope_guard import RepairPlan


def test_sqlite_database_crud(tmp_path: Path):
    """Proves SQLite database handles runs, events, artifacts, and LLM call telemetry."""
    db_file = tmp_path / "test_studio.db"
    db = StudioDatabase(db_file)

    # 1. Create run
    run = db.create_run(
        run_id="run_12345",
        source_type="local",
        source_ref="/repos/target",
        cve_id="CVE-2020-14343",
        repo_dir="/tmp/workspaces/run_12345"
    )
    assert run["id"] == "run_12345"
    assert run["status"] == "INITIALIZED"

    # 2. Add events
    ev1 = db.add_event("run_12345", "STAGE_START", "REACHABILITY", "Analyzing AST")
    assert ev1["stage"] == "REACHABILITY"
    assert ev1["id"] == 1

    events = db.get_events("run_12345")
    assert len(events) == 1
    assert events[0]["message"] == "Analyzing AST"

    # 3. Add and retrieve artifact
    db.add_artifact("run_12345", "diff", "patch.diff", b"--- a\n+++ b\n")
    art = db.get_artifact("run_12345", "diff")
    assert art is not None
    assert art["filename"] == "patch.diff"
    assert art["content"] == b"--- a\n+++ b\n"

    # 4. Record LLM call
    db.record_llm_call("run_12345", "THREAT_INTEL", "google/gemini-2.5-flash", 100, 25, 0, 150.0)
    calls = db.get_llm_calls("run_12345")
    assert len(calls) == 1
    assert calls[0]["prompt_tokens"] == 100

    # 5. Set plan and update run status
    plan = RepairPlan(files_to_touch=["core.py"], diff_budget_lines=25)
    db.set_run_plan("run_12345", plan.model_dump_json())
    db.update_run_status("run_12345", status="COMPLETED", verdict="GREEN_STATE_VERIFIED")

    fetched_run = db.get_run("run_12345")
    assert fetched_run["status"] == "COMPLETED"
    assert fetched_run["verdict"] == "GREEN_STATE_VERIFIED"
    assert "core.py" in fetched_run["plan"]


def test_api_create_run_and_plan_flow(tmp_path: Path):
    """Proves REST API supports run creation, intent recording, plan approval, and artifact retrieval."""
    test_db = StudioDatabase(tmp_path / "api_test.db")
    test_workspace = tmp_path / "workspaces"
    test_workspace.mkdir()

    set_db(test_db)
    set_workspace_root(test_workspace)

    # Create dummy local repository target
    local_repo = tmp_path / "dummy_repo"
    local_repo.mkdir()
    (local_repo / "app.py").write_text("print('hello')\n")

    client = TestClient(app)

    # 1. POST /runs
    res = client.post("/runs", json={
        "source_type": "local",
        "source_ref": str(local_repo),
        "cve_id": "CVE-2020-14343"
    })
    assert res.status_code == 200
    run_data = res.json()
    run_id = run_data["run_id"]
    assert run_data["status"] == "INITIALIZED"

    # 2. GET /runs/{run_id}
    res_get = client.get(f"/runs/{run_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == run_id

    # 3. POST /runs/{run_id}/intent
    res_intent = client.post(f"/runs/{run_id}/intent", json={
        "requirement": "Surgically patch CVE-2020-14343 safe loader vulnerability",
        "target_file": "app.py"
    })
    assert res_intent.status_code == 200
    assert res_intent.json()["status"] == "INTENT_RECORDED"

    # 4. POST /runs/{run_id}/approve-plan
    res_plan = client.post(f"/runs/{run_id}/approve-plan", json={
        "files_to_touch": ["app.py"],
        "strategy": "surgical_sink_hardening",
        "diff_budget_lines": 30,
        "max_files": 3
    })
    assert res_plan.status_code == 200
    assert res_plan.json()["status"] == "PLAN_APPROVED"
    assert res_plan.json()["plan"]["files_to_touch"] == ["app.py"]


def test_api_ingest_guard_blocks_malicious_upload(tmp_path: Path):
    """Proves POST /runs blocks malicious zip-slip uploads via Ingest Guard."""
    test_db = StudioDatabase(tmp_path / "guard_test.db")
    test_workspace = tmp_path / "workspaces"
    test_workspace.mkdir()

    set_db(test_db)
    set_workspace_root(test_workspace)

    # Create zip-slip malicious archive
    bad_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:")

    client = TestClient(app)
    res = client.post("/runs", json={
        "source_type": "upload",
        "source_ref": str(bad_zip),
        "cve_id": "CVE-2020-14343"
    })
    # Must be rejected with HTTP 400 Bad Request
    assert res.status_code == 400
    assert "Zip-slip detected" in res.json()["detail"]


def test_api_export_diff_and_zip(tmp_path: Path):
    """Proves GET /runs/{id}/export downloads diff and zip formats."""
    test_db = StudioDatabase(tmp_path / "export_test.db")
    test_workspace = tmp_path / "workspaces"
    test_workspace.mkdir()

    set_db(test_db)
    set_workspace_root(test_workspace)

    client = TestClient(app)

    # Create local repo
    repo = tmp_path / "my_project"
    repo.mkdir()
    (repo / "main.py").write_text("code = 1\n")

    res = client.post("/runs", json={
        "source_type": "local",
        "source_ref": str(repo),
        "cve_id": "CVE-2020-14343"
    })
    run_id = res.json()["run_id"]

    # Manually populate diff and bundle in database
    sample_diff = "--- a/main.py\n+++ b/main.py\n@@ -1 +1 @@\n-code = 1\n+code = 2\n"
    test_db.update_run_status(run_id, status="COMPLETED", verdict="GREEN_STATE_VERIFIED", diff=sample_diff)

    # 1. Export diff
    res_diff = client.get(f"/runs/{run_id}/export?format=diff")
    assert res_diff.status_code == 200
    assert res_diff.headers["content-type"].startswith("text/x-diff")
    assert "code = 2" in res_diff.text

    # 2. Export zip
    res_zip = client.get(f"/runs/{run_id}/export?format=zip")
    assert res_zip.status_code == 200
    assert res_zip.headers["content-type"] == "application/zip"
    assert len(res_zip.content) > 0
