import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import tempfile
import shutil

from vulntrace.server import app

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "providers" in data
        assert "osv_dev" in data["providers"]
        assert "nebius_token_factory" in data["providers"]
        assert data["providers"]["osv_dev"]["status"] == "ONLINE"

@pytest.mark.asyncio
async def test_cve_intel_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/intel/cve", json={"cve_id": "CVE-2020-14343", "query_tavily": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert data["cve_id"] == "CVE-2020-14343"

@pytest.mark.asyncio
async def test_ast_analyze_endpoint():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        (temp_dir / "mod.py").write_text("import yaml\ndef run(payload): return yaml.load(payload, Loader=yaml.Loader)\n", encoding="utf-8")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/ast/analyze", json={"repo_path": str(temp_dir)})
            assert resp.status_code == 200
            data = resp.json()
            assert data["reachable_vulnerabilities_count"] >= 1
            assert data["verdict"] == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"
            assert len(data["nodes"]) >= 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.mark.asyncio
async def test_evidence_export_endpoint():
    transport = ASGITransport(app=app)
    sample_repo_path = str(Path(__file__).resolve().parent / "fixtures" / "sample_repo")
    mock_run_data = {
        "cve_id": "CVE-2020-14343",
        "repo_path": sample_repo_path,
        "reachability_verdict": "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED",
        "harness": {
            "cve_id": "CVE-2020-14343",
            "target_file": "service.py",
            "function_name": "load_config",
            "harness_code": "import yaml\n",
            "sentinel_filename": "sentinel.txt",
            "latency_ms": 1.2
        },
        "pre_patch_result": {
            "exit_code": 0,
            "stdout": '{"sink_reached": true}',
            "stderr": "",
            "latency_ms": 12.0,
            "sentinel_created": True,
            "reproduction_state": "RED_STATE_REPRODUCED",
            "parent_validated": True,
            "sandbox_engine": "LOCAL_SUBPROCESS_FALLBACK"
        },
        "remediation": {
            "cve_id": "CVE-2020-14343",
            "target_file": "service.py",
            "engine": "NVIDIA_NEMOTRON_3_ULTRA",
            "diff": "--- a/service.py\n+++ b/service.py\n- yaml.load\n+ yaml.safe_load\n",
            "explanation": "SafeLoader replaces Loader",
            "latency_ms": 1200.0,
            "success": True,
            "validation_status": "ACCEPTED"
        },
        "post_patch_result": {
            "exit_code": 42,
            "stdout": '{"assertion": "GREEN_SECURITY_BLOCK_VERIFIED"}',
            "stderr": "",
            "latency_ms": 11.5,
            "sentinel_created": False,
            "reproduction_state": "GREEN_STATE_BLOCKED",
            "parent_validated": True,
            "sandbox_engine": "LOCAL_SUBPROCESS_FALLBACK"
        },
        "regression_tests": {
            "passed": True,
            "exit_code": 0,
            "stdout": "2 passed",
            "stderr": "",
            "test_count": 2,
            "latency_ms": 300.0
        },
        "final_behavioral_verdict": "GREEN_STATE_VERIFIED",
        "sandbox_engine": "LOCAL_SUBPROCESS_FALLBACK",
        "cloud_status": "PERMISSION_DENIED (HTTP 403)",
        "total_pipeline_ms": 1524.7
    }

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test JSON export
        resp_json = await client.post("/api/v1/evidence/export?format=json", json=mock_run_data)
        assert resp_json.status_code == 200
        bundle = resp_json.json()
        assert "schema_version" in bundle
        assert bundle["target"]["cve_id"] == "CVE-2020-14343"
        assert bundle["final_verdict"]["terminal_state"] == "GREEN_STATE_VERIFIED"
        assert bundle["verification_harness"]["sha256"] is not None
        assert bundle["remediation_evidence"]["sha256"] is not None

        # Test Markdown export
        resp_md = await client.post("/api/v1/evidence/export?format=markdown", json=mock_run_data)
        assert resp_md.status_code == 200
        data_md = resp_md.json()
        assert data_md["format"] == "markdown"
        assert "VulnTrace Verification Certificate" in data_md["content"]
        assert "GREEN_STATE_VERIFIED" in data_md["content"]

