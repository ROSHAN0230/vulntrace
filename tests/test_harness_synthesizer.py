import tempfile
import shutil
from pathlib import Path
from vulntrace.agent.harness_synthesizer import HarnessSynthesizer
from vulntrace.models import HarnessGenerateRequest

def test_harness_synthesizer_pyyaml_cve():
    temp_dir = Path(tempfile.mkdtemp(prefix="harness_test_"))
    try:
        service_file = temp_dir / "service.py"
        service_file.write_text("""
import yaml
def load_config(payload: str):
    return yaml.load(payload, Loader=yaml.Loader)
""", encoding="utf-8")

        req = HarnessGenerateRequest(
            repo_path=str(temp_dir),
            cve_id="CVE-2020-14343",
            target_file="service.py",
            function_name="load_config",
            vulnerable_call="yaml.load"
        )
        res = HarnessSynthesizer.synthesize_harness(req)

        assert res.cve_id == "CVE-2020-14343"
        assert "from service import load_config" in res.harness_code
        assert "sentinel_pwned.marker" in res.harness_code
        assert res.sentinel_filename == "sentinel_pwned.marker"
        assert res.latency_ms > 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
