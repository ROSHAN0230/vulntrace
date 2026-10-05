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


def test_harness_synthesizer_multi_parameter_carrier():
    """Proves that multi-parameter functions (e.g. parse_docstring(obj, process_doc)) are invoked with carrier objects."""
    temp_dir = Path(tempfile.mkdtemp(prefix="harness_multi_"))
    try:
        util_file = temp_dir / "flasgger_mock.py"
        util_file.write_text("""
import inspect
import yaml

def parse_docstring(obj, process_doc):
    doc = inspect.getdoc(obj)
    if not doc:
        return None, None, None
    sep = doc.find("---")
    if sep != -1:
        swag = yaml.load(doc[sep + 4:], Loader=yaml.Loader)
        return doc[:sep], None, swag
    return doc, None, None
""", encoding="utf-8")

        req = HarnessGenerateRequest(
            repo_path=str(temp_dir),
            cve_id="CVE-2020-14343",
            target_file="flasgger_mock.py",
            function_name="parse_docstring",
            vulnerable_call="yaml.load"
        )
        res = HarnessSynthesizer.synthesize_harness(req)

        assert "_invoke_target" in res.harness_code
        assert "_carrier" in res.harness_code
        assert "inspect.signature" in res.harness_code

        # Execute harness to verify execution succeeds and creates sentinel
        import subprocess
        import sys
        harness_file = temp_dir / "run_harness.py"
        harness_file.write_text(res.harness_code, encoding="utf-8")
        proc = subprocess.run([sys.executable, str(harness_file)], cwd=str(temp_dir), capture_output=True, text=True)
        assert proc.returncode == 0
        sentinel = temp_dir / res.sentinel_filename
        assert sentinel.exists()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

