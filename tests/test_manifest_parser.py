from pathlib import Path
import tempfile
import shutil
from vulntrace.analyzer.manifest_parser import ManifestParser

def test_manifest_parser_requirements_and_pyproject():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        req_file = temp_dir / "requirements.txt"
        req_file.write_text("PyYAML==5.3.1\nrequests>=2.28.0\n# comment\n", encoding="utf-8")

        resp = ManifestParser.inspect_repository(str(temp_dir))
        assert resp.exists is True
        assert "requirements.txt" in resp.manifest_files
        dep_names = [d.name for d in resp.dependencies]
        assert "PyYAML" in dep_names
        assert "requests" in dep_names
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
