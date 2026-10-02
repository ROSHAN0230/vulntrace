from pathlib import Path
import tempfile
import shutil
from vulntrace.analyzer.ast_visitor import AstReachabilityAnalyzer
from vulntrace.models import AstAnalyzeRequest

def test_ast_reachability_positive_and_negative():
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # File 1: main entrypoint calls vulnerable handler
        main_py = temp_dir / "app.py"
        main_py.write_text("""
import yaml

def public_api(data: str):
    return parse_config(data)

def parse_config(data: str):
    return yaml.load(data, Loader=yaml.Loader)

def unused_dead_function(data: str):
    return yaml.full_load(data)
""", encoding="utf-8")

        req = AstAnalyzeRequest(
            repo_path=str(temp_dir),
            entrypoints=["public_api"]
        )
        res = AstReachabilityAnalyzer.analyze_repository(req)

        assert res.reachable_vulnerabilities_count >= 1
        assert res.unreachable_dead_code_count >= 1
        assert res.verdict == "REACHABLE_VULNERABLE_CALL_PATH_IDENTIFIED"

        # Check that parse_config call to yaml.load is marked reachable
        parse_calls = [c for c in res.discovered_calls if c.function_name == "parse_config"]
        assert len(parse_calls) > 0
        assert parse_calls[0].reachable is True

        # Check that unused_dead_function call to yaml.full_load is marked unreachable
        dead_calls = [c for c in res.discovered_calls if c.function_name == "unused_dead_function"]
        assert len(dead_calls) > 0
        assert dead_calls[0].reachable is False
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
