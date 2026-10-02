import tempfile
import shutil
from pathlib import Path
from vulntrace.sandbox.runner import SubprocessSandboxRunner

def test_sandbox_disposable_workspace_and_sanitization():
    temp_src = Path(tempfile.mkdtemp(prefix="src_test_"))
    try:
        (temp_src / "service.py").write_text("def test(): return 42\n", encoding="utf-8")
        (temp_src / ".git").mkdir()
        (temp_src / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

        disposable = SubprocessSandboxRunner.prepare_disposable_workspace(temp_src)
        try:
            assert disposable.exists()
            assert (disposable / "service.py").exists()
            # Confirm .git was filtered out
            assert not (disposable / ".git").exists()

            # Test environment sanitization
            env = SubprocessSandboxRunner.sanitize_environment(disposable)
            assert "PYTHONPATH" in env
            assert env["PYTHONPATH"] == str(disposable)
            assert "SYSTEMROOT" in env

            # Confirm zero secret leakage
            for k in env:
                assert "NEBIUS" not in k
                assert "TAVILY" not in k
                assert "KEY" not in k or k == "KEY"  # no sensitive key
        finally:
            SubprocessSandboxRunner.cleanup_workspace(disposable)
            assert not disposable.exists()
    finally:
        shutil.rmtree(temp_src, ignore_errors=True)

def test_sandbox_execute_script():
    temp_dir = Path(tempfile.mkdtemp(prefix="exec_test_"))
    try:
        script = temp_dir / "test_run.py"
        script.write_text("import sys\nprint('HELLO_SANDBOX')\nsys.exit(0)\n", encoding="utf-8")

        res = SubprocessSandboxRunner.execute_script(temp_dir, "test_run.py")
        assert res.exit_code == 0
        assert "HELLO_SANDBOX" in res.stdout
        assert res.sandbox_engine == "LOCAL_SUBPROCESS_FALLBACK"
    finally:
        SubprocessSandboxRunner.cleanup_workspace(temp_dir)
